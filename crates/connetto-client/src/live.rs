//! Live queries: run a diesel query once and hold an object that stays fresh.
//!
//! [`ConnettoClient`] wraps a [`ConnettoConnection`] behind a shared async
//! lock and drives it from one background pump task, so applications never
//! hand-write a pump loop. [`ConnettoClient::watch`] takes an ordinary typed
//! diesel query, runs it against the local replica for the immediate answer,
//! renders it to SQLite SQL plus bind values, and registers the matching
//! server subscription. The returned [`LiveQuery`] caches the rows, refreshes
//! them whenever a table the query reads changes (a server patch or a local
//! write alike), and signals each change through an awaitable
//! [`changed`](LiveQuery::changed). Dropping the handle unsubscribes.
//!
//! The pump never parks on the transport while holding the connection lock:
//! it waits with a cancellable pump step
//! ([`ConnettoConnection::pump_one_or`]) that a wake signal interrupts, so
//! creating a live query or running a one-off closure through
//! [`with_conn`](ConnettoClient::with_conn) acquires the lock promptly. The
//! pump task holds only a weak reference to the shared state, so dropping
//! every [`ConnettoClient`] clone ends the pump, closes the transport, and
//! releases the connection: RAII end to end, matching the drop-unsubscribe
//! contract of the handles themselves.

use core::future::Future;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};

use connetto_core::messages::{BindValue, SubscriptionSpec};
use connetto_core::traits::{MaybeSend, Transport};
use diesel::SqliteConnection;
use diesel::query_builder::QueryFragment;
use diesel::query_dsl::RunQueryDsl;
use diesel::query_dsl::methods::LoadQuery;
use diesel::sqlite::Sqlite;
use serde::de::DeserializeOwned;
use sqlparser::ast::{Expr, GroupByExpr, SelectItem, SetExpr, Statement, visit_relations};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use subql::backend::Value as SqliteValue;
use tokio::sync::{Mutex, Notify, broadcast, watch};

use crate::reconnect::{NoReconnect, NoSleep, ReconnectPolicy, Sleeper, TransportFactory};
use crate::{ClientError, ClientEvent, ConnettoConnection};

/// Render a typed diesel query to its SQLite SQL (with `?` placeholders) and
/// the bind values the placeholders stand for, in placeholder order.
///
/// Rendering rides `subql`'s diesel-typed API, the same machinery the
/// engine's own typed registration uses, so the SQL skeleton and bind
/// decoding stay identical on both ends of the wire.
///
/// # Errors
///
/// [`ClientError::Session`] when diesel cannot render the query or a bind
/// uses a type outside the wire's scalar set.
pub fn render_query<Q: QueryFragment<Sqlite>>(
    query: &Q,
) -> Result<(String, Vec<BindValue>), ClientError> {
    let (sql, values) = subql::diesel_api::render_typed::<Sqlite, _>(query)
        .map_err(|e| ClientError::Session(e.to_string()))?;
    let binds = values
        .into_iter()
        .map(|value| match value {
            SqliteValue::Null => Ok(BindValue::Null),
            SqliteValue::Int(i) => Ok(BindValue::Integer(i)),
            SqliteValue::Float(f) => Ok(BindValue::Real(f)),
            SqliteValue::String(s) => Ok(BindValue::Text(s)),
            SqliteValue::Bytes(b) => Ok(BindValue::Blob(b)),
            other => Err(ClientError::Session(format!(
                "unsupported bind value shape {other:?}"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((sql, binds))
}

/// Which answer path a subscription query rides client-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryShape {
    /// A row projection: answered from the replica, refreshed on table changes.
    Rows,
    /// A single ungrouped scalar aggregate: answered by server pushes.
    Aggregate,
}

/// What the client needs from a rendered subscription query: the tables it
/// reads (for targeted refresh) and its shape (for answer-path routing).
struct ParsedSubscription {
    tables: HashSet<String>,
    shape: QueryShape,
}

/// The lowercased names of every table a subscription query reads.
///
/// The same extraction the pump uses to route refreshes, exposed so a relay
/// serving the wire protocol from a worker-held replica can route snapshots
/// and live patches by table.
///
/// # Errors
///
/// [`ClientError::Session`] when the SQL cannot be parsed.
pub fn subscription_tables(sql: &str) -> Result<HashSet<String>, ClientError> {
    Ok(parse_subscription(sql)?.tables)
}

/// Whether a rendered subscription query is answered by server-pushed
/// aggregates rather than from the replica.
///
/// The same shape classification the pump uses to route a query to
/// [`ConnettoClient::watch_value`], exposed so a relay serving the wire
/// protocol from a worker-held connection can route a tab `Subscribe` to the
/// aggregate path instead of a row snapshot, matching the direct client.
///
/// This classifies from the rendered SQL by function name, so it recognizes
/// only the built-in scalar aggregate family (`COUNT`, `SUM`, `AVG`, the
/// extremes, and the variance and stddev functions). It cannot recognize a
/// custom aggregate: a text classifier cannot tell a user aggregate
/// `my_agg(x)` from a user scalar function `my_func(x)` without a name
/// registry, which would misclassify the scalar. Custom aggregates are
/// supported only through the typed [`live()`](crate::dsl::Watchable::live)
/// path, which classifies by diesel's `IsAggregate` type marker. A relay
/// forwarding raw tab SQL therefore serves the built-in family only.
///
/// # Errors
///
/// [`ClientError::Session`] when the SQL cannot be parsed.
pub fn subscription_is_aggregate(sql: &str) -> Result<bool, ClientError> {
    Ok(parse_subscription(sql)?.shape == QueryShape::Aggregate)
}

/// The scalar aggregate functions the server maintains, lowercased.
///
/// This is the built-in family the SQL-text classification recognizes. It is
/// deliberately a fixed set, not a registry of arbitrary user aggregate
/// names: see [`subscription_is_aggregate`] for why a name-based classifier
/// cannot admit custom aggregates without misclassifying scalar functions.
const AGGREGATE_FUNCTIONS: &[&str] = &[
    "avg",
    "count",
    "max",
    "min",
    "stddev_pop",
    "stddev_samp",
    "sum",
    "total",
    "var_pop",
    "var_samp",
];

/// Whether a value watch already knows it faces an aggregate.
#[derive(Clone, Copy)]
enum ShapeSource {
    /// The typed [`live()`](crate::dsl::Watchable::live) dispatch proved the
    /// aggregate shape through diesel's `IsAggregate` marker, so the SQL-text
    /// classification is bypassed. This is the only path that admits a custom
    /// aggregate, whose function name is absent from [`AGGREGATE_FUNCTIONS`].
    Marker,
    /// A dynamic caller with no type-level marker, classified from the
    /// rendered SQL by function name against the built-in family.
    Sql,
}

/// Parse a rendered subscription query into its table set and shape.
fn parse_subscription(sql: &str) -> Result<ParsedSubscription, ClientError> {
    let statements = Parser::parse_sql(&SQLiteDialect {}, sql)
        .map_err(|e| ClientError::Session(e.to_string()))?;
    let mut tables = HashSet::new();
    let _ = visit_relations(&statements, |name| {
        // The ident VALUE, never its Display: a quoted identifier renders
        // with its quote characters, which would never intersect the plain
        // table names the change tracker reports.
        if let Some(ident) = name.0.last().and_then(|part| part.as_ident()) {
            tables.insert(ident.value.to_lowercase());
        }
        core::ops::ControlFlow::<()>::Continue(())
    });
    let shape = match statements.as_slice() {
        [Statement::Query(query)] => query_shape(query),
        _ => QueryShape::Rows,
    };
    Ok(ParsedSubscription { tables, shape })
}

/// A query is aggregate-shaped when it projects exactly one ungrouped call to
/// a known scalar aggregate, mirroring the server's classification closely
/// enough to route the client's answer path.
fn query_shape(query: &sqlparser::ast::Query) -> QueryShape {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return QueryShape::Rows;
    };
    let ungrouped = matches!(
        &select.group_by,
        GroupByExpr::Expressions(exprs, mods) if exprs.is_empty() && mods.is_empty()
    );
    if !ungrouped || select.projection.len() != 1 {
        return QueryShape::Rows;
    }
    let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) =
        &select.projection[0]
    else {
        return QueryShape::Rows;
    };
    let Expr::Function(function) = expr else {
        return QueryShape::Rows;
    };
    let is_aggregate = function
        .name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|ident| AGGREGATE_FUNCTIONS.contains(&ident.value.to_lowercase().as_str()));
    if is_aggregate {
        QueryShape::Aggregate
    } else {
        QueryShape::Rows
    }
}

/// The wire subscription specs backing a row handle, by tier. All tables
/// synced: the query itself rides the wire (server-side predicate pushdown).
/// All tables local: no subscription at all. Mixed: one whole-table
/// subscription per synced table, sorted for a deterministic order, so the
/// synced side stays live and covering for the handle's lifetime. The caller
/// maps each spec to a shared, ref-counted wire subscription.
fn wire_subscriptions(
    local: &HashSet<String>,
    tables: &HashSet<String>,
    query_spec: impl FnOnce() -> SubscriptionSpec,
) -> Vec<SubscriptionSpec> {
    let local_count = tables.intersection(local).count();
    if local_count == 0 {
        return vec![query_spec()];
    }
    if local_count == tables.len() {
        return Vec::new();
    }
    let mut synced: Vec<&str> = tables
        .iter()
        .filter(|table| !local.contains(*table))
        .map(String::as_str)
        .collect();
    synced.sort_unstable();
    synced
        .into_iter()
        .map(|table| SubscriptionSpec::new(format!("SELECT * FROM \"{table}\"")))
        .collect()
}

/// One SQL literal for a bound value, for local re-execution of a rendered
/// aggregate. Text doubles its quotes, blobs render as `X'..'` hex.
fn bind_literal(bind: &BindValue) -> Result<String, ClientError> {
    Ok(match bind {
        BindValue::Null => "NULL".to_owned(),
        BindValue::Integer(value) => value.to_string(),
        BindValue::Real(value) if value.is_finite() => format!("{value:?}"),
        BindValue::Real(_) => {
            return Err(ClientError::Session(
                "non-finite float bind has no SQL literal".to_owned(),
            ));
        }
        BindValue::Text(value) => format!("'{}'", value.replace('\'', "''")),
        BindValue::Blob(bytes) => {
            use core::fmt::Write;
            let mut literal = String::with_capacity(bytes.len() * 2 + 3);
            literal.push_str("X'");
            for byte in bytes {
                let _ = write!(literal, "{byte:02X}");
            }
            literal.push('\'');
            literal
        }
    })
}

/// The rendered SQL with every `?` placeholder replaced by its bind value as
/// a literal, skipping quoted regions. Local re-execution has no bind API for
/// a raw SQL string with a dynamic bind list, and the values are the client's
/// own typed data, escaped per storage class.
fn inline_binds(sql: &str, binds: &[BindValue]) -> Result<String, ClientError> {
    let mut out = String::with_capacity(sql.len());
    let mut remaining = binds.iter();
    let mut in_quote: Option<char> = None;
    for c in sql.chars() {
        if let Some(quote) = in_quote {
            out.push(c);
            if c == quote {
                in_quote = None;
            }
        } else {
            match c {
                '\'' | '"' | '`' => {
                    in_quote = Some(c);
                    out.push(c);
                }
                '?' => {
                    let bind = remaining.next().ok_or_else(|| {
                        ClientError::Session("more placeholders than binds".to_owned())
                    })?;
                    out.push_str(&bind_literal(bind)?);
                }
                _ => out.push(c),
            }
        }
    }
    if remaining.next().is_some() {
        return Err(ClientError::Session(
            "more binds than placeholders".to_owned(),
        ));
    }
    Ok(out)
}

/// Wrap a rendered aggregate query so its scalar answer comes back as the
/// JSON text the wire decoders expect: `json_quote` renders integers and
/// floats as JSON numbers, text as a JSON string, and `NULL` as `null`,
/// matching the server's aggregate push rendering.
fn local_aggregate_probe(sql: &str, binds: &[BindValue]) -> Result<String, ClientError> {
    let inlined = inline_binds(sql, binds)?;
    Ok(format!("SELECT json_quote(({inlined})) AS value"))
}

/// The JSON text a local aggregate probe produced.
#[derive(diesel::QueryableByName)]
struct ProbeRow {
    /// The `json_quote` rendering of the scalar.
    #[diesel(sql_type = diesel::sql_types::Text)]
    value: String,
}

/// Run a local aggregate probe: a single ungrouped aggregate returns exactly
/// one row.
fn run_probe(conn: &mut SqliteConnection, probe: &str) -> Result<String, ClientError> {
    let rows: Vec<ProbeRow> = diesel::sql_query(probe)
        .load(conn)
        .map_err(|e| ClientError::Session(e.to_string()))?;
    rows.into_iter()
        .next()
        .map(|row| row.value)
        .ok_or_else(|| ClientError::Session("aggregate probe returned no row".to_owned()))
}

/// Subscription ids and the wake signal shared with every [`LiveQuery`], so a
/// synchronous `Drop` can queue its unsubscribe for the async pump.
struct Reaper {
    pending: StdMutex<Vec<String>>,
    wake: Arc<Notify>,
}

/// Driver-side refresh callback of one live query: re-run the captured query
/// against the shared connection and publish fresh rows.
type Refresh<T> = Box<dyn FnMut(&mut ConnettoConnection<T>) -> Result<(), ClientError> + Send>;

/// One live handle's driver-side state: which tables it reads, how to re-run
/// its query and publish fresh results, and the ids of the shared wire
/// subscriptions backing it (empty for a handle served purely from the local
/// tier, one carrying the query itself for a synced query, one whole-table
/// subscription per synced table for a mixed-tier query).
struct LiveEntry<T: Transport> {
    sub_id: String,
    tables: HashSet<String>,
    refresh: Refresh<T>,
    wire_ids: Vec<String>,
}

/// Driver-side apply callback of one live value: decode the pushed JSON and
/// publish it when it differs from the current value.
type ApplyValue = Box<dyn FnMut(&str) -> Result<(), ClientError> + Send>;

/// One live value handle's driver-side state, with the id of the shared wire
/// subscription that feeds it (the target of aggregate pushes and what a drop
/// releases a reference on).
struct ValueEntry {
    sub_id: String,
    wire_id: String,
    apply: ApplyValue,
}

/// One shared wire subscription: declared once on the wire under `wire_id`,
/// reference counted across every row and value handle that resolved to the
/// same `spec`. `last_agg` caches the most recent aggregate result so a
/// late-joining value handle resolves immediately, since the server sends the
/// bootstrap only at subscribe time.
struct WireSub {
    wire_id: String,
    spec: SubscriptionSpec,
    refs: usize,
    last_agg: Option<String>,
}

/// The connection and the live registries, guarded together so a refresh
/// always sees the replica state the pump just produced. `wire` is the
/// ref-counted layer beneath the handles: identical queries share one entry,
/// so the client opens one wire subscription per distinct query.
struct State<T: Transport> {
    conn: ConnettoConnection<T>,
    registry: Vec<LiveEntry<T>>,
    values: Vec<ValueEntry>,
    wire: Vec<WireSub>,
}

/// Everything the client handles and the pump task share.
struct Shared<T: Transport> {
    state: Mutex<State<T>>,
    wake: Arc<Notify>,
    reaper: Arc<Reaper>,
    events: broadcast::Sender<ClientEvent>,
    next_live: AtomicU64,
    // Distinct id spaces: handle ids (`live-N`) and shared wire ids (`wire-N`).
    next_wire: AtomicU64,
}

/// The shared surface of every live handle: a current snapshot, an awaitable
/// change signal, the backing subscription id, and drop-unsubscribe. Framework
/// adapters build on this so a single hook serves row and scalar handles
/// alike.
pub trait LiveHandle {
    /// The snapshot type: `Vec<R>` for a row query, `Option<V>` for a scalar.
    type Snapshot;

    /// The current snapshot.
    fn snapshot(&self) -> Self::Snapshot;

    /// Wait until the snapshot changes. Resolves once per real change,
    /// coalescing bursts.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    fn changed(&mut self) -> impl core::future::Future<Output = Result<(), ClientError>> + Send;

    /// The subscription id backing this handle.
    fn sub_id(&self) -> &str;
}

/// A typed diesel query kept fresh by the client's pump.
///
/// Read the current rows with [`rows`](Self::rows) (a cheap clone of the
/// driver-maintained cache) and await [`changed`](Self::changed) to learn when
/// they moved. Dropping the handle queues the server unsubscribe; the pump
/// sends it on its next step.
pub struct LiveQuery<R> {
    sub_id: String,
    rows: Arc<RwLock<Vec<R>>>,
    changed: watch::Receiver<u64>,
    reaper: Arc<Reaper>,
}

impl<R: Clone + Send + Sync> LiveHandle for LiveQuery<R> {
    type Snapshot = Vec<R>;

    fn snapshot(&self) -> Vec<R> {
        self.rows()
    }

    fn changed(&mut self) -> impl core::future::Future<Output = Result<(), ClientError>> + Send {
        LiveQuery::changed(self)
    }

    fn sub_id(&self) -> &str {
        LiveQuery::sub_id(self)
    }
}

impl<R: Clone> LiveQuery<R> {
    /// The current rows, as of the latest refresh.
    #[must_use]
    pub fn rows(&self) -> Vec<R> {
        self.rows.read().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |rows| rows.clone(),
        )
    }
}

impl<R> LiveQuery<R> {
    /// The subscription id backing this handle.
    #[must_use]
    pub fn sub_id(&self) -> &str {
        &self.sub_id
    }

    /// Wait until the rows change. Resolves once per refresh that actually
    /// altered the result set, coalescing bursts.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.changed
            .changed()
            .await
            .map_err(|_| ClientError::Transport("live query driver stopped".to_owned()))
    }
}

impl<R> Drop for LiveQuery<R> {
    fn drop(&mut self) {
        let sub_id = core::mem::take(&mut self.sub_id);
        let mut pending = match self.reaper.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        pending.push(sub_id);
        drop(pending);
        self.reaper.wake.notify_one();
    }
}

/// A server-maintained scalar aggregate kept fresh by the client's pump.
///
/// Created by [`ConnettoClient::watch_value`] for aggregate queries. The
/// replica holds only this client's authorized rows, so it cannot answer a
/// global statistic: the value comes exclusively from server pushes, and
/// [`value`](Self::value) is `None` until the server's bootstrap arrives.
/// Dropping the handle queues the server unsubscribe, exactly like
/// [`LiveQuery`].
pub struct LiveValue<V> {
    sub_id: String,
    value: Arc<RwLock<Option<V>>>,
    changed: watch::Receiver<u64>,
    reaper: Arc<Reaper>,
}

impl<V: Clone + Send + Sync> LiveHandle for LiveValue<V> {
    type Snapshot = Option<V>;

    fn snapshot(&self) -> Option<V> {
        self.value()
    }

    fn changed(&mut self) -> impl core::future::Future<Output = Result<(), ClientError>> + Send {
        LiveValue::changed(self)
    }

    fn sub_id(&self) -> &str {
        LiveValue::sub_id(self)
    }
}

impl<V: Clone> LiveValue<V> {
    /// The current value, or `None` before the server's bootstrap arrives.
    #[must_use]
    pub fn value(&self) -> Option<V> {
        self.value.read().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |value| value.clone(),
        )
    }
}

impl<V> LiveValue<V> {
    /// The subscription id backing this handle.
    #[must_use]
    pub fn sub_id(&self) -> &str {
        &self.sub_id
    }

    /// Wait until the value changes, the initial bootstrap included.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.changed
            .changed()
            .await
            .map_err(|_| ClientError::Transport("live query driver stopped".to_owned()))
    }
}

impl<V> Drop for LiveValue<V> {
    fn drop(&mut self) {
        let sub_id = core::mem::take(&mut self.sub_id);
        let mut pending = match self.reaper.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        pending.push(sub_id);
        drop(pending);
        self.reaper.wake.notify_one();
    }
}

/// Liveness token every [`ConnettoClient`] clone holds. Dropping the last one
/// wakes the pump, which then closes the connection gracefully and exits.
struct ClientToken {
    wake: Arc<Notify>,
}

impl Drop for ClientToken {
    fn drop(&mut self) {
        self.wake.notify_one();
    }
}

/// A shared, background-driven connetto client.
///
/// Wraps a [`ConnettoConnection`] and owns its pump: applications create live
/// queries with [`watch`](Self::watch), run one-off reads and writes with
/// [`with_conn`](Self::with_conn), and observe the raw event stream with
/// [`events`](Self::events). Clones share the one connection. When the last
/// clone drops, the pump closes the connection cleanly (a proper transport
/// close handshake) and ends. A [`LiveQuery`] outliving every client clone
/// keeps its last rows, and its `changed()` reports the driver as stopped.
pub struct ConnettoClient<T: Transport> {
    shared: Arc<Shared<T>>,
    token: Arc<ClientToken>,
}

impl<T: Transport> Clone for ConnettoClient<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            token: Arc::clone(&self.token),
        }
    }
}

impl<T> ConnettoClient<T>
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
{
    /// Take ownership of a connected [`ConnettoConnection`] and start the
    /// background pump that drives it on the ambient tokio runtime.
    ///
    /// Native convenience over [`with_pump`](Self::with_pump), gated on the
    /// `native-transport` feature that carries the tokio runtime. Wasm builds
    /// leave the feature off and drive the pump future with `spawn_local`.
    #[cfg(feature = "native-transport")]
    #[must_use]
    pub fn start(conn: ConnettoConnection<T>) -> Self {
        let (client, pump) = Self::with_pump(conn);
        tokio::spawn(pump);
        client
    }

    /// Take ownership of a connected [`ConnettoConnection`] and return the
    /// client together with its pump future, which the caller must drive to
    /// completion (`tokio::spawn` on native, `spawn_local` on wasm).
    ///
    /// The pump exits when the last client clone drops or the transport
    /// closes. The future is the single place the platform's driving mode
    /// touches the client, so every other behavior stays identical across
    /// native and wasm.
    pub fn with_pump(conn: ConnettoConnection<T>) -> (Self, impl Future<Output = ()>) {
        Self::build(conn, None::<ReconnectDriver<NoReconnect<T>, NoSleep>>)
    }

    /// Like [`with_pump`](Self::with_pump), but the pump survives transport
    /// drops: it backs off per `policy`, obtains a fresh connection from
    /// `factory`, resumes the session with the highest applied cursor, and
    /// re-declares every live subscription, without dropping any handle.
    /// The server replays retained changes as ordinary live patches or
    /// orders a full resync. Observers see [`ClientEvent::Reconnecting`] per
    /// attempt and [`ClientEvent::Reconnected`] on success. Exhausting the
    /// policy broadcasts [`ClientEvent::Closed`] and ends the pump.
    ///
    /// A mutation that was fully sent but not yet processed when the
    /// transport died is NOT replayed (acceptance has no reply, so a resend
    /// could double-apply). Writes captured but never sent re-flush after
    /// the resume.
    pub fn with_reconnect<F, S>(
        conn: ConnettoConnection<T>,
        factory: F,
        sleeper: S,
        policy: ReconnectPolicy,
    ) -> (Self, impl Future<Output = ()>)
    where
        F: TransportFactory<Transport = T> + MaybeSend + 'static,
        S: Sleeper + MaybeSend + 'static,
    {
        Self::build(
            conn,
            Some(ReconnectDriver {
                factory,
                sleeper,
                policy,
            }),
        )
    }

    /// Shared constructor body behind the two pump flavors.
    fn build<F, S>(
        conn: ConnettoConnection<T>,
        reconnect: Option<ReconnectDriver<F, S>>,
    ) -> (Self, impl Future<Output = ()>)
    where
        F: TransportFactory<Transport = T> + MaybeSend + 'static,
        S: Sleeper + MaybeSend + 'static,
    {
        let wake = Arc::new(Notify::new());
        let (events, _) = broadcast::channel(256);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                conn,
                registry: Vec::new(),
                values: Vec::new(),
                wire: Vec::new(),
            }),
            wake: Arc::clone(&wake),
            reaper: Arc::new(Reaper {
                pending: StdMutex::new(Vec::new()),
                wake: Arc::clone(&wake),
            }),
            events,
            next_live: AtomicU64::new(1),
            next_wire: AtomicU64::new(1),
        });
        let token = Arc::new(ClientToken { wake });
        let driver = pump(Arc::clone(&shared), Arc::downgrade(&token), reconnect);
        (Self { shared, token }, driver)
    }

    /// Run a typed diesel query and keep its result fresh.
    ///
    /// Executes the query against the local replica for the immediate,
    /// offline-capable answer, registers a server subscription rendered from
    /// the same query (SQLite SQL plus bind values, translated server-side),
    /// and returns a [`LiveQuery`] whose rows the pump refreshes whenever a
    /// table the query reads changes. Dropping the handle unsubscribes.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, the initial local
    /// read fails, or the subscribe frame cannot be sent.
    pub async fn watch<Q, R>(&self, query: Q) -> Result<LiveQuery<R>, ClientError>
    where
        Q: QueryFragment<Sqlite> + Clone + Send + 'static,
        Q: for<'query> LoadQuery<'query, SqliteConnection, R>,
        R: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_fn(move || query.clone()).await
    }

    /// Run a diesel query produced by a factory closure and keep its result
    /// fresh.
    ///
    /// The row live query for a boxed (`.into_boxed()`) or otherwise
    /// dynamically built query. Such a query carries no compile-time
    /// aggregation marker, so the typed [`live()`](crate::dsl::Watchable::live)
    /// verb cannot dispatch on it, and it is not `Clone`, so
    /// [`watch`](Self::watch), which clones a stored query on every refresh,
    /// cannot re-run it. In place of a query value it takes `build`, a factory
    /// that yields a fresh query instance on each call.
    ///
    /// `build` is invoked once to render the server subscription, once for the
    /// initial local read, and again on every refresh. It MUST be pure and
    /// stable: each call has to build an equivalent query, the same SQL,
    /// tables, and binds. The wire subscription is fixed from the first
    /// render, so a `build` that renders different SQL on a later call would
    /// silently diverge from what refresh reads. A deliberately time-varying
    /// window is a separate replica-retention feature, not this.
    ///
    /// Like [`watch`](Self::watch) it reads the local replica first for the
    /// immediate, offline-capable answer, registers a server subscription
    /// rendered from the query, and returns a [`LiveQuery`] whose rows the pump
    /// refreshes whenever a table the query reads changes. Dropping the handle
    /// unsubscribes. A boxed aggregate query has no row answer here: send it to
    /// [`watch_value_with`](Self::watch_value_with) instead.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, is aggregate-shaped,
    /// the initial local read fails, or the subscribe frame cannot be sent.
    pub async fn watch_fn<F, Q, R>(&self, build: F) -> Result<LiveQuery<R>, ClientError>
    where
        F: Fn() -> Q + Send + 'static,
        Q: QueryFragment<Sqlite>,
        Q: for<'query> LoadQuery<'query, SqliteConnection, R>,
        R: Clone + PartialEq + Send + Sync + 'static,
    {
        let (sql, binds) = render_query(&build())?;
        let parsed = parse_subscription(&sql)?;
        if parsed.shape == QueryShape::Aggregate {
            return Err(ClientError::Session(
                "aggregate query: use watch_value, the replica cannot answer a global statistic"
                    .to_owned(),
            ));
        }
        let tables = parsed.tables;
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");

        // Interrupt the pump's idle wait so the FIFO lock admits us promptly.
        self.shared.wake.notify_one();
        let mut state = self.shared.state.lock().await;

        let initial: Vec<R> = build()
            .load(state.conn.conn())
            .map_err(|e| ClientError::Session(e.to_string()))?;
        let rows = Arc::new(RwLock::new(initial));
        let (tx, rx) = watch::channel(0_u64);

        let refresh_rows = Arc::clone(&rows);
        let refresh = Box::new(move |conn: &mut ConnettoConnection<T>| {
            let fresh: Vec<R> = build()
                .load(conn.conn())
                .map_err(|e| ClientError::Session(e.to_string()))?;
            let unchanged = refresh_rows.read().is_ok_and(|current| *current == fresh);
            if !unchanged {
                match refresh_rows.write() {
                    Ok(mut rows) => *rows = fresh,
                    Err(poisoned) => *poisoned.into_inner() = fresh,
                }
                tx.send_modify(|generation| *generation += 1);
            }
            Ok(())
        });

        // Tier dispatch. A query over local tier tables alone registers no
        // server subscription: the update hook refreshes it on local writes.
        // A mixed query subscribes each synced table whole, tied to the
        // handle: the requirement is that the synced side stays live and
        // covering while the handle exists, and whole-table subscribe is the
        // disposable v1 mechanism (predicate pushdown is a later refinement).
        let specs = wire_subscriptions(state.conn.local_tables(), &tables, || {
            SubscriptionSpec::new(sql).with_binds(binds)
        });
        let mut wire_ids = Vec::with_capacity(specs.len());
        for spec in specs {
            let (wire_id, _) = attach_wire(&mut state, &self.shared.next_wire, spec).await?;
            wire_ids.push(wire_id);
        }
        state.registry.push(LiveEntry {
            sub_id: sub_id.clone(),
            tables,
            refresh,
            wire_ids,
        });

        Ok(LiveQuery {
            sub_id,
            rows,
            changed: rx,
            reaper: Arc::clone(&self.shared.reaper),
        })
    }

    /// Watch a server-maintained scalar aggregate, decoding each push with
    /// plain serde.
    ///
    /// The query must be a single ungrouped aggregate of the built-in family
    /// (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, or the variance and stddev
    /// family), classified from the rendered SQL by function name. It
    /// registers like any subscription, but the answer path is inverted: no
    /// local read happens (the replica holds only this client's authorized
    /// subset), and every value, the bootstrap included, arrives as a server
    /// push decoded from JSON into `V`. Use an `Option` value type (for
    /// example `Option<f64>`) for aggregates that are `null` over an empty
    /// set, such as `AVG`, `MIN`, and `MAX`.
    ///
    /// This decode is plain serde and does NOT apply the wire-lenient numeric
    /// rules the typed [`live()`](crate::dsl::Watchable::live) path applies
    /// (for example an integer `SUM` the server renders as `"3.0"` fails
    /// `V = i64` here). For a numeric aggregate prefer the typed path, or
    /// [`watch_value_with`](Self::watch_value_with) supplying a wire-aware
    /// decoder such as the [`AggregateWire`](crate::dsl::AggregateWire) family.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, is not
    /// aggregate-shaped, or the subscribe frame cannot be sent. A server-side
    /// refusal (for example an aggregate on an RLS table) arrives later as
    /// [`ClientEvent::NonFatal`] on [`events`](Self::events).
    pub async fn watch_value<Q, V>(&self, query: Q) -> Result<LiveValue<V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        V: DeserializeOwned + Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_value_with(query, |json| {
            serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))
        })
        .await
    }

    /// Watch a scalar aggregate, decoding each push with a caller-supplied
    /// decoder.
    ///
    /// The decoder-parameterized peer of [`watch_value`](Self::watch_value),
    /// for a value type whose wire decode is not plain serde: pass a
    /// [`AggregateWire`](crate::dsl::AggregateWire) decoder, or one built from
    /// the reusable primitives in [`dsl::wire`](crate::dsl::wire). This is the
    /// runtime path a boxed (`.into_boxed()`) or otherwise dynamic query takes,
    /// since such a query carries no type-level aggregation marker.
    ///
    /// Like [`watch_value`](Self::watch_value), the query is classified as an
    /// aggregate from its rendered SQL by function name, so it recognizes only
    /// the built-in family. A custom aggregate (a name absent from the
    /// built-in set) must be driven through the typed
    /// [`live()`](crate::dsl::Watchable::live) path, which classifies by
    /// diesel's `IsAggregate` marker instead.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, is not
    /// aggregate-shaped, or the subscribe frame cannot be sent. A server-side
    /// refusal arrives later as [`ClientEvent::NonFatal`] on
    /// [`events`](Self::events).
    pub async fn watch_value_with<Q, V>(
        &self,
        query: Q,
        decode: fn(&str) -> Result<V, ClientError>,
    ) -> Result<LiveValue<V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_value_core(query, decode, ShapeSource::Sql).await
    }

    /// The typed `live()` entry: the aggregate shape is already proven by
    /// diesel's `IsAggregate` marker, so the SQL-text classification is
    /// bypassed and a custom aggregate name is accepted.
    pub(crate) async fn watch_value_typed<Q, V>(
        &self,
        query: Q,
        decode: fn(&str) -> Result<V, ClientError>,
    ) -> Result<LiveValue<V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_value_core(query, decode, ShapeSource::Marker)
            .await
    }

    /// The decoder-parameterized core behind every value watch. `shape` says
    /// whether the aggregate shape is trusted from a type-level marker or must
    /// be classified from the rendered SQL.
    async fn watch_value_core<Q, V>(
        &self,
        query: Q,
        decode: fn(&str) -> Result<V, ClientError>,
        shape: ShapeSource,
    ) -> Result<LiveValue<V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        let (sql, binds) = render_query(&query)?;
        let parsed = parse_subscription(&sql)?;
        if matches!(shape, ShapeSource::Sql) && parsed.shape != QueryShape::Aggregate {
            return Err(ClientError::Session(
                "row query: use watch, a row projection is answered from the replica".to_owned(),
            ));
        }
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");

        let value = Arc::new(RwLock::new(None::<V>));
        let (tx, rx) = watch::channel(0_u64);
        let apply_value = Arc::clone(&value);
        let mut apply: ApplyValue = Box::new(move |json: &str| {
            let fresh: V = decode(json)?;
            let unchanged = apply_value
                .read()
                .is_ok_and(|current| current.as_ref() == Some(&fresh));
            if !unchanged {
                match apply_value.write() {
                    Ok(mut value) => *value = Some(fresh),
                    Err(poisoned) => *poisoned.into_inner() = Some(fresh),
                }
                tx.send_modify(|generation| *generation += 1);
            }
            Ok(())
        });

        // Interrupt the pump's idle wait so the FIFO lock admits us promptly.
        self.shared.wake.notify_one();
        let mut state = self.shared.state.lock().await;

        // Tier dispatch. A local tier table is complete by definition, so a
        // local aggregate is served by exact local re-execution on change,
        // through the same wire decoder the server path uses (`json_quote`
        // renders the scalar as the JSON the decoder expects). A mixed
        // aggregate is refused: the local side cannot be pushed to the server
        // and the synced side's replica subset cannot answer globally.
        let local_count = parsed
            .tables
            .intersection(state.conn.local_tables())
            .count();
        if local_count > 0 {
            if local_count != parsed.tables.len() {
                return Err(ClientError::Session(
                    "mixed-tier aggregate: a statistic cannot span local and synced tables"
                        .to_owned(),
                ));
            }
            let probe = local_aggregate_probe(&sql, &binds)?;
            // The bootstrap sets the value without a generation bump, like
            // the initial rows of a row handle: the first `changed()` must
            // wait for a real change, not report the registration itself.
            let bootstrap = decode(&run_probe(state.conn.conn(), &probe)?)?;
            match value.write() {
                Ok(mut slot) => *slot = Some(bootstrap),
                Err(poisoned) => *poisoned.into_inner() = Some(bootstrap),
            }
            let refresh = Box::new(move |conn: &mut ConnettoConnection<T>| {
                apply(&run_probe(conn.conn(), &probe)?)
            });
            state.registry.push(LiveEntry {
                sub_id: sub_id.clone(),
                tables: parsed.tables,
                refresh,
                wire_ids: Vec::new(),
            });
            return Ok(LiveValue {
                sub_id,
                value,
                changed: rx,
                reaper: Arc::clone(&self.shared.reaper),
            });
        }

        let spec = SubscriptionSpec::new(sql).with_binds(binds);
        let (wire_id, cached) = attach_wire(&mut state, &self.shared.next_wire, spec).await?;
        if let Some(json) = cached {
            // Late joiner: the server sends the bootstrap only at the first
            // subscribe, so resolve from the cached last result now. Set the
            // slot directly, without a generation bump, so the first changed()
            // still waits for a real change (like a bootstrap).
            let bootstrap = decode(&json)?;
            match value.write() {
                Ok(mut slot) => *slot = Some(bootstrap),
                Err(poisoned) => *poisoned.into_inner() = Some(bootstrap),
            }
        }
        state.values.push(ValueEntry {
            sub_id: sub_id.clone(),
            wire_id,
            apply,
        });

        Ok(LiveValue {
            sub_id,
            value,
            changed: rx,
            reaper: Arc::clone(&self.shared.reaper),
        })
    }

    /// Run a closure against the shared connection: one-off diesel reads and
    /// captured writes. Local writes committed here are auto-submitted by the
    /// pump's next flush, and any live query reading the written tables
    /// refreshes.
    pub async fn with_conn<F, O>(&self, f: F) -> O
    where
        F: FnOnce(&mut ConnettoConnection<T>) -> O,
    {
        self.shared.wake.notify_one();
        let mut state = self.shared.state.lock().await;
        let out = f(&mut state.conn);
        drop(state);
        // A write may have landed: let the pump flush and refresh promptly.
        self.shared.wake.notify_one();
        out
    }

    /// Send a keepalive probe. The matching [`ClientEvent::Pong`] on the
    /// [`events`](Self::events) stream doubles as a barrier: the server
    /// processes frames in order, so the pong proves every frame sent before
    /// the ping (subscribes and unsubscribes included) was handled.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the ping cannot be sent.
    pub async fn ping(&self, nonce: u64) -> Result<(), ClientError> {
        self.shared.wake.notify_one();
        let mut state = self.shared.state.lock().await;
        state.conn.ping(nonce).await
    }

    /// Subscribe to the raw [`ClientEvent`] stream the pump produces
    /// (rejections, conflicts, aggregate values, non-fatal errors). Lagging
    /// receivers drop the oldest events.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<ClientEvent> {
        self.shared.events.subscribe()
    }

    /// Postfix-free spelling of the [`Watchable`](crate::dsl::Watchable)
    /// verb: `client.live(query)` is `query.live(&client)`, with the handle
    /// type chosen at compile time from the query's shape. The `R` parameter
    /// is turbofish-friendly for row queries: `client.live::<_, Order>(q)`.
    ///
    /// # Errors
    ///
    /// See [`watch`](Self::watch) and [`watch_value`](Self::watch_value).
    pub async fn live<Q, R>(&self, query: Q) -> Result<Q::Handle, ClientError>
    where
        Q: crate::dsl::Watchable<T, R>,
    {
        query.live(self).await
    }
}

/// A configured reconnect driver: the factory, the sleeper, and the policy.
struct ReconnectDriver<F, S> {
    factory: F,
    sleeper: S,
    policy: ReconnectPolicy,
}

/// Whether a pump-step failure means the transport is gone (and a reconnect
/// driver should take over) rather than a local fault.
fn is_disconnect(err: &ClientError) -> bool {
    matches!(err, ClientError::Transport(_))
}

/// Decrement one reference on the wire subscription `wire_id`. When the last
/// sharer drops, remove the entry and record its id for a single Unsubscribe.
fn release_wire(wire: &mut Vec<WireSub>, wire_id: &str, released: &mut Vec<String>) {
    if let Some(pos) = wire.iter().position(|w| w.wire_id == wire_id) {
        wire[pos].refs -= 1;
        if wire[pos].refs == 0 {
            released.push(wire.remove(pos).wire_id);
        }
    }
}

/// Attach a handle to the wire subscription for `spec`, sharing an existing
/// one (increment its ref count) or declaring a new one (subscribe once, ref
/// count 1). Returns the wire id and, for an aggregate handle joining an
/// existing sub, the cached last aggregate result to resolve from at once.
async fn attach_wire<T>(
    state: &mut State<T>,
    next_wire: &AtomicU64,
    spec: SubscriptionSpec,
) -> Result<(String, Option<String>), ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    if let Some(existing) = state.wire.iter_mut().find(|w| w.spec == spec) {
        existing.refs += 1;
        return Ok((existing.wire_id.clone(), existing.last_agg.clone()));
    }
    let seq = next_wire.fetch_add(1, Ordering::Relaxed);
    let wire_id = format!("wire-{seq}");
    state.conn.subscribe_spec(&wire_id, spec.clone()).await?;
    state.wire.push(WireSub {
        wire_id: wire_id.clone(),
        spec,
        refs: 1,
        last_agg: None,
    });
    Ok((wire_id, None))
}

/// Drain the reaper queue: remove each dropped handle's driver-side entry,
/// then cancel the wire subscriptions that backed it. A local tier handle has
/// none, so its retirement is purely local. Entries are removed before any
/// send, so a transport failure can never resurrect a dropped handle.
async fn drain_dropped<T>(state: &mut State<T>, reaper: &Reaper) -> Result<(), ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let pending = {
        let mut queue = match reaper.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        core::mem::take(&mut *queue)
    };
    let mut released: Vec<String> = Vec::new();
    for sub_id in pending {
        if let Some(pos) = state.registry.iter().position(|e| e.sub_id == sub_id) {
            let entry = state.registry.remove(pos);
            for wire_id in entry.wire_ids {
                release_wire(&mut state.wire, &wire_id, &mut released);
            }
        }
        if let Some(pos) = state.values.iter().position(|e| e.sub_id == sub_id) {
            let entry = state.values.remove(pos);
            release_wire(&mut state.wire, &entry.wire_id, &mut released);
        }
    }
    for wire_id in released {
        state.conn.unsubscribe(&wire_id).await?;
    }
    Ok(())
}

/// The background pump: drains queued unsubscribes, flushes local writes,
/// takes one cancellable pump step, then refreshes every live query whose
/// tables changed. When the last [`ConnettoClient`] clone drops, the pump
/// closes the connection gracefully (transport close handshake) and exits.
///
/// A transport drop ends the pump, unless a reconnect driver is present, in
/// which case the pump recovers: backoff, fresh transport, session resume,
/// re-declared subscriptions. Local faults (session, apply, protocol) stay
/// terminal either way.
async fn pump<T, F, S>(
    shared: Arc<Shared<T>>,
    alive: Weak<ClientToken>,
    mut reconnect: Option<ReconnectDriver<F, S>>,
) where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    F: TransportFactory<Transport = T> + MaybeSend + 'static,
    S: Sleeper + MaybeSend + 'static,
{
    let mut needs_recovery = false;
    loop {
        if alive.upgrade().is_none() {
            let mut state = shared.state.lock().await;
            let _ = state.conn.close().await;
            return;
        }

        // The previous iteration lost the transport. Recover here, outside
        // the state lock, so watch and with_conn callers are only blocked
        // during the brief resume itself, never during backoff sleeps.
        if needs_recovery {
            let outcome = match reconnect.as_mut() {
                Some(driver) => recover(&shared, driver).await,
                None => Recovery::Exhausted,
            };
            match outcome {
                Recovery::Live => needs_recovery = false,
                Recovery::ReauthRequired => {
                    let _ = shared.events.send(ClientEvent::AuthenticationRequired);
                    return;
                }
                Recovery::Exhausted => {
                    let _ = shared.events.send(ClientEvent::Closed);
                    return;
                }
            }
        }

        let mut state = shared.state.lock().await;

        // 1. Unsubscribes queued by dropped handles. A send failure only
        //    marks the transport for recovery: the server-side subscription
        //    dies with the session either way, and the entry is already out
        //    of the registry, so nothing re-declares it.
        if let Err(err) = drain_dropped(&mut state, &shared.reaper).await {
            if is_disconnect(&err) {
                needs_recovery = true;
            } else {
                return;
            }
        }
        if needs_recovery {
            continue;
        }

        // 2. Auto-submit local writes committed since the last step.
        if let Err(err) = state.conn.flush().await {
            if is_disconnect(&err) {
                needs_recovery = true;
                continue;
            }
            return;
        }

        // 3. One cancellable pump step. A wake interrupts the idle wait so
        //    lock waiters (watch, with_conn, drops) get in promptly.
        let wake = Arc::clone(&shared.wake);
        match state.conn.pump_one_or(wake.notified()).await {
            // A deliberate server close: tell the app why, then take the same
            // path a dropped transport takes. The socket is gone either way.
            Ok(Some(event @ ClientEvent::ServerClosed { .. })) => {
                let _ = shared.events.send(event);
                if reconnect.is_some() {
                    needs_recovery = true;
                    continue;
                }
                let _ = shared.events.send(ClientEvent::Closed);
                return;
            }
            Ok(Some(ClientEvent::Closed)) => {
                if reconnect.is_some() {
                    needs_recovery = true;
                    continue;
                }
                let _ = shared.events.send(ClientEvent::Closed);
                return;
            }
            Ok(Some(event)) => {
                route_aggregate(&mut state, shared.as_ref(), &event);
                let _ = shared.events.send(event);
            }
            Ok(None) => {}
            Err(err) => {
                if is_disconnect(&err) {
                    needs_recovery = true;
                    continue;
                }
                return;
            }
        }

        // 4. Refresh live queries whose tables changed, from server patches
        //    and local writes alike.
        let changed = state.conn.take_changed();
        if !changed.is_empty() {
            let changed: HashSet<String> = changed.into_iter().map(|t| t.to_lowercase()).collect();
            let State {
                conn,
                registry,
                values: _,
                wire: _,
            } = &mut *state;
            for entry in registry.iter_mut() {
                if entry.tables.is_disjoint(&changed) {
                    continue;
                }
                if let Err(err) = (entry.refresh)(conn) {
                    let _ = shared.events.send(ClientEvent::NonFatal {
                        related_to: Some(entry.sub_id.clone()),
                        detail: format!("live query refresh failed: {err}"),
                    });
                }
            }
        }
    }
}

/// Route an aggregate push to its live value handle before the broadcast,
/// so observers of both see the same order.
fn route_aggregate<T>(state: &mut State<T>, shared: &Shared<T>, event: &ClientEvent)
where
    T: Transport,
{
    let ClientEvent::Aggregate {
        sub_id,
        result_json,
        ..
    } = event
    else {
        return;
    };
    // Cache the last result on the wire sub so a value handle joining later
    // resolves immediately, since the server pushes the bootstrap only once.
    if let Some(wire) = state.wire.iter_mut().find(|w| w.wire_id == *sub_id) {
        wire.last_agg = Some(result_json.clone());
    }
    // Fan out to every value handle sharing this wire sub, each with its own
    // decoder and typed value, not just the first.
    for entry in state.values.iter_mut().filter(|e| e.wire_id == *sub_id) {
        if let Err(err) = (entry.apply)(result_json) {
            let _ = shared.events.send(ClientEvent::NonFatal {
                related_to: Some(entry.sub_id.clone()),
                detail: format!("live value update failed: {err}"),
            });
        }
    }
}

/// The outcome of a reconnect sequence.
enum Recovery {
    /// The session resumed and every subscription was re-declared.
    Live,
    /// The backoff policy ran out of attempts.
    Exhausted,
    /// The credential was rejected (a refresh that could not recover it, or a
    /// handshake `AuthenticationFailed`), so retrying is futile and the driver
    /// routes to interactive re-login instead.
    ReauthRequired,
}

/// Run the reconnect sequence to completion: backoff, fresh transport,
/// session resume, re-declared subscriptions.
///
/// Sleeps and connect attempts run WITHOUT the state lock. Only the resume
/// handshake and the re-subscribes hold it, so application reads and writes
/// against the replica proceed during an outage.
async fn recover<T, F, S>(shared: &Shared<T>, driver: &mut ReconnectDriver<F, S>) -> Recovery
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    F: TransportFactory<Transport = T>,
    S: Sleeper,
{
    let mut backoff = driver.policy.initial_backoff;
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        if driver.policy.max_attempts.is_some_and(|max| attempt > max) {
            return Recovery::Exhausted;
        }
        let _ = shared.events.send(ClientEvent::Reconnecting { attempt });
        driver.sleeper.sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(driver.policy.max_backoff);

        let Ok(transport) = driver.factory.connect().await else {
            continue;
        };
        let mut state = shared.state.lock().await;
        match state.conn.resume(transport).await {
            Ok(()) => {}
            // A rejected credential is not a transport blip: stop the backoff
            // loop and let the pump surface a re-login requirement.
            Err(ClientError::Auth(_)) => return Recovery::ReauthRequired,
            Err(_) => continue,
        }
        // Re-declare every live subscription under its original id, so the
        // server streams retained changes (or a full resync) into the same
        // handles. A send failure here means the fresh transport died
        // already: try again from the top.
        let specs: Vec<(String, SubscriptionSpec)> = state
            .wire
            .iter()
            .map(|wire| (wire.wire_id.clone(), wire.spec.clone()))
            .collect();
        let mut redeclared = true;
        for (sub_id, spec) in specs {
            if state.conn.subscribe_spec(&sub_id, spec).await.is_err() {
                redeclared = false;
                break;
            }
        }
        if !redeclared {
            continue;
        }
        let _ = shared.events.send(ClientEvent::Reconnected);
        return Recovery::Live;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::prelude::*;

    diesel::table! {
        orders (id) {
            id -> BigInt,
            quantity -> BigInt,
        }
    }

    // A bound value renders as a placeholder plus a typed bind, never inline.
    #[test]
    fn render_query_emits_placeholders_and_binds() {
        let query = orders::table.filter(orders::quantity.gt(5_i64));
        let (sql, binds) = render_query(&query).expect("render");
        assert!(
            sql.contains('?'),
            "bind renders as a placeholder, got {sql}"
        );
        assert!(!sql.contains('5'), "the value must not inline, got {sql}");
        assert_eq!(binds, vec![BindValue::Integer(5)]);
    }

    // Table extraction yields the bare name whatever the quote style, so it
    // intersects the change tracker's plain table names.
    #[test]
    fn query_tables_unquotes_identifiers() {
        let parsed = parse_subscription(
            "SELECT `orders`.`id` FROM `orders` WHERE (`orders`.`quantity` > ?1)",
        )
        .expect("parse");
        assert_eq!(parsed.tables, HashSet::from(["orders".to_owned()]));
        assert_eq!(parsed.shape, QueryShape::Rows);
    }

    // Shape classification routes aggregates to watch_value and rows to watch.
    #[test]
    fn shape_classifies_aggregates_and_rows() {
        let agg = parse_subscription("SELECT COUNT(*) FROM `orders`").expect("parse");
        assert_eq!(agg.shape, QueryShape::Aggregate);
        let rows = parse_subscription("SELECT * FROM orders WHERE quantity > 0").expect("parse");
        assert_eq!(rows.shape, QueryShape::Rows);
        let grouped = parse_subscription("SELECT status, COUNT(*) FROM orders GROUP BY status")
            .expect("parse");
        assert_eq!(grouped.shape, QueryShape::Rows);
    }

    // The public aggregate-shape classifier mirrors subscription_tables: it is
    // the relay's way to route a tab Subscribe to the aggregate path instead of
    // a row snapshot, matching the client's own routing.
    #[test]
    fn subscription_is_aggregate_classifies_shape() {
        assert!(subscription_is_aggregate("SELECT COUNT(*) FROM `orders`").expect("parse"));
        assert!(subscription_is_aggregate("SELECT MIN(quantity) FROM orders").expect("parse"));
        assert!(
            !subscription_is_aggregate("SELECT * FROM orders WHERE quantity > 0").expect("parse")
        );
        assert!(
            !subscription_is_aggregate("SELECT status, COUNT(*) FROM orders GROUP BY status")
                .expect("parse")
        );
        assert!(subscription_is_aggregate("NOT SQL AT ALL (").is_err());
    }
}
