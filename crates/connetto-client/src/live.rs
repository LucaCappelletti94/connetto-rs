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
use core::task::Poll;
use core::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};

use connetto_core::messages::{BindValue, SubscriptionSpec};
use connetto_core::quote_ident;
use connetto_core::traits::{MaybeSend, Transport};
use diesel::associations::{HasTable, Identifiable};
use diesel::dsl::Find;
use diesel::query_builder::{
    AsChangeset, AsQuery, InsertStatement, IntoUpdateTarget, QueryFragment, UpdateStatement,
};
use diesel::query_dsl::RunQueryDsl;
use diesel::query_dsl::methods::{FindDsl, LoadQuery};
use diesel::sqlite::Sqlite;
use diesel::{Insertable, SqliteConnection};
use serde::de::DeserializeOwned;
use sqlparser::ast::{
    Expr, GroupByExpr, SelectItem, SetExpr, Statement, TableFactor, visit_relations,
};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use subql::backend::Value as SqliteValue;
use tokio::sync::{Mutex, Notify, broadcast, watch};

use crate::reconnect::{NoReconnect, NoSleep, ReconnectPolicy, Sleeper, TransportFactory};
use crate::subscriptions::DEFAULT_GRACE;
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
    /// A grouped aggregate projecting its group columns and one aggregate:
    /// answered by server pushes keyed by group (R84).
    Grouped,
}

/// What the client needs from a rendered subscription query: the tables it
/// reads (for targeted refresh), its shape (for answer-path routing), and,
/// for a grouped statistic, the group column names in `GROUP BY` order (what
/// a keyed handle extracts its map key with from a whole answer's objects).
struct ParsedSubscription {
    tables: HashSet<String>,
    shape: QueryShape,
    group_columns: Vec<String>,
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
/// aggregate frames rather than from the replica: a scalar aggregate or a
/// grouped statistic (R84), whose keyed frames ride the same path.
///
/// The same shape classification the pump uses to route a query to
/// [`ConnettoClient::watch_value`] or [`ConnettoClient::watch_groups`],
/// exposed so a relay serving the wire protocol from a worker-held connection
/// can route a tab `Subscribe` to the aggregate path instead of a row
/// snapshot, matching the direct client.
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
    Ok(parse_subscription(sql)?.shape != QueryShape::Rows)
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
    let (shape, group_columns) = match statements.as_slice() {
        [Statement::Query(query)] => query_shape(query),
        _ => (QueryShape::Rows, Vec::new()),
    };
    Ok(ParsedSubscription {
        tables,
        shape,
        group_columns,
    })
}

/// Whether `expr` is a call to one of the built-in aggregate functions.
fn is_aggregate_call(expr: &Expr) -> bool {
    let Expr::Function(function) = expr else {
        return false;
    };
    function
        .name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .is_some_and(|ident| AGGREGATE_FUNCTIONS.contains(&ident.value.to_lowercase().as_str()))
}

/// The lowercased column name of a plain identifier expression, unqualified
/// or table-qualified, or `None` for anything else.
fn plain_column(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(ident.value.to_lowercase()),
        Expr::CompoundIdentifier(parts) => parts.last().map(|ident| ident.value.to_lowercase()),
        _ => None,
    }
}

/// A query is aggregate-shaped when it projects exactly one ungrouped call to
/// a known scalar aggregate, mirroring the server's classification closely
/// enough to route the client's answer path. It is grouped when a plain-column
/// `GROUP BY` is projected in full alongside exactly one such call, which is
/// the shape whose whole-answer objects a keyed handle can take its map key
/// from (R84). Anything else, a `GROUP BY` over expressions or one whose
/// columns the projection hides included, stays a row query.
fn query_shape(query: &sqlparser::ast::Query) -> (QueryShape, Vec<String>) {
    let rows = (QueryShape::Rows, Vec::new());
    let SetExpr::Select(select) = query.body.as_ref() else {
        return rows;
    };
    let group_exprs = match &select.group_by {
        GroupByExpr::Expressions(exprs, mods) if mods.is_empty() => exprs,
        GroupByExpr::Expressions(..) | GroupByExpr::All(_) => return rows,
    };
    if group_exprs.is_empty() {
        if select.projection.len() != 1 {
            return rows;
        }
        let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) =
            &select.projection[0]
        else {
            return rows;
        };
        if is_aggregate_call(expr) {
            return (QueryShape::Aggregate, Vec::new());
        }
        return rows;
    }
    // Grouped: every GROUP BY entry is a plain column, and the projection is
    // exactly those columns plus one aggregate call, in any order.
    let Some(group_columns) = group_exprs
        .iter()
        .map(plain_column)
        .collect::<Option<Vec<_>>>()
    else {
        return rows;
    };
    let mut aggregates = 0_usize;
    let mut projected: Vec<String> = Vec::new();
    for item in &select.projection {
        let (SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }) = item else {
            return (QueryShape::Rows, group_columns);
        };
        if is_aggregate_call(expr) {
            aggregates += 1;
        } else if let Some(column) = plain_column(expr) {
            projected.push(column);
        } else {
            return (QueryShape::Rows, group_columns);
        }
    }
    let mut wanted = group_columns.clone();
    wanted.sort_unstable();
    projected.sort_unstable();
    if aggregates == 1 && projected == wanted {
        (QueryShape::Grouped, group_columns)
    } else {
        (QueryShape::Rows, group_columns)
    }
}

/// Decode a keyed handle's map key from the JSON array of group values with
/// serde: the bare element for a single group column (so `K = i64` or
/// `String` needs no tuple), the whole array for several (a tuple decodes
/// from it).
fn decode_group_key<K: DeserializeOwned>(json: &str) -> Result<K, ClientError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))?;
    if let serde_json::Value::Array(elements) = &value
        && let [element] = elements.as_slice()
        && let Ok(key) = serde_json::from_value(element.clone())
    {
        return Ok(key);
    }
    serde_json::from_value(value).map_err(|e| ClientError::Session(e.to_string()))
}

/// Split one whole-answer object into the key's JSON array (the group
/// columns, in `GROUP BY` order) and the one remaining member's JSON, which
/// is the aggregate value. The projection was checked at registration to be
/// exactly the group columns plus one aggregate, so a differently shaped
/// object is a fault worth naming, not a case.
fn split_whole_object(
    json: &str,
    group_columns: &[String],
) -> Result<(String, String), ClientError> {
    let serde_json::Value::Object(mut object) =
        serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))?
    else {
        return Err(ClientError::Session(format!(
            "a whole answer's element is not an object: {json}"
        )));
    };
    let mut key_values = Vec::with_capacity(group_columns.len());
    for column in group_columns {
        let Some(value) = object.remove(column) else {
            return Err(ClientError::Session(format!(
                "a whole answer's element misses group column {column}: {json}"
            )));
        };
        key_values.push(value);
    }
    let mut rest = object.into_iter();
    let (Some((_, aggregate)), None) = (rest.next(), rest.next()) else {
        return Err(ClientError::Session(format!(
            "a whole answer's element does not hold exactly one aggregate beside its group \
             columns: {json}"
        )));
    };
    Ok((
        serde_json::Value::Array(key_values).to_string(),
        aggregate.to_string(),
    ))
}

/// Build a keyed handle's map from the rested rows of its statistic, both
/// resting shapes admitted: a keyed row decodes from the group values beside
/// its key, a whole answer's positional row from its object by group column
/// name. Returns the map and the newest row's as-of time.
fn build_groups_map<K, V>(
    rows: &[crate::aggregates::RestedGroup],
    group_columns: &[String],
    decode_key: fn(&str) -> Result<K, ClientError>,
    decode_value: fn(&str) -> Result<V, ClientError>,
) -> Result<(HashMap<K, V>, Option<i64>), ClientError>
where
    K: Eq + core::hash::Hash,
{
    let mut map = HashMap::with_capacity(rows.len());
    let mut as_of: Option<i64> = None;
    for row in rows {
        as_of = as_of.max(Some(row.updated_at));
        let (key, value) = if let Some(values) = &row.group_values_json {
            (decode_key(values)?, decode_value(&row.result_json)?)
        } else {
            let (key_json, value_json) = split_whole_object(&row.result_json, group_columns)?;
            (decode_key(&key_json)?, decode_value(&value_json)?)
        };
        map.insert(key, value);
    }
    Ok((map, as_of))
}

/// Decode a row-shaped handle's answer from the rested rows of its
/// statistic, in stored order (answer order for a whole answer's positional
/// rows, key order for a keyed row set). Every body is one row's JSON
/// object, whichever tier rested it. Returns the rows and the newest row's
/// as-of time.
fn decode_rested_rows<R: DeserializeOwned>(
    rows: &[crate::aggregates::RestedGroup],
) -> Result<(Vec<R>, Option<i64>), ClientError> {
    let mut decoded = Vec::with_capacity(rows.len());
    let mut as_of: Option<i64> = None;
    for row in rows {
        as_of = as_of.max(Some(row.updated_at));
        decoded.push(
            serde_json::from_str(&row.result_json)
                .map_err(|e| ClientError::Session(e.to_string()))?,
        );
    }
    Ok((decoded, as_of))
}

/// Refuse a scalar value watch whose rendered SQL is not a scalar aggregate,
/// naming the right method, unless a type-level marker already proved the
/// shape.
fn require_scalar_shape(
    shape: ShapeSource,
    parsed: &ParsedSubscription,
) -> Result<(), ClientError> {
    if matches!(shape, ShapeSource::Marker) {
        return Ok(());
    }
    match parsed.shape {
        QueryShape::Aggregate => Ok(()),
        QueryShape::Grouped => Err(ClientError::Session(
            "grouped aggregate: use watch_groups, one scalar cannot carry a keyed result"
                .to_owned(),
        )),
        QueryShape::Rows => Err(ClientError::Session(
            "row query: use watch, a row projection is answered from the replica".to_owned(),
        )),
    }
}

/// Refuse a grouped watch unless the rendered SQL proves the runtime grouped
/// shape, or a type-level marker already proved the aggregate and the parser
/// can still name every plain group column needed to rebuild a whole answer.
fn require_grouped_shape(
    shape: ShapeSource,
    parsed: &ParsedSubscription,
) -> Result<(), ClientError> {
    if matches!(shape, ShapeSource::Marker) {
        return if parsed.group_columns.is_empty() {
            Err(ClientError::Session(
                "typed grouped statistic: GROUP BY expressions must be plain projected columns"
                    .to_owned(),
            ))
        } else {
            Ok(())
        };
    }
    match parsed.shape {
        QueryShape::Grouped => Ok(()),
        QueryShape::Aggregate => Err(ClientError::Session(
            "scalar aggregate: use watch_value, there is no group to key on".to_owned(),
        )),
        QueryShape::Rows => Err(ClientError::Session(
            "not a grouped statistic: watch_groups needs a plain-column GROUP BY projected in \
             full beside exactly one aggregate"
                .to_owned(),
        )),
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
        .map(|table| SubscriptionSpec::new(format!("SELECT * FROM {}", quote_ident(table))))
        .collect()
}

/// What one subscription still wants from the replica.
pub(crate) struct Coverage {
    /// Lowercased replica tables the subscription reads.
    pub tables: HashSet<String>,
    /// Its `WHERE` clause with every bind already a literal, or `None` when it
    /// has none and therefore covers the whole table.
    pub predicate: Option<String>,
}

/// The coverage a row subscription contributes, or `None` for an aggregate,
/// which holds no replica rows.
///
/// Binds are inlined into the whole statement before parsing, not into the
/// extracted clause afterwards, because a placeholder anywhere ahead of the
/// `WHERE` would otherwise shift every value in it by one.
///
/// Pagination needs no special handling here and gets none: taking the `WHERE`
/// clause alone already discards `LIMIT`, `OFFSET` and `FETCH`, so a paginated
/// subscription contributes the predicate its page was drawn from. That
/// protects a superset of what it was actually delivered, which can only keep
/// too much, never too little.
pub(crate) fn coverage_of(spec: &SubscriptionSpec) -> Result<Option<Coverage>, ClientError> {
    let sql = inline_binds(&spec.query, &spec.binds)?;
    let parsed = parse_subscription(&sql)?;
    if matches!(parsed.shape, QueryShape::Aggregate | QueryShape::Grouped) {
        return Ok(None);
    }
    let statements = Parser::parse_sql(&SQLiteDialect {}, &sql)
        .map_err(|err| ClientError::Session(err.to_string()))?;
    // Only the outer query's own tables cover this subscription's rows. A
    // membership term reads a second table inside an `IN (SELECT ...)`, which
    // `visit_relations` (and so `parsed.tables`) collects for refresh routing,
    // but a changed row of that table is never a row of the subscribed table,
    // so a departure there must not be tested against this predicate.
    let (tables, predicate) = match statements.as_slice() {
        [Statement::Query(query)] => match query.body.as_ref() {
            SetExpr::Select(select) => (
                outer_tables(select),
                select.selection.as_ref().map(ToString::to_string),
            ),
            _ => (parsed.tables, None),
        },
        _ => (parsed.tables, None),
    };
    Ok(Some(Coverage { tables, predicate }))
}

/// The base tables named in a query's own `FROM` and `JOIN`s, excluding any
/// relation that appears only inside a subquery. A membership term's `IN
/// (SELECT ... FROM member_table ...)` names `member_table`, which belongs to
/// refresh routing but not to the set whose row departures this subscription
/// answers for.
fn outer_tables(select: &sqlparser::ast::Select) -> HashSet<String> {
    let mut tables = HashSet::new();
    for from in &select.from {
        collect_relation(&from.relation, &mut tables);
        for join in &from.joins {
            collect_relation(&join.relation, &mut tables);
        }
    }
    tables
}

/// Insert the lowercased base-table name a [`TableFactor`] names, if it names
/// one. A derived table (a subquery in `FROM`) names none and is skipped.
fn collect_relation(relation: &TableFactor, tables: &mut HashSet<String>) {
    if let TableFactor::Table { name, .. } = relation
        && let Some(ident) = name.0.last().and_then(|part| part.as_ident())
    {
        tables.insert(ident.value.to_lowercase());
    }
}

/// One SQL literal for a wire value, so a primary key can be matched inside a
/// statement that has no bind list.
pub(crate) fn bind_literal_of(
    value: &sqlite_diff_rs::Value<String, Vec<u8>>,
) -> Result<String, ClientError> {
    bind_literal(&match value {
        sqlite_diff_rs::Value::Null => BindValue::Null,
        sqlite_diff_rs::Value::Integer(int) => BindValue::Integer(*int),
        sqlite_diff_rs::Value::Real(real) => BindValue::Real(*real),
        sqlite_diff_rs::Value::Text(text) => BindValue::Text(text.clone()),
        sqlite_diff_rs::Value::Blob(blob) => BindValue::Blob(blob.clone()),
    })
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

/// What [`LiveQuery`] and [`LiveValue`] both are underneath: a subscription
/// id, the wake signal its refreshes arrive on, and the queue that unsubscribes
/// it when the handle goes.
///
/// Dropping this is what queues the unsubscribe, so it is the last field of
/// each handle rather than a duplicated `Drop` on each.
struct LiveHandleCore {
    sub_id: String,
    changed: watch::Receiver<u64>,
    reaper: Arc<Reaper>,
}

impl LiveHandleCore {
    fn new(sub_id: String, changed: watch::Receiver<u64>, reaper: &Arc<Reaper>) -> Self {
        Self {
            sub_id,
            changed,
            reaper: Arc::clone(reaper),
        }
    }

    fn sub_id(&self) -> &str {
        &self.sub_id
    }

    async fn changed(&mut self) -> Result<(), ClientError> {
        self.changed
            .changed()
            .await
            .map_err(|_| ClientError::Transport("live query driver stopped".to_owned()))
    }
}

impl Drop for LiveHandleCore {
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

/// A rested scalar and when it was last synced: the pair a [`LiveValue`]
/// holds. The as-of time is the stored `updated_at` on the local clock, so
/// the application judges staleness by its age plus the connection-state
/// events it already receives (R83 decision 6).
struct Rested<V> {
    value: Option<V>,
    as_of: Option<i64>,
}

impl<V> Default for Rested<V> {
    fn default() -> Self {
        Self {
            value: None,
            as_of: None,
        }
    }
}

/// Driver-side apply callback of one live value: decode the value and publish
/// it with its as-of time. Both come from the resting table, the one home for
/// the last value, so a live push and a bootstrap take the same path. `None`
/// clears the value (the addressed key left the result set) and the as-of with
/// it.
type ApplyValue = Box<dyn FnMut(Option<&str>, Option<i64>) -> Result<(), ClientError> + Send>;

/// One live value handle's driver-side state, with the id of the shared wire
/// subscription that feeds it (the target of aggregate pushes and what a drop
/// releases a reference on).
struct ValueEntry {
    sub_id: String,
    wire_id: String,
    apply: ApplyValue,
}

/// Apply the full rested row set of a computed statistic to one handle (a
/// keyed grouped map or a row-shaped answer). Called by the pump with the
/// rows it just re-read after any frame of the statistic, so delta, removal,
/// and whole-answer replacement all take the same path and a handle never
/// sees which tier served it (R84, decision 4).
type ApplyComputed =
    Box<dyn FnMut(&[crate::aggregates::RestedGroup]) -> Result<(), ClientError> + Send>;

/// One computed handle's driver-side state, with the id of the shared wire
/// subscription that feeds it.
struct ComputedEntry {
    sub_id: String,
    wire_id: String,
    apply: ApplyComputed,
}

/// One shared wire subscription: declared once on the wire under `wire_id`,
/// reference counted across every row and value handle that resolved to the
/// same `spec`. The last aggregate value no longer lives here: R83 rests it in
/// `_connetto_aggregates`, so a late joiner and a restart both bootstrap
/// through that one row.
struct WireSub {
    wire_id: String,
    spec: SubscriptionSpec,
    refs: usize,
}

/// The connection and the live registries, guarded together so a refresh
/// always sees the replica state the pump just produced. `wire` is the
/// ref-counted layer beneath the handles: identical queries share one entry,
/// so the client opens one wire subscription per distinct query.
struct State<T: Transport> {
    conn: ConnettoConnection<T>,
    registry: Vec<LiveEntry<T>>,
    values: Vec<ValueEntry>,
    computed: Vec<ComputedEntry>,
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
    /// Whether the replica has ever received data from a server, shared with
    /// every live handle. Updated where the cursor is observed rather than
    /// where queries refresh, so it holds for a first sync that delivers no
    /// rows and therefore refreshes nothing.
    ever_synced: Arc<AtomicBool>,
}

impl<T: Transport> Shared<T> {
    /// Take the state lock, interrupting the pump's idle wait.
    ///
    /// Queue first, then wake: the fair mutex hands the pump's released lock
    /// to an already queued caller before the pump can take it back. Waking
    /// before queueing races instead: the pump can consume the wake, finish
    /// its cycle, re-acquire the lock, and park on a fresh wake future all
    /// inside the caller's descheduling window, after which the caller queues
    /// on a lock the idle pump holds forever. CPU-starved CI hit exactly that.
    async fn lock_interrupting(&self) -> tokio::sync::MutexGuard<'_, State<T>> {
        let mut lock = core::pin::pin!(self.state.lock());
        let first = core::future::poll_fn(|cx| Poll::Ready(lock.as_mut().poll(cx))).await;
        match first {
            Poll::Ready(guard) => guard,
            Poll::Pending => {
                self.wake.notify_one();
                lock.await
            }
        }
    }
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
    handle: LiveHandleCore,
    rows: Arc<RwLock<Vec<R>>>,
    /// Whether this query reads any synced table. False for a query over
    /// device-private tables alone, whose rows never depended on a server.
    reads_synced: bool,
    ever_synced: Arc<AtomicBool>,
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
        self.handle.sub_id()
    }

    /// Whether these rows come from a replica that has never synced.
    ///
    /// True only while this query reads synced tables and no server has ever
    /// answered. An empty result then means the rows were never fetched, not
    /// that there are none, and the application picks the sentence to show.
    /// Always false for a query over device-private tables alone.
    ///
    /// Turns false for good on the first sync, including one that delivers no
    /// rows, which is what separates a loaded empty set from an unloaded one.
    #[must_use]
    pub fn never_synced(&self) -> bool {
        self.reads_synced && !self.ever_synced.load(Ordering::Relaxed)
    }

    /// Wait until the rows change. Resolves once per refresh that actually
    /// altered the result set, coalescing bursts.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.handle.changed().await
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
    handle: LiveHandleCore,
    value: Arc<RwLock<Rested<V>>>,
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
    /// The current value, or `None` before any value has arrived. On an
    /// offline restart this is the last synced value read from the resting
    /// table, not `None`, which is the whole of R83.
    #[must_use]
    pub fn value(&self) -> Option<V> {
        self.value.read().map_or_else(
            |poisoned| poisoned.into_inner().value.clone(),
            |slot| slot.value.clone(),
        )
    }

    /// When the current value was last synced, in seconds since the epoch on
    /// the local clock, or `None` while no value has arrived. The application
    /// judges staleness from its age together with the connection-state
    /// events it already receives (R83 decision 6).
    #[must_use]
    pub fn as_of_secs(&self) -> Option<i64> {
        self.value
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().as_of, |slot| slot.as_of)
    }
}

impl<V> LiveValue<V> {
    /// The subscription id backing this handle.
    #[must_use]
    pub fn sub_id(&self) -> &str {
        self.handle.sub_id()
    }

    /// Wait until the value changes, the initial bootstrap included.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.handle.changed().await
    }
}

/// A grouped statistic and when it was last synced: the pair a [`LiveGroups`]
/// holds. Empty until the server's seed arrives (or a rested set bootstraps
/// it offline), like the scalar's `None`.
struct RestedGroups<K, V> {
    map: HashMap<K, V>,
    as_of: Option<i64>,
}

impl<K, V> Default for RestedGroups<K, V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            as_of: None,
        }
    }
}

/// A server-maintained grouped aggregate kept fresh by the client's pump, one
/// entry per group (R84).
///
/// Created by [`ConnettoClient::watch_groups`] for grouped aggregate queries.
/// The replica holds only this client's authorized rows, so it cannot answer
/// a global statistic: the map comes exclusively from server pushes, resting
/// in `_connetto_aggregates` (R83), so an offline restart shows the last
/// synced map. A fold delta upserts one entry, a group's departure removes
/// one, and a server-side demotion to whole answers rebuilds the map without
/// surfacing as a distinct state. Dropping the handle queues the server
/// unsubscribe, exactly like [`LiveQuery`].
pub struct LiveGroups<K, V> {
    handle: LiveHandleCore,
    state: Arc<RwLock<RestedGroups<K, V>>>,
}

impl<K, V> LiveHandle for LiveGroups<K, V>
where
    K: Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    type Snapshot = HashMap<K, V>;

    fn snapshot(&self) -> HashMap<K, V> {
        self.map()
    }

    fn changed(&mut self) -> impl core::future::Future<Output = Result<(), ClientError>> + Send {
        LiveGroups::changed(self)
    }

    fn sub_id(&self) -> &str {
        LiveGroups::sub_id(self)
    }
}

impl<K: Clone, V: Clone> LiveGroups<K, V> {
    /// The current map, one entry per group. Empty before any value has
    /// arrived. On an offline restart this is the last synced map read from
    /// the resting table, not empty, which is R83 extended to groups.
    #[must_use]
    pub fn map(&self) -> HashMap<K, V> {
        self.state.read().map_or_else(
            |poisoned| poisoned.into_inner().map.clone(),
            |slot| slot.map.clone(),
        )
    }

    /// When the map was last synced, in seconds since the epoch on the local
    /// clock, or `None` while nothing has arrived. The application judges
    /// staleness from its age together with the connection-state events it
    /// already receives (R83 decision 6).
    #[must_use]
    pub fn as_of_secs(&self) -> Option<i64> {
        self.state
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().as_of, |slot| slot.as_of)
    }
}

impl<K, V> LiveGroups<K, V> {
    /// The subscription id backing this handle.
    #[must_use]
    pub fn sub_id(&self) -> &str {
        self.handle.sub_id()
    }

    /// Wait until the map changes, the initial seed included.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.handle.changed().await
    }
}

/// A rested row-shaped answer and when it was last synced: the pair a
/// [`LiveRows`] holds.
struct RestedRows<R> {
    rows: Vec<R>,
    as_of: Option<i64>,
}

impl<R> Default for RestedRows<R> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            as_of: None,
        }
    }
}

/// A server-computed row answer kept fresh by the client's pump (R84).
///
/// Created by [`ConnettoClient::watch_rows`] for row-shaped queries the
/// server re-executes rather than syncing (joins, `DISTINCT`, expression
/// projections). The whole answer replaces the rows on every move: there are
/// no per-row patches to a computed result. Each answer rests in
/// `_connetto_aggregates` (R83), so an offline restart shows the last synced
/// rows. Dropping the handle queues the server unsubscribe, exactly like
/// [`LiveQuery`].
pub struct LiveRows<R> {
    handle: LiveHandleCore,
    state: Arc<RwLock<RestedRows<R>>>,
}

impl<R: Clone + Send + Sync> LiveHandle for LiveRows<R> {
    type Snapshot = Vec<R>;

    fn snapshot(&self) -> Vec<R> {
        self.rows()
    }

    fn changed(&mut self) -> impl core::future::Future<Output = Result<(), ClientError>> + Send {
        LiveRows::changed(self)
    }

    fn sub_id(&self) -> &str {
        LiveRows::sub_id(self)
    }
}

impl<R: Clone> LiveRows<R> {
    /// The current answer, in the order the server produced it. Empty before
    /// any answer has arrived. On an offline restart this is the last synced
    /// answer read from the resting table, not empty.
    #[must_use]
    pub fn rows(&self) -> Vec<R> {
        self.state.read().map_or_else(
            |poisoned| poisoned.into_inner().rows.clone(),
            |slot| slot.rows.clone(),
        )
    }

    /// When the answer was last synced, in seconds since the epoch on the
    /// local clock, or `None` while nothing has arrived (R83 decision 6).
    #[must_use]
    pub fn as_of_secs(&self) -> Option<i64> {
        self.state
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().as_of, |slot| slot.as_of)
    }
}

impl<R> LiveRows<R> {
    /// The subscription id backing this handle.
    #[must_use]
    pub fn sub_id(&self) -> &str {
        self.handle.sub_id()
    }

    /// Wait until the answer changes, the initial one included.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the driving [`ConnettoClient`] is gone.
    pub async fn changed(&mut self) -> Result<(), ClientError> {
        self.handle.changed().await
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
        mut conn: ConnettoConnection<T>,
        reconnect: Option<ReconnectDriver<F, S>>,
    ) -> (Self, impl Future<Output = ()>)
    where
        F: TransportFactory<Transport = T> + MaybeSend + 'static,
        S: Sleeper + MaybeSend + 'static,
    {
        let wake = Arc::new(Notify::new());
        let (events, _) = broadcast::channel(256);
        let ever_synced = Arc::new(AtomicBool::new(conn.has_ever_synced()));
        // Seeded from what a previous run left declared, so watching the same
        // query again re-claims its record instead of minting a second one for
        // the same text, and so a fresh id can never collide with a stored one.
        let declared = conn.declared_subscriptions().unwrap_or_default();
        let next_wire = declared
            .iter()
            .filter_map(|(id, _)| id.strip_prefix(WIRE_PREFIX))
            .filter_map(|n| n.parse::<u64>().ok())
            .max()
            .map_or(1, |max| max.saturating_add(1));
        let wire: Vec<WireSub> = declared
            .into_iter()
            .map(|(wire_id, spec)| WireSub {
                wire_id,
                spec,
                // Nothing in this run holds them yet. A watch that re-claims
                // one takes the count to one, and one never claimed stays here
                // for R15's grace to retire.
                refs: 0,
            })
            .collect();
        let shared = Arc::new(Shared {
            ever_synced,
            state: Mutex::new(State {
                conn,
                registry: Vec::new(),
                values: Vec::new(),
                computed: Vec::new(),
                wire,
            }),
            wake: Arc::clone(&wake),
            reaper: Arc::new(Reaper {
                pending: StdMutex::new(Vec::new()),
                wake: Arc::clone(&wake),
            }),
            events,
            next_live: AtomicU64::new(1),
            next_wire: AtomicU64::new(next_wire),
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

    /// Run a diesel query and keep its result fresh, choosing how long the
    /// subscription outlives its last handle. See
    /// [`watch_fn_with_grace`](Self::watch_fn_with_grace).
    ///
    /// # Errors
    ///
    /// Same as [`watch`](Self::watch).
    pub async fn watch_with_grace<Q, R>(
        &self,
        query: Q,
        grace: Duration,
    ) -> Result<LiveQuery<R>, ClientError>
    where
        Q: QueryFragment<Sqlite> + Clone + Send + 'static,
        Q: for<'query> LoadQuery<'query, SqliteConnection, R>,
        R: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_fn_with_grace(move || query.clone(), grace).await
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
        self.watch_fn_with_grace(build, DEFAULT_GRACE).await
    }

    /// Run a diesel query and keep its result fresh, choosing how long the
    /// subscription outlives its last handle.
    ///
    /// The default is [`crate::DEFAULT_GRACE`] and the ceiling is
    /// [`crate::MAX_GRACE`], above
    /// which the request is clamped: wanting to outlive the cap is by
    /// definition a pin, so use [`pin`](Self::pin) for that. A zero grace ends
    /// the subscription the moment the last handle drops, which is what the
    /// behaviour was before graces existed.
    ///
    /// # Errors
    ///
    /// Same as [`watch_fn`](Self::watch_fn).
    pub async fn watch_fn_with_grace<F, Q, R>(
        &self,
        build: F,
        grace: Duration,
    ) -> Result<LiveQuery<R>, ClientError>
    where
        F: Fn() -> Q + Send + 'static,
        Q: QueryFragment<Sqlite>,
        Q: for<'query> LoadQuery<'query, SqliteConnection, R>,
        R: Clone + PartialEq + Send + Sync + 'static,
    {
        let mut state = self.shared.lock_interrupting().await;
        self.register_watch(&mut state, build, grace).await
    }

    /// Register a live query against already-locked state: render it, read the
    /// initial rows, wire the subscription, and return the handle. Shared by
    /// [`watch_fn_with_grace`](Self::watch_fn_with_grace) and the write-and-keep
    /// surface, so an insert and the watch over its row land under one lock.
    async fn register_watch<F, Q, R>(
        &self,
        state: &mut State<T>,
        build: F,
        grace: Duration,
    ) -> Result<LiveQuery<R>, ClientError>
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
        // A grouped statistic over complete local tables is an ordinary row
        // query the replica answers exactly, so only the synced case routes
        // away.
        if parsed.shape == QueryShape::Grouped
            && parsed
                .tables
                .intersection(state.conn.local_tables())
                .count()
                != parsed.tables.len()
        {
            return Err(ClientError::Session(
                "grouped statistic: use watch_groups, the replica cannot answer a global \
                 statistic as rows"
                    .to_owned(),
            ));
        }
        let tables = parsed.tables;
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");

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
            let wire_id = attach_wire(state, &self.shared.next_wire, spec, grace).await?;
            wire_ids.push(wire_id);
        }
        let reads_synced = !wire_ids.is_empty();
        state.registry.push(LiveEntry {
            sub_id: sub_id.clone(),
            tables,
            refresh,
            wire_ids,
        });

        Ok(LiveQuery {
            handle: LiveHandleCore::new(sub_id, rx, &self.shared.reaper),
            rows,
            reads_synced,
            ever_synced: Arc::clone(&self.shared.ever_synced),
        })
    }

    /// Insert `values` and keep the inserted row live: the returned
    /// [`LiveQuery`] tracks exactly that row, so it survives eviction while any
    /// handle holds it and reports the row vanishing when it is deleted.
    ///
    /// The table is the value's own, inferred at the type level from the
    /// returned row rather than named. The insert appends a `RETURNING` clause,
    /// reads the primary key from the row's [`Identifiable`] impl, and watches
    /// `table.find(key)`. Single-column primary keys only: a composite key uses
    /// the two-call pattern (`with_conn` write, then `watch(table.find(key))`).
    ///
    /// Until the server acknowledges this write the row is spared eviction by
    /// the pending-write guard, so the write and the watch need not be atomic
    /// even though they share one lock here (R15 step 4).
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the insert or the watch registration fails.
    pub async fn insert_watched_with_grace<V, R, K>(
        &self,
        values: V,
        grace: Duration,
    ) -> Result<(R, LiveQuery<R>), ClientError>
    where
        V: Insertable<R::Table>,
        R: HasTable + Clone + PartialEq + Send + Sync + 'static,
        for<'a> &'a R: Identifiable<Id = &'a K>,
        K: Clone + Send + Sync + 'static,
        R::Table: FindDsl<K> + Send + 'static,
        Find<R::Table, K>: QueryFragment<Sqlite> + for<'q> LoadQuery<'q, SqliteConnection, R>,
        InsertStatement<R::Table, <V as Insertable<R::Table>>::Values>:
            for<'q> LoadQuery<'q, SqliteConnection, R>,
    {
        let mut state = self.shared.lock_interrupting().await;
        let row: R = diesel::insert_into(<R as HasTable>::table())
            .values(values)
            .get_result(state.conn.conn())
            .map_err(|e| ClientError::Session(e.to_string()))?;
        let key: K = (*Identifiable::id(&row)).clone();
        let live = self
            .register_watch(
                &mut state,
                move || <R as HasTable>::table().find(key.clone()),
                grace,
            )
            .await?;
        Ok((row, live))
    }

    /// Insert `values` and keep the inserted row live with the default grace.
    /// See [`insert_watched_with_grace`](Self::insert_watched_with_grace).
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the insert or the watch registration fails.
    pub async fn insert_watched<V, R, K>(&self, values: V) -> Result<(R, LiveQuery<R>), ClientError>
    where
        V: Insertable<R::Table>,
        R: HasTable + Clone + PartialEq + Send + Sync + 'static,
        for<'a> &'a R: Identifiable<Id = &'a K>,
        K: Clone + Send + Sync + 'static,
        R::Table: FindDsl<K> + Send + 'static,
        Find<R::Table, K>: QueryFragment<Sqlite> + for<'q> LoadQuery<'q, SqliteConnection, R>,
        InsertStatement<R::Table, <V as Insertable<R::Table>>::Values>:
            for<'q> LoadQuery<'q, SqliteConnection, R>,
    {
        self.insert_watched_with_grace(values, DEFAULT_GRACE).await
    }

    /// Insert `values` and pin the inserted row under `name`, the durable form
    /// of keeping a written row: it survives restarts and being offline until
    /// [`unpin`](Self::unpin). Returns the inserted row.
    ///
    /// The table is inferred from the row and its primary key read from the
    /// row's [`Identifiable`] impl, as in [`insert_watched`](Self::insert_watched).
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the insert or the pin fails.
    pub async fn insert_pinned<V, R, K>(&self, name: &str, values: V) -> Result<R, ClientError>
    where
        V: Insertable<R::Table>,
        R: HasTable,
        for<'a> &'a R: Identifiable<Id = &'a K>,
        K: Clone,
        R::Table: FindDsl<K>,
        Find<R::Table, K>: QueryFragment<Sqlite>,
        InsertStatement<R::Table, <V as Insertable<R::Table>>::Values>:
            for<'q> LoadQuery<'q, SqliteConnection, R>,
    {
        let mut state = self.shared.lock_interrupting().await;
        let row: R = diesel::insert_into(<R as HasTable>::table())
            .values(values)
            .get_result(state.conn.conn())
            .map_err(|e| ClientError::Session(e.to_string()))?;
        let key: K = (*Identifiable::id(&row)).clone();
        let query = <R as HasTable>::table().find(key);
        let (sql, binds) = render_query(&query)?;
        let spec = SubscriptionSpec::new(sql).with_binds(binds);
        let wire_id = attach_wire(
            &mut state,
            &self.shared.next_wire,
            spec.clone(),
            DEFAULT_GRACE,
        )
        .await?;
        state.conn.pin_subscription(name, &wire_id, &spec)?;
        Ok(row)
    }

    /// Update the rows `target` names and keep the updated row live: the update
    /// twin of [`insert_watched`](Self::insert_watched). `target` is an
    /// identifiable row reference or a `table.find(key)`, `changeset` the diesel
    /// change to apply. Returns the updated row and a [`LiveQuery`] over it.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the update or the watch registration fails.
    pub async fn update_watched<Tgt, C, R, K>(
        &self,
        target: Tgt,
        changeset: C,
    ) -> Result<(R, LiveQuery<R>), ClientError>
    where
        Tgt: IntoUpdateTarget,
        C: AsChangeset<Target = <Tgt as HasTable>::Table>,
        R: HasTable + Clone + PartialEq + Send + Sync + 'static,
        for<'a> &'a R: Identifiable<Id = &'a K>,
        K: Clone + Send + Sync + 'static,
        R::Table: FindDsl<K> + Send + 'static,
        Find<R::Table, K>: QueryFragment<Sqlite> + for<'q> LoadQuery<'q, SqliteConnection, R>,
        UpdateStatement<
            <Tgt as HasTable>::Table,
            <Tgt as IntoUpdateTarget>::WhereClause,
            <C as AsChangeset>::Changeset,
        >: AsQuery + for<'q> LoadQuery<'q, SqliteConnection, R>,
    {
        let mut state = self.shared.lock_interrupting().await;
        let row: R = diesel::update(target)
            .set(changeset)
            .get_result(state.conn.conn())
            .map_err(|e| ClientError::Session(e.to_string()))?;
        let key: K = (*Identifiable::id(&row)).clone();
        let live = self
            .register_watch(
                &mut state,
                move || <R as HasTable>::table().find(key.clone()),
                DEFAULT_GRACE,
            )
            .await?;
        Ok((row, live))
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
        require_scalar_shape(shape, &parsed)?;
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");

        let value = Arc::new(RwLock::new(Rested::<V>::default()));
        let (tx, rx) = watch::channel(0_u64);
        let apply_value = Arc::clone(&value);
        let mut apply: ApplyValue = Box::new(move |json: Option<&str>, as_of: Option<i64>| {
            let fresh: Option<V> = json.map(decode).transpose()?;
            let changed = {
                let mut slot = match apply_value.write() {
                    Ok(slot) => slot,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let changed = slot.value != fresh;
                slot.value = fresh;
                slot.as_of = as_of;
                changed
            };
            if changed {
                tx.send_modify(|generation| *generation += 1);
            }
            Ok(())
        });

        let mut state = self.shared.lock_interrupting().await;

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
            let now = state.conn.now_secs()?;
            let bootstrap = decode(&run_probe(state.conn.conn(), &probe)?)?;
            match value.write() {
                Ok(mut slot) => {
                    slot.value = Some(bootstrap);
                    slot.as_of = Some(now);
                }
                Err(poisoned) => {
                    let mut slot = poisoned.into_inner();
                    slot.value = Some(bootstrap);
                    slot.as_of = Some(now);
                }
            }
            let refresh = Box::new(move |conn: &mut ConnettoConnection<T>| {
                let now = conn.now_secs()?;
                apply(Some(&run_probe(conn.conn(), &probe)?), Some(now))
            });
            state.registry.push(LiveEntry {
                sub_id: sub_id.clone(),
                tables: parsed.tables,
                refresh,
                wire_ids: Vec::new(),
            });
            return Ok(LiveValue {
                handle: LiveHandleCore::new(sub_id, rx, &self.shared.reaper),
                value,
            });
        }

        // Bootstrap from the resting table before subscribing, so both cases,
        // a same-run late joiner and an offline restart, resolve through the
        // one rested row rather than a run-local cache (R83 decision 3). The
        // server's next push overwrites it. Set the slot directly, with no
        // generation bump, so the first changed() still waits for a real
        // change, like any bootstrap.
        if let Some((json, updated_at)) = state.conn.rested_scalar(&sql, &binds)? {
            let bootstrap = decode(&json)?;
            match value.write() {
                Ok(mut slot) => {
                    slot.value = Some(bootstrap);
                    slot.as_of = Some(updated_at);
                }
                Err(poisoned) => {
                    let mut slot = poisoned.into_inner();
                    slot.value = Some(bootstrap);
                    slot.as_of = Some(updated_at);
                }
            }
        }
        let spec = SubscriptionSpec::new(sql).with_binds(binds);
        // No grace for an aggregate. The grace exists so a re-watch does not
        // re-pay a snapshot, but an aggregate handle holds no replica rows and
        // its value rests durably in `_connetto_aggregates`, so keeping the
        // subscription alive across a drop would buy nothing the resting table
        // does not already give.
        let wire_id = attach_wire(&mut state, &self.shared.next_wire, spec, Duration::ZERO).await?;
        state.values.push(ValueEntry {
            sub_id: sub_id.clone(),
            wire_id,
            apply,
        });

        Ok(LiveValue {
            handle: LiveHandleCore::new(sub_id, rx, &self.shared.reaper),
            value,
        })
    }

    /// Watch a grouped aggregate as a live map, one entry per group,
    /// decoding the key and the value with serde (R84).
    ///
    /// The query must project its group columns and exactly one aggregate,
    /// for example `SELECT status, COUNT(*) FROM orders GROUP BY status`,
    /// which is what lets a whole-answer demotion rebuild the map. `K`
    /// decodes from the group values the server pushes beside each key: the
    /// bare value for a single group column, a JSON array in `GROUP BY` order
    /// for several (a tuple decodes from it). `V` decodes from the aggregate
    /// value with plain serde: for a wire-lenient decode (the `SUM`
    /// accumulator's float rendering, `NUMERIC` extremes as strings), pass a
    /// [`AggregateWire`](crate::dsl::AggregateWire) decoder through
    /// [`watch_groups_with`](Self::watch_groups_with).
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, is not
    /// grouped-aggregate-shaped, reads a local table (a local tier is
    /// complete, so `watch` answers it as rows), or the subscribe frame
    /// cannot be sent. A server-side refusal arrives later as
    /// [`ClientEvent::NonFatal`] on [`events`](Self::events).
    pub async fn watch_groups<Q, K, V>(&self, query: Q) -> Result<LiveGroups<K, V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        K: DeserializeOwned + Eq + core::hash::Hash + Clone + PartialEq + Send + Sync + 'static,
        V: DeserializeOwned + Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_groups_with(query, decode_group_key::<K>, |json| {
            serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))
        })
        .await
    }

    /// Watch a grouped aggregate, decoding key and value with caller-supplied
    /// decoders. The decoder-parameterized peer of
    /// [`watch_groups`](Self::watch_groups): `decode_key` receives the JSON
    /// array of group values in `GROUP BY` order, `decode_value` one
    /// aggregate value's JSON.
    ///
    /// # Errors
    ///
    /// See [`watch_groups`](Self::watch_groups).
    pub async fn watch_groups_with<Q, K, V>(
        &self,
        query: Q,
        decode_key: fn(&str) -> Result<K, ClientError>,
        decode_value: fn(&str) -> Result<V, ClientError>,
    ) -> Result<LiveGroups<K, V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        K: Eq + core::hash::Hash + Clone + PartialEq + Send + Sync + 'static,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_groups_core(query, decode_key, decode_value, ShapeSource::Sql)
            .await
    }

    /// The typed `live()` grouped entry: diesel proved the grouped aggregate
    /// shape, so only the plain-column requirement needed for whole-answer
    /// rebuilds remains a runtime check.
    pub(crate) async fn watch_groups_typed<Q, K, V>(
        &self,
        query: Q,
        decode_key: fn(&str) -> Result<K, ClientError>,
        decode_value: fn(&str) -> Result<V, ClientError>,
    ) -> Result<LiveGroups<K, V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        K: Eq + core::hash::Hash + Clone + PartialEq + Send + Sync + 'static,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        self.watch_groups_core(query, decode_key, decode_value, ShapeSource::Marker)
            .await
    }

    async fn watch_groups_core<Q, K, V>(
        &self,
        query: Q,
        decode_key: fn(&str) -> Result<K, ClientError>,
        decode_value: fn(&str) -> Result<V, ClientError>,
        shape: ShapeSource,
    ) -> Result<LiveGroups<K, V>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        K: Eq + core::hash::Hash + Clone + PartialEq + Send + Sync + 'static,
        V: Clone + PartialEq + Send + Sync + 'static,
    {
        let (sql, binds) = render_query(&query)?;
        let parsed = parse_subscription(&sql)?;
        require_grouped_shape(shape, &parsed)?;
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");
        let groups_state = Arc::new(RwLock::new(RestedGroups::<K, V>::default()));
        let (tx, rx) = watch::channel(0_u64);

        let apply_state = Arc::clone(&groups_state);
        let group_columns = parsed.group_columns.clone();
        let apply: ApplyComputed = Box::new(move |rows| {
            let (fresh, as_of) = build_groups_map(rows, &group_columns, decode_key, decode_value)?;
            let changed = {
                let mut slot = match apply_state.write() {
                    Ok(slot) => slot,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let changed = slot.map != fresh;
                slot.map = fresh;
                // An emptied statistic rests no row to date itself by, so the
                // last data's as-of stands.
                if as_of.is_some() {
                    slot.as_of = as_of;
                }
                changed
            };
            if changed {
                tx.send_modify(|generation| *generation += 1);
            }
            Ok(())
        });

        let mut state = self.shared.lock_interrupting().await;

        // Tier dispatch, mirroring the scalar watch: a local tier is complete,
        // so a grouped query over it is an ordinary row query the replica
        // answers exactly, and a statistic cannot span the tiers.
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
            return Err(ClientError::Session(
                "local grouped query: use watch, a complete local tier answers it as rows"
                    .to_owned(),
            ));
        }

        // Bootstrap from the resting table before subscribing, so a same-run
        // late joiner and an offline restart both resolve through the rested
        // rows (R83 decision 3, extended to groups). Set the slot directly,
        // with no generation bump, so the first changed() still waits for a
        // real change.
        let rested = state.conn.rested_groups(&sql, &binds)?;
        if !rested.is_empty() {
            let (map, as_of) =
                build_groups_map(&rested, &parsed.group_columns, decode_key, decode_value)?;
            match groups_state.write() {
                Ok(mut slot) => {
                    slot.map = map;
                    slot.as_of = as_of;
                }
                Err(poisoned) => {
                    let mut slot = poisoned.into_inner();
                    slot.map = map;
                    slot.as_of = as_of;
                }
            }
        }
        let spec = SubscriptionSpec::new(sql).with_binds(binds);
        // No grace, as for the scalar watch: the map rests durably in
        // `_connetto_aggregates` and the handle holds no replica rows.
        let wire_id = attach_wire(&mut state, &self.shared.next_wire, spec, Duration::ZERO).await?;
        state.computed.push(ComputedEntry {
            sub_id: sub_id.clone(),
            wire_id,
            apply,
        });

        Ok(LiveGroups {
            handle: LiveHandleCore::new(sub_id, rx, &self.shared.reaper),
            state: groups_state,
        })
    }

    /// Watch a row-shaped query the server computes, decoding each answer row
    /// into `R` with serde (R84).
    ///
    /// This is the explicit surface for queries the server serves by
    /// re-execution rather than by syncing rows (joins, `DISTINCT`,
    /// expression projections): whether a query is re-executed is the
    /// server's tiering decision, invisible to the client's type system, so
    /// this handle is asked for by name and never dispatched to. The whole
    /// answer replaces [`rows`](LiveRows::rows) on every move, in the order
    /// the server produced it, and each answer rests in
    /// `_connetto_aggregates` so an offline restart shows the last synced
    /// one. `R` decodes from one answer row's JSON object by column name,
    /// like a diesel row from `#[derive(Deserialize)]`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the query cannot be rendered, is
    /// aggregate-shaped (use [`watch_value`](Self::watch_value) or
    /// [`watch_groups`](Self::watch_groups)), reads a local table (a
    /// complete local tier answers it through [`watch`](Self::watch)), or
    /// the subscribe frame cannot be sent. A server-side refusal arrives
    /// later as [`ClientEvent::NonFatal`] on [`events`](Self::events).
    pub async fn watch_rows<Q, R>(&self, query: Q) -> Result<LiveRows<R>, ClientError>
    where
        Q: QueryFragment<Sqlite>,
        R: DeserializeOwned + Clone + PartialEq + Send + Sync + 'static,
    {
        let (sql, binds) = render_query(&query)?;
        let parsed = parse_subscription(&sql)?;
        match parsed.shape {
            QueryShape::Rows => {}
            QueryShape::Aggregate => {
                return Err(ClientError::Session(
                    "scalar aggregate: use watch_value, an answer row cannot carry it".to_owned(),
                ));
            }
            QueryShape::Grouped => {
                return Err(ClientError::Session(
                    "grouped statistic: use watch_groups, the keyed map is its shape".to_owned(),
                ));
            }
        }
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");
        let rows_state = Arc::new(RwLock::new(RestedRows::<R>::default()));
        let (tx, rx) = watch::channel(0_u64);

        let apply_state = Arc::clone(&rows_state);
        let apply: ApplyComputed = Box::new(move |rested| {
            let (fresh, as_of) = decode_rested_rows(rested)?;
            let changed = {
                let mut slot = match apply_state.write() {
                    Ok(slot) => slot,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let changed = slot.rows != fresh;
                slot.rows = fresh;
                // An emptied answer rests no row to date itself by, so the
                // last data's as-of stands.
                if as_of.is_some() {
                    slot.as_of = as_of;
                }
                changed
            };
            if changed {
                tx.send_modify(|generation| *generation += 1);
            }
            Ok(())
        });

        let mut state = self.shared.lock_interrupting().await;

        // Tier dispatch, as for the other computed watches: a complete local
        // tier answers the query exactly through watch, and a computed answer
        // cannot span the tiers.
        let local_count = parsed
            .tables
            .intersection(state.conn.local_tables())
            .count();
        if local_count > 0 {
            if local_count != parsed.tables.len() {
                return Err(ClientError::Session(
                    "mixed-tier query: a computed answer cannot span local and synced tables"
                        .to_owned(),
                ));
            }
            return Err(ClientError::Session(
                "local query: use watch, a complete local tier answers it as rows".to_owned(),
            ));
        }

        // Bootstrap from the resting table before subscribing (R83 decision
        // 3). Set the slot directly, with no generation bump, so the first
        // changed() still waits for a real change.
        let rested = state.conn.rested_groups(&sql, &binds)?;
        if !rested.is_empty() {
            let (rows, as_of) = decode_rested_rows(&rested)?;
            match rows_state.write() {
                Ok(mut slot) => {
                    slot.rows = rows;
                    slot.as_of = as_of;
                }
                Err(poisoned) => {
                    let mut slot = poisoned.into_inner();
                    slot.rows = rows;
                    slot.as_of = as_of;
                }
            }
        }
        let spec = SubscriptionSpec::new(sql).with_binds(binds);
        // No grace, as for the other computed watches: the answer rests
        // durably and the handle holds no replica rows.
        let wire_id = attach_wire(&mut state, &self.shared.next_wire, spec, Duration::ZERO).await?;
        state.computed.push(ComputedEntry {
            sub_id: sub_id.clone(),
            wire_id,
            apply,
        });

        Ok(LiveRows {
            handle: LiveHandleCore::new(sub_id, rx, &self.shared.reaper),
            state: rows_state,
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
        let mut state = self.shared.lock_interrupting().await;
        let out = f(&mut state.conn);
        drop(state);
        // A write may have landed: let the pump flush and refresh promptly.
        self.shared.wake.notify_one();
        out
    }

    /// Keep a query's rows synced and covered until [`unpin`](Self::unpin),
    /// under an application-chosen name.
    ///
    /// A pin is the durable form of interest: it has no handle and no clock,
    /// so it survives closing and reopening the application and it survives
    /// being offline. Pinning the same name and query twice is a no-op, and
    /// pinning a changed query under an existing name replaces it, which is
    /// the upgrade path. Collisions between application features are the
    /// application's to avoid, since the application chooses the names.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the record.
    pub async fn pin(&self, name: &str, query: &str) -> Result<(), ClientError> {
        let mut state = self.shared.lock_interrupting().await;
        let spec = SubscriptionSpec::new(query);
        let wire_id = attach_wire(
            &mut state,
            &self.shared.next_wire,
            spec.clone(),
            DEFAULT_GRACE,
        )
        .await?;
        state.conn.pin_subscription(name, &wire_id, &spec)
    }

    /// End the pin under `name`. Unknown names are a no-op, so this is safe to
    /// call unconditionally. Its rows stop being covered by the pin and become
    /// evictable unless something else still wants them.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub async fn unpin(&self, name: &str) -> Result<(), ClientError> {
        let mut state = self.shared.lock_interrupting().await;
        state.conn.unpin_subscription(name)
    }

    /// Every pin, as name and query, in name order.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub async fn pins(&self) -> Result<Vec<(String, String)>, ClientError> {
        let mut state = self.shared.lock_interrupting().await;
        state.conn.pins()
    }

    /// Reclaim replica space now: evict every row no live subscription covers
    /// and return the freed pages to the filesystem.
    ///
    /// The automatic pass already runs when a subscription ends. This is the
    /// application-callable form for a free-up-space affordance, sweeping every
    /// declared table at once. It is a no-op while the transport is down and
    /// spares every pending write, exactly like the automatic pass.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a replica read or write failure.
    pub async fn tidy(&self) -> Result<(), ClientError> {
        let mut state = self.shared.lock_interrupting().await;
        state.conn.tidy()
    }

    /// Send a keepalive probe. The matching [`ClientEvent::Pong`] on the
    /// [`events`](Self::events) stream doubles as a barrier: the server
    /// processes frames in order, so the pong proves every frame sent before
    /// the ping (subscribes and unsubscribes included) was handled. Dropped
    /// handles queue their unsubscribes for the pump, so the ping drains that
    /// queue first: without that, the ping could overtake a queued
    /// unsubscribe and the pong would fence nothing.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the ping cannot be sent.
    pub async fn ping(&self, nonce: u64) -> Result<(), ClientError> {
        let mut state = self.shared.lock_interrupting().await;
        drain_dropped(&mut state, &self.shared.reaper).await?;
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
    // A send attempted with no socket is the same situation as one whose socket
    // died: there is a transport to go and find, and the run continues either
    // way. Anything else is a genuine fault and ends the pump.
    matches!(err, ClientError::Transport(_) | ClientError::NotConnected)
}

/// Decrement one reference on the wire subscription `wire_id`. When the last
/// sharer drops, report its id so the grace countdown can start.
///
/// The entry stays in the set at zero references rather than being removed,
/// which is what lets a re-watch inside the grace re-claim it instead of
/// minting a second subscription for the same query and paying a fresh
/// snapshot. It leaves the set only when its grace runs out.
fn release_wire(wire: &mut [WireSub], wire_id: &str, released: &mut Vec<String>) {
    if let Some(entry) = wire.iter_mut().find(|w| w.wire_id == wire_id) {
        entry.refs -= 1;
        if entry.refs == 0 {
            released.push(entry.wire_id.clone());
        }
    }
}

/// Attach a handle to the wire subscription for `spec`, sharing an existing
/// one (increment its ref count) or declaring a new one (subscribe once, ref
/// count 1). Returns the wire id. An aggregate handle bootstraps from the
/// resting table rather than from a cached last value here (R83).
/// The id space for shared wire subscriptions, distinct from handle ids.
const WIRE_PREFIX: &str = "wire-";

async fn attach_wire<T>(
    state: &mut State<T>,
    next_wire: &AtomicU64,
    spec: SubscriptionSpec,
    grace: Duration,
) -> Result<String, ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    if let Some(existing) = state.wire.iter_mut().find(|w| w.spec == spec) {
        let reclaimed = existing.refs == 0;
        existing.refs += 1;
        let wire_id = existing.wire_id.clone();
        if reclaimed {
            // Held again, so the countdown stops. The server still has this
            // subscription, so nothing goes on the wire and no snapshot is
            // paid, which is the whole point of the grace.
            state.conn.hold_subscription(&wire_id)?;
        }
        return Ok(wire_id);
    }
    let seq = next_wire.fetch_add(1, Ordering::Relaxed);
    let wire_id = format!("{WIRE_PREFIX}{seq}");
    state
        .conn
        .subscribe_spec_with_grace(&wire_id, spec.clone(), grace)
        .await?;
    state.wire.push(WireSub {
        wire_id: wire_id.clone(),
        spec,
        refs: 1,
    });
    Ok(wire_id)
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
        if let Some(pos) = state.computed.iter().position(|e| e.sub_id == sub_id) {
            let entry = state.computed.remove(pos);
            release_wire(&mut state.wire, &entry.wire_id, &mut released);
        }
    }
    // The last handle dropping starts a countdown, it does not end the
    // subscription. Navigating away and back inside the grace re-claims the
    // record and pays no fresh snapshot, which is the whole point of the
    // grace. A pin ignores this: it has no handle to drop.
    for wire_id in released {
        state.conn.release_subscription(&wire_id)?;
    }
    // Anything whose grace has since run out ends here, which is the only
    // place a watch is ever unsubscribed. Nothing runs on a timer: the pass
    // happens whenever the pump next steps, and an expiry is a comparison.
    //
    // Only when something could actually have expired, which is exactly when
    // some entry is unheld: a countdown starts at the last drop, and a record
    // inherited from a previous run is seeded unheld. With every watch held
    // this costs nothing, which matters because the pump steps per frame and
    // the replica is a real file on a browser's storage.
    if !state.wire.iter().any(|w| w.refs == 0) {
        return Ok(());
    }
    // A subscription this run still holds a handle on is never retired, however
    // the record reads. The record carries the durable claim and the reference
    // count carries the handles, and an unpin arriving while a handle is open
    // would otherwise unsubscribe a live query out from under it.
    //
    // Grace expiry and unpin both surface here as an expired record. The whole
    // pass waits while the transport is down: the record is left in place so the
    // next connected step retires it, because a row evicted offline could not be
    // re-fetched (R15 D3).
    if state.conn.is_connected() {
        for sub_id in state.conn.expired_subscriptions()? {
            if state.wire.iter().any(|w| w.wire_id == sub_id && w.refs > 0) {
                continue;
            }
            // The raw unsubscribe evicts rows scoped to this subscription's
            // tables before the record goes, sparing rows a survivor or a
            // pending write still wants. The retain follows success so a
            // failure leaves the refs == 0 entry in place and the next drain
            // retries it rather than stranding the expired record.
            state.conn.unsubscribe(&sub_id).await?;
            state.wire.retain(|w| w.wire_id != sub_id);
        }
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

        // 2. No socket and a driver to find one: go and find it. With no
        //    driver there is nothing to recover to, so the pump falls through
        //    and step 4 parks it until local work wakes it, which is what
        //    keeps device-private queries refreshing with no server at all.
        if reconnect.is_some() && !state.conn.is_connected() {
            needs_recovery = true;
            continue;
        }

        // 3. Auto-submit local writes committed since the last step.
        if let Err(err) = state.conn.flush().await {
            if is_disconnect(&err) {
                needs_recovery = true;
                continue;
            }
            return;
        }

        // 4. One cancellable pump step. A wake interrupts the idle wait so
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

        // The first cursor is the moment "empty" stops meaning "never
        // fetched", so it is recorded here rather than beside the refresh
        // below, which an empty first sync gives nothing to do.
        if !shared.ever_synced.load(Ordering::Relaxed) && state.conn.has_ever_synced() {
            shared.ever_synced.store(true, Ordering::Relaxed);
        }

        // 5. Refresh live queries whose tables changed, from server patches
        //    and local writes alike.
        refresh_changed(&mut state, &shared.events);
    }
}

/// Re-run every live query whose tables were touched since the last step.
fn refresh_changed<T: Transport>(state: &mut State<T>, events: &broadcast::Sender<ClientEvent>) {
    let changed = state.conn.take_changed_unfiltered();
    if changed.is_empty() {
        return;
    }
    let changed: HashSet<String> = changed.into_iter().map(|t| t.to_lowercase()).collect();
    let State {
        conn,
        registry,
        values: _,
        computed: _,
        wire: _,
    } = state;
    for entry in registry.iter_mut() {
        if entry.tables.is_disjoint(&changed) {
            continue;
        }
        if let Err(err) = (entry.refresh)(conn) {
            let _ = events.send(ClientEvent::NonFatal {
                related_to: Some(entry.sub_id.clone()),
                detail: format!("live query refresh failed: {err}"),
            });
        }
    }
}

/// Push a rested aggregate to its live handles.
///
/// The resting write already happened in the connection's frame-application
/// path, so this only reads the rested rows back and fans them out, which
/// makes each handle mirror the table exactly for both a live push and a
/// bootstrap. A scalar frame feeds the value handles from the one rested
/// scalar row. Any frame of a grouped statistic (a keyed delta, a group's
/// departure, or a whole-answer demotion) feeds the keyed handles from the
/// full rested group set, so all three shapes take one path and a demotion
/// never surfaces (R84, decision 4).
fn route_aggregate<T>(state: &mut State<T>, shared: &Shared<T>, event: &ClientEvent)
where
    T: Transport,
{
    let ClientEvent::Aggregate {
        sub_id, group_key, ..
    } = event
    else {
        return;
    };
    let State {
        conn,
        registry: _,
        values,
        computed,
        wire,
    } = state;
    let Some(target) = wire.iter().find(|w| w.wire_id == *sub_id) else {
        return;
    };
    if group_key.is_none() && values.iter().any(|e| e.wire_id == *sub_id) {
        let rested = match conn.rested_scalar(target.spec.query.as_str(), &target.spec.binds) {
            Ok(rested) => rested,
            Err(err) => {
                let _ = shared.events.send(ClientEvent::NonFatal {
                    related_to: Some(sub_id.clone()),
                    detail: format!("reading rested aggregate failed: {err}"),
                });
                return;
            }
        };
        let (json, as_of) = match rested {
            Some((json, as_of)) => (Some(json), Some(as_of)),
            None => (None, None),
        };
        // Fan out to every value handle sharing this wire sub, each with its
        // own decoder and typed value, not just the first.
        for entry in values.iter_mut().filter(|e| e.wire_id == *sub_id) {
            if let Err(err) = (entry.apply)(json.as_deref(), as_of) {
                let _ = shared.events.send(ClientEvent::NonFatal {
                    related_to: Some(entry.sub_id.clone()),
                    detail: format!("live value update failed: {err}"),
                });
            }
        }
    }
    if !computed.iter().any(|e| e.wire_id == *sub_id) {
        return;
    }
    let rested = match conn.rested_groups(target.spec.query.as_str(), &target.spec.binds) {
        Ok(rested) => rested,
        Err(err) => {
            let _ = shared.events.send(ClientEvent::NonFatal {
                related_to: Some(sub_id.clone()),
                detail: format!("reading rested computed rows failed: {err}"),
            });
            return;
        }
    };
    // Fan out to every keyed handle sharing this wire sub, each with its own
    // decoders and typed map.
    for entry in computed.iter_mut().filter(|e| e.wire_id == *sub_id) {
        if let Err(err) = (entry.apply)(&rested) {
            let _ = shared.events.send(ClientEvent::NonFatal {
                related_to: Some(entry.sub_id.clone()),
                detail: format!("live groups update failed: {err}"),
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
    /// The silent refresh could not produce a login grant, so retrying is
    /// futile and the driver routes to interactive re-login instead. The server
    /// never signals this: a grant it refuses leaves the connection open and
    /// says nothing, so the client learns it from its own token source.
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
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        if driver
            .policy
            .max_attempts()
            .is_some_and(|max| attempt > max)
        {
            return Recovery::Exhausted;
        }
        let _ = shared.events.send(ClientEvent::Reconnecting { attempt });
        driver.sleeper.sleep(driver.policy.backoff(attempt)).await;

        let Ok(transport) = driver.factory.connect().await else {
            continue;
        };
        let mut state = shared.state.lock().await;
        match state.conn.attach(transport).await {
            Ok(()) => {}
            // A rejected credential is not a transport blip: stop the backoff
            // loop and let the pump surface a re-login requirement.
            Err(ClientError::Auth(_)) => return Recovery::ReauthRequired,
            Err(_) => continue,
        }
        // Re-declaring every live subscription under its original id is
        // `attach`'s own job now, from the persisted set, which is the same
        // work a first connection does.
        let _ = shared.events.send(ClientEvent::Reconnected);
        return Recovery::Live;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::prelude::*;

    diesel::table! {
        /// Orders, the fixture these render tests build queries against.
        orders (id) {
            /// Order identifier, the primary key.
            id -> BigInt,
            /// How many units the order is for.
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

    // Shape classification routes scalar aggregates to watch_value, grouped
    // statistics to watch_groups, and rows to watch.
    #[test]
    fn shape_classifies_aggregates_and_rows() {
        let agg = parse_subscription("SELECT COUNT(*) FROM `orders`").expect("parse");
        assert_eq!(agg.shape, QueryShape::Aggregate);
        let rows = parse_subscription("SELECT * FROM orders WHERE quantity > 0").expect("parse");
        assert_eq!(rows.shape, QueryShape::Rows);
        let grouped = parse_subscription("SELECT status, COUNT(*) FROM orders GROUP BY status")
            .expect("parse");
        assert_eq!(grouped.shape, QueryShape::Grouped);
        assert_eq!(grouped.group_columns, vec!["status".to_owned()]);
    }

    // The grouped shape needs its group columns projected and plain: an
    // expression GROUP BY, a hidden group column, or a second aggregate all
    // stay row queries, which watch then refuses or serves as such.
    #[test]
    fn grouped_shape_requires_projected_plain_columns_and_one_aggregate() {
        let quoted = parse_subscription(
            "SELECT `orders`.`status`, count(*) FROM `orders` GROUP BY `orders`.`status`",
        )
        .expect("parse");
        assert_eq!(quoted.shape, QueryShape::Grouped);
        assert_eq!(quoted.group_columns, vec!["status".to_owned()]);
        let composite = parse_subscription(
            "SELECT region, status, COUNT(*) FROM orders GROUP BY region, status",
        )
        .expect("parse");
        assert_eq!(composite.shape, QueryShape::Grouped);
        assert_eq!(
            composite.group_columns,
            vec!["region".to_owned(), "status".to_owned()],
            "group columns keep GROUP BY order, not projection order"
        );
        for hidden in [
            "SELECT COUNT(*) FROM orders GROUP BY status",
            "SELECT upper(status), COUNT(*) FROM orders GROUP BY upper(status)",
            "SELECT status, COUNT(*), SUM(quantity) FROM orders GROUP BY status",
            "SELECT status, quantity, COUNT(*) FROM orders GROUP BY status",
        ] {
            let parsed = parse_subscription(hidden).expect("parse");
            assert_eq!(parsed.shape, QueryShape::Rows, "not grouped: {hidden}");
        }
    }

    // The public aggregate-shape classifier mirrors subscription_tables: it is
    // the relay's way to route a tab Subscribe to the aggregate path instead of
    // a row snapshot, matching the client's own routing. A grouped statistic
    // rides the aggregate path too: its frames are aggregate frames.
    #[test]
    fn subscription_is_aggregate_classifies_shape() {
        assert!(subscription_is_aggregate("SELECT COUNT(*) FROM `orders`").expect("parse"));
        assert!(subscription_is_aggregate("SELECT MIN(quantity) FROM orders").expect("parse"));
        assert!(
            !subscription_is_aggregate("SELECT * FROM orders WHERE quantity > 0").expect("parse")
        );
        assert!(
            subscription_is_aggregate("SELECT status, COUNT(*) FROM orders GROUP BY status")
                .expect("parse")
        );
        assert!(subscription_is_aggregate("NOT SQL AT ALL (").is_err());
    }

    // The keyed handle's serde key decode: a single group column decodes from
    // its bare value, several from the array, and a one-element tuple still
    // decodes from a one-element array.
    #[test]
    fn group_key_decodes_bare_and_tuple() {
        let single: String = decode_group_key("[\"eu\"]").expect("decode");
        assert_eq!(single, "eu");
        let number: i64 = decode_group_key("[7]").expect("decode");
        assert_eq!(number, 7);
        let tuple: (String, i64) = decode_group_key("[\"eu\",7]").expect("decode");
        assert_eq!(tuple, ("eu".to_owned(), 7));
        let one_tuple: (String,) = decode_group_key("[\"eu\"]").expect("decode");
        assert_eq!(one_tuple, ("eu".to_owned(),));
    }

    // A whole answer's object splits into the key array (in GROUP BY order,
    // not object order) and the one remaining aggregate value; an element
    // missing a group column or holding two extra members names the fault.
    #[test]
    fn whole_object_splits_into_key_and_value() {
        let (key, value) =
            split_whole_object("{\"count\":3,\"status\":\"open\"}", &["status".to_owned()])
                .expect("split");
        assert_eq!(key, "[\"open\"]");
        assert_eq!(value, "3");
        let (key, _) = split_whole_object(
            "{\"region\":\"eu\",\"count\":3,\"status\":\"open\"}",
            &["status".to_owned(), "region".to_owned()],
        )
        .expect("split");
        assert_eq!(key, "[\"open\",\"eu\"]", "key order follows GROUP BY");
        assert!(split_whole_object("{\"count\":3}", &["status".to_owned()]).is_err());
        assert!(
            split_whole_object(
                "{\"count\":3,\"sum\":9,\"status\":\"open\"}",
                &["status".to_owned()],
            )
            .is_err()
        );
    }

    // The map builder admits both resting shapes at once and keeps the newest
    // as-of, so a demotion mid-life never surfaces to the handle.
    #[test]
    fn groups_map_builds_from_both_resting_shapes() {
        let rows = vec![
            crate::aggregates::RestedGroup {
                group_values_json: Some("[\"open\"]".to_owned()),
                result_json: "2".to_owned(),
                updated_at: 10,
            },
            crate::aggregates::RestedGroup {
                group_values_json: None,
                result_json: "{\"status\":\"done\",\"count\":1}".to_owned(),
                updated_at: 12,
            },
        ];
        let decode_key: fn(&str) -> Result<String, ClientError> = decode_group_key;
        let decode_value: fn(&str) -> Result<i64, ClientError> =
            |json| serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()));
        let (map, as_of) =
            build_groups_map(&rows, &["status".to_owned()], decode_key, decode_value)
                .expect("build");
        assert_eq!(
            map,
            HashMap::from([("open".to_owned(), 2), ("done".to_owned(), 1)]),
        );
        assert_eq!(as_of, Some(12), "the newest row dates the map");
    }

    // A membership term reads a second table inside `IN (SELECT ...)`. Refresh
    // routing needs both tables, so `parse_subscription` keeps them, but a
    // subscription answers departures only for its own rows, so `coverage_of`
    // drops the membership table: a `project_members` change must never be
    // tested against the `docs` predicate.
    #[test]
    fn coverage_of_excludes_the_membership_subquery_table() {
        let query = "SELECT * FROM docs WHERE project_id IN \
                     (SELECT project_id FROM project_members WHERE user_id = current_app_user())";
        let parsed = parse_subscription(query).expect("parse");
        assert!(
            parsed.tables.contains("project_members"),
            "refresh routing must still watch the membership table, got {:?}",
            parsed.tables
        );
        let coverage = coverage_of(&SubscriptionSpec::new(query))
            .expect("coverage")
            .expect("a row subscription has coverage");
        assert_eq!(
            coverage.tables,
            HashSet::from(["docs".to_owned()]),
            "coverage answers only for the subscribed table"
        );
        assert!(
            coverage.predicate.is_some(),
            "the term predicate is kept so still_covered can re-test it"
        );
    }
}
