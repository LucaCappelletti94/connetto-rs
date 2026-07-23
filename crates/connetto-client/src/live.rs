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

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock, Weak};

use connetto_core::messages::{BindValue, SubscriptionSpec};
use connetto_core::traits::Transport;
use diesel::query_builder::{MoveableBindCollector, QueryBuilder, QueryFragment};
use diesel::query_dsl::methods::LoadQuery;
use diesel::sqlite::{OwnedSqliteBindValue, Sqlite, SqliteBindCollector, SqliteQueryBuilder};
use sqlparser::ast::visit_relations;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use tokio::sync::{Mutex, Notify, broadcast, watch};

use crate::{ClientError, ClientEvent, ConnettoConnection};

/// Render a typed diesel query to its SQLite SQL (with `?` placeholders) and
/// the bind values the placeholders stand for, in placeholder order.
///
/// # Errors
///
/// [`ClientError::Session`] when diesel cannot render the query.
pub fn render_query<Q: QueryFragment<Sqlite>>(
    query: &Q,
) -> Result<(String, Vec<BindValue>), ClientError> {
    let mut builder = SqliteQueryBuilder::new();
    query
        .to_sql(&mut builder, &Sqlite)
        .map_err(|e| ClientError::Session(e.to_string()))?;
    let sql = builder.finish();

    let mut collector = SqliteBindCollector::new();
    query
        .collect_binds(&mut collector, &mut (), &Sqlite)
        .map_err(|e| ClientError::Session(e.to_string()))?;
    let binds = collector
        .moveable()
        .binds()
        .map(|(value, _)| match value {
            OwnedSqliteBindValue::String(s) => BindValue::Text(s.to_string()),
            OwnedSqliteBindValue::Binary(b) => BindValue::Blob(b.to_vec()),
            OwnedSqliteBindValue::I32(i) => BindValue::Integer(i64::from(*i)),
            OwnedSqliteBindValue::I64(i) => BindValue::Integer(*i),
            OwnedSqliteBindValue::F64(f) => BindValue::Real(*f),
            OwnedSqliteBindValue::Null => BindValue::Null,
        })
        .collect();
    Ok((sql, binds))
}

/// The lowercased names of every table `sql` reads, for targeted refresh.
fn query_tables(sql: &str) -> Result<HashSet<String>, ClientError> {
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
    Ok(tables)
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

/// One live handle's driver-side state: which tables it reads and how to
/// re-run its query and publish fresh rows.
struct LiveEntry<T: Transport> {
    sub_id: String,
    tables: HashSet<String>,
    refresh: Refresh<T>,
}

/// The connection and the live-query registry, guarded together so a refresh
/// always sees the replica state the pump just produced.
struct State<T: Transport> {
    conn: ConnettoConnection<T>,
    registry: Vec<LiveEntry<T>>,
}

/// Everything the client handles and the pump task share.
struct Shared<T: Transport> {
    state: Mutex<State<T>>,
    wake: Arc<Notify>,
    reaper: Arc<Reaper>,
    events: broadcast::Sender<ClientEvent>,
    next_live: AtomicU64,
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
    T: Transport + Send + 'static,
    T::Error: core::fmt::Display,
{
    /// Take ownership of a connected [`ConnettoConnection`] and start the
    /// background pump that drives it.
    #[must_use]
    pub fn start(conn: ConnettoConnection<T>) -> Self {
        let wake = Arc::new(Notify::new());
        let (events, _) = broadcast::channel(256);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                conn,
                registry: Vec::new(),
            }),
            wake: Arc::clone(&wake),
            reaper: Arc::new(Reaper {
                pending: StdMutex::new(Vec::new()),
                wake: Arc::clone(&wake),
            }),
            events,
            next_live: AtomicU64::new(1),
        });
        let token = Arc::new(ClientToken { wake });
        tokio::spawn(pump(Arc::clone(&shared), Arc::downgrade(&token)));
        Self { shared, token }
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
        Q: for<'query> LoadQuery<'query, ConnettoConnection<T>, R>,
        R: Clone + PartialEq + Send + Sync + 'static,
    {
        let (sql, binds) = render_query(&query)?;
        let tables = query_tables(&sql)?;
        let seq = self.shared.next_live.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("live-{seq}");

        // Interrupt the pump's idle wait so the FIFO lock admits us promptly.
        self.shared.wake.notify_one();
        let mut state = self.shared.state.lock().await;

        let initial: Vec<R> = query
            .clone()
            .load(&mut state.conn)
            .map_err(|e| ClientError::Session(e.to_string()))?;
        let rows = Arc::new(RwLock::new(initial));
        let (tx, rx) = watch::channel(0_u64);

        let refresh_rows = Arc::clone(&rows);
        let refresh = Box::new(move |conn: &mut ConnettoConnection<T>| {
            let fresh: Vec<R> = query
                .clone()
                .load(conn)
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

        state
            .conn
            .subscribe_spec(&sub_id, SubscriptionSpec::new(sql).with_binds(binds))
            .await?;
        state.registry.push(LiveEntry {
            sub_id: sub_id.clone(),
            tables,
            refresh,
        });

        Ok(LiveQuery {
            sub_id,
            rows,
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
}

/// The background pump: drains queued unsubscribes, flushes local writes,
/// takes one cancellable pump step, then refreshes every live query whose
/// tables changed. When the last [`ConnettoClient`] clone drops, the pump
/// closes the connection gracefully (transport close handshake) and exits.
/// It also exits when the transport closes or fails.
async fn pump<T>(shared: Arc<Shared<T>>, alive: Weak<ClientToken>)
where
    T: Transport + Send + 'static,
    T::Error: core::fmt::Display,
{
    loop {
        if alive.upgrade().is_none() {
            let mut state = shared.state.lock().await;
            let _ = state.conn.close().await;
            return;
        }
        let mut state = shared.state.lock().await;

        // 1. Unsubscribes queued by dropped handles.
        let pending = {
            let mut queue = match shared.reaper.pending.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            core::mem::take(&mut *queue)
        };
        for sub_id in pending {
            state.registry.retain(|entry| entry.sub_id != sub_id);
            if state.conn.unsubscribe(&sub_id).await.is_err() {
                return;
            }
        }

        // 2. Auto-submit local writes committed since the last step.
        if state.conn.flush().await.is_err() {
            return;
        }

        // 3. One cancellable pump step. A wake interrupts the idle wait so
        //    lock waiters (watch, with_conn, drops) get in promptly.
        let wake = Arc::clone(&shared.wake);
        match state.conn.pump_one_or(wake.notified()).await {
            Ok(Some(event)) => {
                let closed = matches!(event, ClientEvent::Closed);
                let _ = shared.events.send(event);
                if closed {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => return,
        }

        // 4. Refresh live queries whose tables changed, from server patches
        //    and local writes alike.
        let changed = state.conn.take_changed();
        if !changed.is_empty() {
            let changed: HashSet<String> = changed.into_iter().map(|t| t.to_lowercase()).collect();
            let State { conn, registry } = &mut *state;
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
        let tables =
            query_tables("SELECT `orders`.`id` FROM `orders` WHERE (`orders`.`quantity` > ?1)")
                .expect("parse");
        assert_eq!(tables, HashSet::from(["orders".to_owned()]));
    }
}
