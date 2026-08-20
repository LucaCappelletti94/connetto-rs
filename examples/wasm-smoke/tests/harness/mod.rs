//! Relay-parity test harness.
//!
//! The relay-parity plan (`docs/plan-relay-parity.md`) makes the browser
//! relay hub protocol-transparent against the direct server: a tab client
//! behind the `RelayHub` must observe the same handshake, snapshots, live
//! patches, events, and values as a client on a direct socket to
//! `connetto-server`. This harness is the reusable way to assert that. It
//! connects one direct client (a `BrowserSocket` straight to the server) and
//! one relay tab client (a broadcast `MessageTransport` to the DB worker's hub)
//! against the same running stack, subscribes both to the same live query,
//! and exposes helpers to drive them through identical steps and compare what
//! each observes.
//!
//! Each later parity phase (1 through 7) copies the worked example in
//! `tests/parity.rs`, adds a single failing assertion for the leg it fixes,
//! then implements. The relay hub lives in `connetto-web`, which is a
//! wasm-only crate (`web-sys`, `js-sys`, the sahpool OPFS VFS), so relay
//! parity cannot be exercised natively: every parity assertion here is a
//! headless-Chrome browser test against a real server and Postgres. The
//! cheaper native and unit sub-steps a phase may have (widening a
//! `ClientEvent`, a wire classifier) belong in the touched crate's own native
//! tests, not this harness.
//!

// Shared test support: each parity test binary uses a different subset of
// these helpers, so unused ones are expected per binary.
#![allow(dead_code)]

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::Transport;
use connetto_wasm_smoke::leader::Membership;
use connetto_wasm_smoke::locks::HeldLock;
use connetto_wasm_smoke::workers::{
    DEMO_QUERY, DEMO_SQLITE_DDL, DEMO_WS_URL, announce_tab, await_db_worker_ready,
};
use connetto_wasm_smoke::{BrowserSocket, MessageTransport, leader, locks};
use diesel::prelude::*;
use web_sys::BroadcastChannel;

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

/// One synced `orders` row, the shape both mirrors converge on.
#[derive(Queryable, Selectable, Debug, PartialEq, Eq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Order {
    pub id: rosetta_uuid::Uuid,
    pub owner_id: String,
    pub quantity: i64,
}

/// Progress marker for diagnosing a harness timeout: the stages appear in the
/// captured console output.
pub fn stage(message: &str) {
    web_sys::console::log_1(&message.into());
}

/// Relay the DB worker's breadcrumbs into the page console: a worker's console
/// is not always visible to the harness, so the bootstrap broadcasts its
/// progress and failures on this channel instead.
pub fn relay_worker_breadcrumbs() {
    use wasm_bindgen::JsCast;
    let channel = web_sys::BroadcastChannel::new("connetto-debug").expect("broadcast channel");
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
        |event: web_sys::MessageEvent| {
            web_sys::console::log_1(&event.data());
        },
    );
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    // The channel itself must outlive the test to keep delivering.
    core::mem::forget(channel);
}

/// Base for row ids unique across smoke runs, in the parity harness's own
/// band. The demo Postgres is long-lived and accumulates rows across runs, so
/// ids must be globally unique. Millisecond time makes them monotonic.
#[must_use]
pub fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    70_000_000_000 + millis
}

/// The served URL of this test's wasm-bindgen glue module, recovered from the
/// wasm fetch the harness already performed. The DB worker bootstrap receives
/// it as a query parameter.
#[must_use]
pub fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .expect("query resource entries")
    .as_string()
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

/// Connect a tab client to the DB worker over its own wire channel.
///
/// Announces the channel and waits for the worker's attachment ack first, so
/// the handshake cannot outrun the worker's end of the channel.
pub async fn connect_tab(
    client_id: &str,
    token: String,
    identity: &str,
) -> ConnettoConnection<MessageTransport<BroadcastChannel>> {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await;
    let transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(connetto_wasm_smoke::CALLER_FUNCTION, identity);
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect through the wire channel")
}

/// Connect a client directly to `connetto-server` over a `BrowserSocket`.
pub async fn connect_server(
    name: &str,
    tag: i64,
    token: String,
    identity: &str,
) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect(DEMO_WS_URL)
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig::new(format!("{name}-{tag}"))
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(connetto_wasm_smoke::CALLER_FUNCTION, identity);
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

/// Pump `conn` until an event matches `pred`, applying every frame in between.
/// The harness timeout bounds the wait.
pub async fn pump_until<T>(
    conn: &mut ConnettoConnection<T>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

/// Pump `conn` until its local replica holds the order row `id`.
pub async fn pump_until_row<T>(conn: &mut ConnettoConnection<T>, id: rosetta_uuid::Uuid)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        if load_orders(conn).iter().any(|row| row.id == id) {
            return;
        }
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
    }
}

/// The full `orders` mirror of `conn`, sorted by id for order-independent
/// comparison between two clients.
pub fn load_orders<T>(conn: &mut ConnettoConnection<T>) -> Vec<Order>
where
    T: Transport,
{
    orders::table
        .order(orders::id)
        .load(conn.conn())
        .expect("local read")
}

/// Insert one row through `writer`, minting its id from the `orders` DEFAULT,
/// and fence on a pong: control frames are processed in order, so the pong
/// proves the server applied the mutation. Returns the minted 16-byte id.
pub async fn write_row(
    writer: &mut ConnettoConnection<BrowserSocket>,
    nonce: u64,
    identity: &str,
) -> rosetta_uuid::Uuid {
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq(identity), orders::quantity.eq(5_i64)))
        .execute(writer.conn())
        .expect("writer insert");
    let id = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    writer.push().await.expect("push").expect("mutation sent");
    writer.ping(nonce).await.expect("ping");
    pump_until(
        writer,
        |event| matches!(event, ClientEvent::Pong { nonce: n } if *n == nonce),
    )
    .await;
    id
}

/// Two clients subscribed to the same live query, one straight to the server
/// and one behind the relay hub, plus the worker they share.
///
/// The invariant this fixture upholds is protocol transparency: after both
/// have converged on a change, `direct` and `relay` hold identical mirror
/// state and observe the same event legs. Later phases assert additional legs
/// (aggregates, full resync, conflicts, non-fatal errors) on the same pair.
pub struct ParityFixture {
    /// A client on a direct `BrowserSocket` to `connetto-server`.
    pub direct: ConnettoConnection<BrowserSocket>,
    /// A tab client on a broadcast `MessageTransport` to the DB worker's
    /// relay hub.
    pub relay: ConnettoConnection<MessageTransport<BroadcastChannel>>,
    /// Keeps the leader's DB worker alive for the fixture's lifetime.
    membership: Membership,
    /// The relay tab's liveness lock, released on teardown.
    tab_lock: Option<HeldLock>,
}

impl ParityFixture {
    /// Bring up the shared stack and both clients, subscribed to
    /// [`DEMO_QUERY`] and pumped through their initial snapshots.
    ///
    /// The caller seeds any pre-existing rows through a writer BEFORE calling
    /// this, so both the worker replica and the direct client snapshot them.
    /// `base` names this run's unique id band and the leader lock.
    /// `token` and `user_id` come from one `common::mint_session` call:
    /// both clients share the session so the same `owner_id` is visible
    /// through each connection's policy view.
    pub async fn setup(base: i64, sub_id: &str, token: String, user_id: &str) -> ParityFixture {
        relay_worker_breadcrumbs();

        // The worker logs in for itself, and only a tab can answer that
        // request. Installed before the worker spawns, because a
        // `BroadcastChannel` buffers nothing for a late subscriber.
        crate::common::play_the_tab();

        // This page wins the leader election and owns the DB worker that hosts
        // the relay hub the tab client speaks to.
        let membership = leader::join(&format!("connetto-parity-{base}"), &glue_url());
        await_db_worker_ready().await.expect("db worker ready");
        stage("db worker ready");

        // The direct client: a plain server session, the parity reference.
        let mut direct = connect_server("parity-direct", base, token.clone(), user_id).await;
        direct
            .subscribe(&format!("{sub_id}-direct"), DEMO_QUERY)
            .await
            .expect("direct subscribe");
        pump_until(&mut direct, |event| {
            matches!(event, ClientEvent::SnapshotEnd { .. })
        })
        .await;
        stage("direct client snapshot ended");

        // The relay tab client: holds its liveness lock before connecting, the
        // protocol the hub's reaper requires.
        let client_id = rosetta_uuid::Uuid::new_v4().to_string();
        let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
        let mut relay = connect_tab(&client_id, token, user_id).await;
        relay
            .subscribe(&format!("{sub_id}-relay"), DEMO_QUERY)
            .await
            .expect("relay subscribe");
        pump_until(&mut relay, |event| {
            matches!(event, ClientEvent::SnapshotEnd { .. })
        })
        .await;
        stage("relay tab snapshot ended");

        ParityFixture {
            direct,
            relay,
            membership,
            tab_lock: Some(tab_lock),
        }
    }

    /// Pump both clients until each holds the order row `id`, applying every
    /// frame in between. Returns once both have converged.
    pub async fn converge_row(&mut self, id: rosetta_uuid::Uuid) {
        pump_until_row(&mut self.direct, id).await;
        pump_until_row(&mut self.relay, id).await;
    }

    /// Pump both clients until each observes a [`ClientEvent::LivePatch`] and
    /// holds the order row `id`. This asserts the live-patch leg reaches the
    /// relay tab exactly as it reaches the direct client, not merely that the
    /// row eventually appears.
    pub async fn converge_live_patch(&mut self, id: rosetta_uuid::Uuid) {
        for _ in 0..2 {
            pump_until(&mut self.direct, |event| {
                matches!(event, ClientEvent::LivePatch { .. })
            })
            .await;
            if load_orders(&mut self.direct).iter().any(|row| row.id == id) {
                break;
            }
        }
        assert!(
            load_orders(&mut self.direct).iter().any(|row| row.id == id),
            "direct client did not receive row {id:?} as a live patch"
        );
        for _ in 0..2 {
            pump_until(&mut self.relay, |event| {
                matches!(event, ClientEvent::LivePatch { .. })
            })
            .await;
            if load_orders(&mut self.relay).iter().any(|row| row.id == id) {
                break;
            }
        }
        assert!(
            load_orders(&mut self.relay).iter().any(|row| row.id == id),
            "relay tab did not receive row {id:?} as a live patch"
        );
    }

    /// Assert the two mirrors hold identical row state. Both subscribe to the
    /// same query, so a transparent relay yields byte-identical row sets. Call
    /// after a `converge_*` so neither client is mid-patch.
    pub fn assert_mirrors_match(&mut self) {
        let direct_rows = load_orders(&mut self.direct);
        let relay_rows = load_orders(&mut self.relay);
        assert_eq!(
            direct_rows, relay_rows,
            "direct and relay mirrors diverged: the relay is not transparent"
        );
    }
    /// Subscribe both clients to the aggregate `query` under `sub_id`.
    pub async fn subscribe_aggregate(&mut self, sub_id: &str, query: &str) {
        self.direct
            .subscribe(sub_id, query)
            .await
            .expect("direct aggregate subscribe");
        self.relay
            .subscribe(sub_id, query)
            .await
            .expect("relay aggregate subscribe");
    }

    /// Pump both clients until each delivers the next aggregate value for
    /// `sub_id`, assert the two agree, and return the shared value. This is
    /// the aggregate analogue of `converge_live_patch`: it proves the relay
    /// serves an `AggregateUpdate` for the sub, not a row snapshot, and that
    /// the value matches the direct client's.
    pub async fn converge_aggregate(&mut self, sub_id: &str) -> i64 {
        let direct = pump_aggregate(&mut self.direct, sub_id).await;
        let relay = pump_aggregate(&mut self.relay, sub_id).await;
        assert_eq!(
            direct, relay,
            "direct and relay aggregate values diverged for {sub_id}: the relay is not transparent"
        );
        direct
    }

    /// Close both clients and resign leadership, releasing the DB worker.
    pub async fn teardown(mut self) {
        self.direct.close().await.expect("close direct");
        self.relay.close().await.expect("close relay");
        if let Some(lock) = self.tab_lock.take() {
            lock.release();
        }
        drop(self.membership);
    }
}

/// Pump `conn` until it delivers the next aggregate value for `sub_id`,
/// returning the parsed scalar. Frames for other subscriptions are applied
/// and skipped. The harness timeout bounds the wait, so a relay that serves
/// an aggregate query as a row snapshot (delivering no `AggregateUpdate`)
/// surfaces as a timeout, which is exactly the pre-parity failure.
pub async fn pump_aggregate<T>(conn: &mut ConnettoConnection<T>, sub_id: &str) -> i64
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if let ClientEvent::Aggregate {
            sub_id: got,
            result_json,
            ..
        } = &event
            && got == sub_id
        {
            return result_json
                .trim()
                .trim_matches('"')
                .parse()
                .expect("aggregate scalar int");
        }
    }
}
