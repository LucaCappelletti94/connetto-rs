//! Phase R36: what a caller asked for is watched, and an identity that keeps
//! being told no is banned.
//!
//! The properties, each asserted rather than assumed:
//!
//! * a crossed threshold bans the person, closes every connection they hold,
//!   and refuses the next handshake, telling the caller nothing either time;
//! * the application's answer decides the outcome, and one that answers nothing
//!   gets connetto's proposal, which is permanent;
//! * an expiry that passes stops applying with nothing having run, and leaves no
//!   record, while a lift leaves one;
//! * **reads drive no counter**, which is the assertion standing between this
//!   feature and banning every honest user;
//! * an unidentified caller has its connection closed and the application is
//!   **not** asked, since a verdict about a caller nobody can ban would mean
//!   nothing;
//! * the ban applies with row-level security enabled on the ban table and no
//!   policy admitting anyone, because the check reads on the owner pool;
//! * **a person's tally survives signing out and back in**, and two connections
//!   of one person accumulate once, which is why the tally names the person
//!   rather than the handle;
//! * **revoking a share produces no refusal at all**, which is the correction
//!   this whole phase rests on.
//!
//! `#[ignore]` by default: the ban list, the audit table and the write target
//! all need a running Postgres.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Grant, Handshake, SUBSCRIPTION_REFUSED, Subscribe,
    SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::audit::{AUTH_OP_TYPE, AuthOp, pg_audit_hook};
use connetto_server::ban::Instant;
use connetto_server::{
    AbuseConfig, AbuseLimits, ConnectionLimits, Crossing, Enforcement, EnforcementFuture,
    EnforcementPolicy, LoopbackTransport, Materializer, NewBan, PermissiveAuth, PersonLimits,
    RequestGuard, SessionConfig, SessionManager, Snapshot, SnapshotSource, ThrottleConfig,
    TierLimits, connetto_audit_table, connetto_ban_table, loopback, pg_ban_store, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RowValue, insert_changeset};
use diesel::prelude::*;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::Postgres as PgBackend;
use subql::visibility::{RowView, Verdict, VisibilityPolicy, WriteOp};
use subql::{CdcSource, PgSqliteEmuSource};

// The reference defaults over `Id = String`, which is what `TestGrantChecker`
// resolves a `user:` grant to.
connetto_ban_table!(String, diesel::sql_types::Text);
connetto_audit_table!(
    String,
    diesel::sql_types::Text,
    uuid::Uuid,
    diesel::sql_types::Uuid,
);

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// A query naming a table that does not resolve, which is signal two.
const GHOST: &str = "SELECT * FROM nosuch WHERE quantity > 0";
/// A window long enough that nothing rolls over mid-test.
const WINDOW: Duration = Duration::from_secs(300);
/// How long a test waits for work that rides a spawned task.
const SETTLE: Duration = Duration::from_secs(5);
/// The capability whose relation the application deleted. The token still checks
/// out, so nothing about the handshake changes and the rows simply stop matching.
const REVOKED_KEY: &str = "key:gone";

/// A snapshot source with one row, and none at all for a caller whose only
/// share key was withdrawn.
struct KeyedSnapshot;

impl SnapshotSource for KeyedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        auth: &Principal,
    ) -> Result<Snapshot, Self::Error> {
        let withdrawn = auth
            .capabilities()
            .iter()
            .any(|subject| subject.key() == REVOKED_KEY);
        if withdrawn {
            return Ok(Snapshot {
                patchset: Vec::new(),
                cursor: Cursor::new(Vec::new()),
            });
        }
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(3))
            .expect("set quantity")
            .set(3, Value::Text("seed".to_owned()))
            .expect("set status");
        Ok(Snapshot {
            patchset: PatchSet::<SimpleTable, String, Vec<u8>>::new()
                .insert(insert)
                .build(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

/// Withholds every row from every reader and refuses every write, which is the
/// two shapes a policy denial takes.
struct DenyAll;

impl VisibilityPolicy for DenyAll {
    type Watcher = Arc<Principal>;
    type Error = std::convert::Infallible;
    type Backend = PgBackend;

    // The caller pre-fills every verdict with a denial, so granting nothing
    // withholds every row.
    #[allow(clippy::unused_async_trait_impl)]
    async fn may_see<R>(
        &self,
        _row: &R,
        _watchers: &[Self::Watcher],
        _verdicts: &mut [Verdict],
    ) -> Result<(), Self::Error>
    where
        R: RowView<Backend = PgBackend> + Sync + ?Sized,
    {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_write<R>(
        &self,
        _row: &R,
        _watcher: &Self::Watcher,
        _op: WriteOp,
    ) -> Result<Verdict, Self::Error>
    where
        R: RowView<Backend = PgBackend> + Sync + ?Sized,
    {
        Ok(Verdict::Deny)
    }
}

/// Answers every crossing with a fixed verdict and counts how many it was asked
/// about, so a test can assert the application was never consulted.
struct Recording {
    verdict: Enforcement,
    asked: Arc<AtomicUsize>,
}

impl EnforcementPolicy<String> for Recording {
    fn on_threshold<'a>(&'a self, _crossing: &'a Crossing<String>) -> EnforcementFuture<'a> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        let verdict = self.verdict;
        Box::pin(async move { verdict })
    }
}

/// Thresholds tight enough for a test to cross them, uniform across signals so
/// each test names only the numbers it cares about.
fn limits(person: u32, connection: u32) -> AbuseConfig {
    AbuseLimits::new()
        .person(
            PersonLimits::new()
                .refused_grants(person, WINDOW)
                .unresolvable_subscriptions(person, WINDOW)
                .rejected_writes(person, WINDOW)
                .failed_renewals(person, WINDOW),
        )
        .connection(
            ConnectionLimits::new()
                .refused_grants(connection)
                .unresolvable_subscriptions(connection)
                .rejected_writes(connection),
        )
        .build()
        .expect("the thresholds a test names are valid")
}

/// Create the deployment-owned ban and audit tables. connetto emits no DDL, so
/// the test owns them, and the SQL mirrors the module documentation of
/// `connetto_server::ban` and `docs/architecture/08-authorization.md`.
async fn reset_tables(fixture: &Fixture) {
    for statement in [
        "DROP TABLE IF EXISTS connetto_bans".to_owned(),
        "DROP TABLE IF EXISTS auth_events".to_owned(),
        format!("DROP TYPE IF EXISTS {AUTH_OP_TYPE}"),
        format!(
            "CREATE TYPE {AUTH_OP_TYPE} AS ENUM (\
                'logged_out', 'session_revoked', 'token_replayed', \
                'capability_minted', 'permission_change', 'model_change', \
                'banned', 'ban_lifted')"
        ),
        "CREATE TABLE connetto_bans (\
            user_id TEXT PRIMARY KEY, \
            session UUID NOT NULL, \
            reason TEXT NOT NULL, \
            banned_at TIMESTAMPTZ NOT NULL, \
            expires_at TIMESTAMPTZ)"
            .to_owned(),
        format!(
            "CREATE TABLE auth_events (\
                at TIMESTAMPTZ NOT NULL DEFAULT now(), \
                session UUID NOT NULL, \
                user_id TEXT, \
                op {AUTH_OP_TYPE} NOT NULL, \
                table_name TEXT, \
                pk UUID)"
        ),
    ] {
        fixture.exec(&statement).await;
    }
}

/// A guard wired to the real ban list and audit sink on the owner pool.
fn guard(
    fixture: &Fixture,
    abuse: AbuseConfig,
    policy: Option<Arc<dyn EnforcementPolicy<String>>>,
) -> Arc<RequestGuard<String>> {
    throttled_guard(fixture, ThrottleConfig::default(), abuse, policy)
}

/// The same, with the request limits tightened too, for a test whose subject is
/// what happens when a rate limit trips.
fn throttled_guard(
    fixture: &Fixture,
    throttle: ThrottleConfig,
    abuse: AbuseConfig,
    policy: Option<Arc<dyn EnforcementPolicy<String>>>,
) -> Arc<RequestGuard<String>> {
    let mut built = RequestGuard::new(throttle, abuse)
        .with_bans(pg_ban_store::<ConnettoBans>(fixture.admin().clone()));
    if let Some(policy) = policy {
        built = built.with_enforcement(policy);
    }
    let built = Arc::new(built);
    built.set_audit_hook(pg_audit_hook::<ConnettoAudit>(fixture.admin().clone()));
    built
}

/// A manager over `auth`, with the close hook pointing back at it so a ban ends
/// the connections the banned person holds.
fn manager<A>(
    fixture: &Fixture,
    auth: A,
    guard: &Arc<RequestGuard<String>>,
) -> Arc<SessionManager<KeyedSnapshot, A, ConnettoWatermark>>
where
    A: VisibilityPolicy<Watcher = Arc<Principal>, Backend = PgBackend> + 'static,
{
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        KeyedSnapshot,
        auth,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::clone(guard),
        SessionConfig::default(),
    );
    let closing = Arc::clone(&manager);
    guard.set_close_hook(Arc::new(move |user| {
        let manager = Arc::clone(&closing);
        tokio::spawn(async move {
            manager.close_person(&user).await;
        });
    }));
    manager
}

/// A connection and the task serving it.
struct Live {
    client: LoopbackTransport,
    server: tokio::task::JoinHandle<()>,
}

/// Read a counter without meeting the diesel prelude's blanket `load`.
fn times_asked(counter: &AtomicUsize) -> usize {
    AtomicUsize::load(counter, Ordering::Relaxed)
}

/// Open a connection presenting `grants`, expecting the handshake to succeed.
async fn connect<A>(
    manager: &Arc<SessionManager<KeyedSnapshot, A, ConnettoWatermark>>,
    client_id: &str,
    grants: &[&str],
) -> Live
where
    A: VisibilityPolicy<Watcher = Arc<Principal>, Backend = PgBackend> + 'static,
{
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(manager);
    let server = tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id);
    for grant in grants {
        handshake = handshake.with_grant(Grant::new(*grant));
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected a handshake ack");
    };
    Live { client, server }
}

/// Attempt a handshake and report whether it was acknowledged.
///
/// A refused one draws no frame and no reason: the socket simply ends, which is
/// what a banned caller sees and what a caller whose subscription failed sees,
/// so neither learns which happened.
async fn handshake_accepted<A>(
    manager: &Arc<SessionManager<KeyedSnapshot, A, ConnettoWatermark>>,
    client_id: &str,
    grants: &[&str],
) -> bool
where
    A: VisibilityPolicy<Watcher = Arc<Principal>, Backend = PgBackend> + 'static,
{
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(manager);
    let server = tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id);
    for grant in grants {
        handshake = handshake.with_grant(Grant::new(*grant));
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let accepted = match tokio::time::timeout(SETTLE, client.recv()).await {
        Ok(Ok(Some(IncomingFrame::Control(ControlMessage::HandshakeAck(_))))) => true,
        Ok(Ok(None)) => false,
        other => panic!("expected an ack or a bare close, got {other:?}"),
    };
    drop(client);
    server.await.expect("join server");
    accepted
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        match transport.recv().await.expect("recv") {
            Some(IncomingFrame::Control(msg)) => return msg,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("the connection closed while waiting for a control frame"),
        }
    }
}

/// Subscribe and read until the subscription resolves, returning the frame that
/// settled it.
async fn subscribe(client: &mut LoopbackTransport, sub_id: &str, query: &str) -> ControlMessage {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: sub_id.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
    loop {
        match next_control(client).await {
            ControlMessage::SnapshotBegin(_) => {}
            settled => return settled,
        }
    }
}

/// Name one table or column that does not resolve, and confirm the refusal is
/// the fixed one.
async fn probe(client: &mut LoopbackTransport, sub_id: &str) {
    let ControlMessage::NonFatalError(refusal) = subscribe(client, sub_id, GHOST).await else {
        panic!("naming a table that does not exist draws the fixed refusal");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
}

/// The ban on `user`, read with the owner's connection.
async fn ban_row(pool: &Pool<AsyncPgConnection>, user: &str) -> Option<(String, Option<Instant>)> {
    let mut conn = pool.get().await.expect("owner connection");
    connetto_bans::table
        .filter(connetto_bans::user_id.eq(user))
        .select((connetto_bans::reason, connetto_bans::expires_at))
        .first::<(String, Option<Instant>)>(&mut conn)
        .await
        .optional()
        .expect("read the ban list")
}

/// Wait for the ban on `user` to land, since the write rides a spawned task.
async fn await_ban(pool: &Pool<AsyncPgConnection>, user: &str) -> (String, Option<Instant>) {
    let deadline = tokio::time::Instant::now() + SETTLE;
    loop {
        if let Some(row) = ban_row(pool, user).await {
            return row;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no ban was written for {user}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// How many `auth_events` rows carry `op`.
async fn recorded(pool: &Pool<AsyncPgConnection>, op: AuthOp) -> i64 {
    let mut conn = pool.get().await.expect("owner connection");
    auth_events::table
        .filter(auth_events::op.eq(op))
        .count()
        .get_result(&mut conn)
        .await
        .expect("count the recorded events")
}

/// Wait for one `auth_events` row carrying `op`, since the write is spawned.
async fn await_recorded(pool: &Pool<AsyncPgConnection>, op: AuthOp) {
    let deadline = tokio::time::Instant::now() + SETTLE;
    loop {
        if recorded(pool, op).await > 0 {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no {} row was recorded",
            op.label()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Wait for the connection to end, which is all a banned caller is told.
async fn expect_dropped(live: Live) {
    let Live { mut client, server } = live;
    let closed = tokio::time::timeout(SETTLE, async {
        while let Some(frame) = client.recv().await.expect("recv") {
            // A queued patch may trail the refusal, so read past anything until
            // the socket ends.
            let _ = frame;
        }
    })
    .await;
    assert!(closed.is_ok(), "the connection was not closed");
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_crossed_threshold_bans_the_person_and_refuses_the_next_handshake() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(2, 1), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);

    let mut live = connect(&manager, "prober", &["user:alice#one"]).await;
    probe(&mut live.client, "ghost-0").await;
    probe(&mut live.client, "ghost-1").await;

    let (reason, expires_at) = await_ban(fixture.admin(), "alice").await;
    assert_eq!(
        reason, "unresolvable_subscription 2 per 300s",
        "the ban names the threshold it crossed while it is in force"
    );
    assert!(
        expires_at.is_none(),
        "connetto proposes a permanent ban and nothing overrode it"
    );
    await_recorded(fixture.admin(), AuthOp::Banned).await;

    // The live connection ends, telling the caller nothing that distinguishes a
    // ban from any other close.
    expect_dropped(live).await;

    assert!(
        !handshake_accepted(&manager, "prober", &["user:alice#one"]).await,
        "the next handshake is refused at the door"
    );
    assert!(
        handshake_accepted(&manager, "other", &["user:bob#one"]).await,
        "a ban names one identity and no one else"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn the_application_decides_the_outcome_and_silence_takes_the_proposal() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;

    // Overriding with a bounded ban.
    let asked = Arc::new(AtomicUsize::new(0));
    let bounded = guard(
        &fixture,
        limits(2, 1),
        Some(Arc::new(Recording {
            verdict: Enforcement::BanFor(Duration::from_secs(3600)),
            asked: Arc::clone(&asked),
        })),
    );
    let bounded_manager = manager(&fixture, PermissiveAuth, &bounded);
    let mut live = connect(&bounded_manager, "bounded", &["user:carol#one"]).await;
    probe(&mut live.client, "ghost-0").await;
    probe(&mut live.client, "ghost-1").await;
    let (_, expires_at) = await_ban(fixture.admin(), "carol").await;
    assert!(
        expires_at.is_some(),
        "the application's duration replaced the permanent proposal"
    );
    assert_eq!(times_asked(&asked), 1, "asked once, for one crossing");
    expect_dropped(live).await;

    // Declining leaves nothing behind, and the connection stays open.
    let declined = Arc::new(AtomicUsize::new(0));
    let lenient = guard(
        &fixture,
        limits(2, 1),
        Some(Arc::new(Recording {
            verdict: Enforcement::Ignore,
            asked: Arc::clone(&declined),
        })),
    );
    let lenient_manager = manager(&fixture, PermissiveAuth, &lenient);
    let mut tolerated = connect(&lenient_manager, "lenient", &["user:dave#one"]).await;
    probe(&mut tolerated.client, "ghost-0").await;
    probe(&mut tolerated.client, "ghost-1").await;
    // The refusal below both proves the session survived and orders the assert
    // after the crossing was handled.
    probe(&mut tolerated.client, "ghost-2").await;
    assert!(
        ban_row(fixture.admin(), "dave").await.is_none(),
        "the application declined, so no ban was written"
    );
    assert!(times_asked(&declined) >= 1, "the application was asked");
    tolerated.client.close().await.expect("close");
    tolerated.server.await.expect("join server");
}

/// An expiry that passes stops applying with nothing having run, and a lift is
/// the only way a ban ends with a record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn an_expiry_lapses_silently_and_only_a_lift_is_recorded() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(2, 1), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);
    let bans = pg_ban_store::<ConnettoBans>(fixture.admin().clone());
    let session = connetto_core::SessionId::from_uuid(uuid::Uuid::new_v4());

    bans.impose(NewBan::starting_now(
        "erin".to_owned(),
        session,
        "unresolvable_subscription 2 per 300s",
        Some(Duration::from_secs(3600)),
    ))
    .await
    .expect("impose the live ban");
    let lapsed = NewBan {
        user_id: "frank".to_owned(),
        session,
        reason: "unresolvable_subscription 2 per 300s".to_owned(),
        banned_at: chrono::Utc::now() - chrono::TimeDelta::hours(2),
        expires_at: Some(chrono::Utc::now() - chrono::TimeDelta::hours(1)),
    };
    bans.impose(lapsed).await.expect("impose the lapsed ban");

    assert!(
        !handshake_accepted(&manager, "erin", &["user:erin#one"]).await,
        "a ban whose expiry has not passed still refuses"
    );
    assert!(
        handshake_accepted(&manager, "frank", &["user:frank#one"]).await,
        "an expiry that passed stops applying, with nothing having run to lift it"
    );
    assert!(
        ban_row(fixture.admin(), "frank").await.is_some(),
        "the lapsed row stays until something clears it"
    );
    assert_eq!(
        recorded(fixture.admin(), AuthOp::BanLifted).await,
        0,
        "an expiry that merely lapses appears nowhere"
    );

    assert!(
        guard.lift_ban(&"frank".to_owned()).await.expect("lift"),
        "the lift clears the lapsed row"
    );
    assert!(
        ban_row(fixture.admin(), "frank").await.is_none(),
        "the lift removed the row"
    );
    await_recorded(fixture.admin(), AuthOp::BanLifted).await;
    assert!(
        !guard.lift_ban(&"frank".to_owned()).await.expect("lift"),
        "a second lift finds nothing and records nothing"
    );
    assert_eq!(
        recorded(fixture.admin(), AuthOp::BanLifted).await,
        1,
        "one lift, one record"
    );
}

/// Reads drive no counter, which is what keeps this feature from banning every
/// honest user.
///
/// The per-person threshold is two and this caller drives nine read events, so
/// anything a read touched would have crossed it several times over. The caller
/// subscribes successfully and then has every row withheld by the policy, which
/// is what a filtered read is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn filtered_reads_drive_no_counter() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(2, 1), None);
    let manager = manager(&fixture, DenyAll, &guard);

    let mut live = connect(&manager, "reader", &["user:grace#one"]).await;
    for nth in 0..5 {
        let settled = subscribe(&mut live.client, &format!("sub-{nth}"), QUERY).await;
        assert!(
            matches!(settled, ControlMessage::SnapshotEnd(_)),
            "a resolvable query is served, got {settled:?}"
        );
    }

    // Four row changes, every one of them withheld from this reader.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    for sql in [
        "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'a')",
        "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'b')",
        "UPDATE orders SET status = 'c' WHERE id = 1",
        "DELETE FROM orders WHERE id = 2",
    ] {
        source.execute_sql(sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch event");
        }
    }

    // A ping orders the assertion after every frame the changes produced.
    live.client
        .send_control(ControlMessage::Ping(connetto_core::messages::Ping {
            nonce: 7,
        }))
        .await
        .expect("send ping");
    loop {
        match live.client.recv().await.expect("recv") {
            Some(IncomingFrame::Control(ControlMessage::Pong(pong))) => {
                assert_eq!(pong.nonce, 7);
                break;
            }
            Some(_) => {}
            None => panic!("the connection closed, so a read drove a counter"),
        }
    }
    assert!(
        ban_row(fixture.admin(), "grace").await.is_none(),
        "a read must never reach a threshold, whatever the policy withheld"
    );

    live.client.close().await.expect("close");
    live.server.await.expect("join server");
}

/// An unidentified caller is closed and the application is never asked, because
/// a verdict about a caller nobody can ban would mean nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn an_unidentified_caller_is_closed_and_the_application_is_not_asked() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let asked = Arc::new(AtomicUsize::new(0));
    let guard = guard(
        &fixture,
        limits(4, 1),
        Some(Arc::new(Recording {
            verdict: Enforcement::BanPermanently,
            asked: Arc::clone(&asked),
        })),
    );
    let manager = manager(&fixture, PermissiveAuth, &guard);

    let mut live = connect(&manager, "visitor", &[]).await;
    probe(&mut live.client, "ghost-0").await;
    expect_dropped(live).await;

    assert_eq!(
        times_asked(&asked),
        0,
        "the trait only ever receives a caller that can actually be banned"
    );
    // A reconnect starts over, since the connection was the window.
    let mut again = connect(&manager, "visitor", &[]).await;
    probe(&mut again.client, "ghost-0").await;
    expect_dropped(again).await;
}

/// The ban applies with row-level security on the ban table and no policy
/// admitting anyone, because the check reads on the owner pool.
///
/// The reader half is the assertion that matters: on that pool the row is not an
/// error but zero rows, so a regression here fails silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_ban_applies_under_row_level_security_with_no_policy_admitting_anyone() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    fixture
        .setup(&[
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ban_reader') \
             THEN CREATE ROLE ban_reader LOGIN PASSWORD 'ban_reader'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO ban_reader",
            "GRANT SELECT ON connetto_bans TO ban_reader",
            "ALTER TABLE connetto_bans ENABLE ROW LEVEL SECURITY",
            "DROP POLICY IF EXISTS bans_admit_nobody ON connetto_bans",
            "CREATE POLICY bans_admit_nobody ON connetto_bans FOR SELECT USING (false)",
        ])
        .await;

    let guard = guard(&fixture, limits(2, 1), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);
    let bans = pg_ban_store::<ConnettoBans>(fixture.admin().clone());
    bans.impose(NewBan::starting_now(
        "heidi".to_owned(),
        connetto_core::SessionId::from_uuid(uuid::Uuid::new_v4()),
        "unresolvable_subscription 2 per 300s",
        None,
    ))
    .await
    .expect("impose the ban");

    let reader = connetto_test_harness::pool_for(&connetto_test_harness::with_user(
        fixture.admin_url(),
        "ban_reader",
        "ban_reader",
    ))
    .await;
    let mut reader_conn = reader.get().await.expect("reader connection");
    let visible: i64 = connetto_bans::table
        .count()
        .get_result(&mut reader_conn)
        .await
        .expect("count as the reader role");
    assert_eq!(
        visible, 0,
        "the policy admits nobody, so on this pool the ban is zero rows rather than an error"
    );

    assert!(
        !handshake_accepted(&manager, "heidi", &["user:heidi#one"]).await,
        "the check reads on the owner pool, so the ban applies regardless"
    );

    fixture
        .setup(&[
            "DROP POLICY IF EXISTS bans_admit_nobody ON connetto_bans",
            "ALTER TABLE connetto_bans DISABLE ROW LEVEL SECURITY",
        ])
        .await;
}

/// An offline queue flushing rejected writes must not reach the threshold, since
/// that is the honest burst the shipped numbers have to clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn an_offline_queue_of_rejected_writes_does_not_reach_the_threshold() {
    const FLUSHED: u64 = 100;

    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    // The shipped per-person number for this signal, which is the one no rate
    // limit sits above.
    let guard = guard(&fixture, limits(1000, 200), None);
    let manager = manager(&fixture, DenyAll, &guard);
    let mut live = connect(&manager, "queued", &["user:ivan#one"]).await;

    for seq in 1..=FLUSHED {
        let changeset = insert_changeset(
            "orders",
            &["id", "price", "quantity", "status"],
            &[0],
            vec![
                RowValue::Integer(i64::try_from(seq).expect("a small sequence fits")),
                RowValue::Real(1.0),
                RowValue::Integer(1),
                RowValue::Text("queued".to_owned()),
            ],
        );
        let payload = zstd::encode_all(changeset.as_slice(), 3).expect("compress");
        live.client
            .send_control(ControlMessage::MutationHeader(
                connetto_core::messages::MutationHeader::new(seq, 1),
            ))
            .await
            .expect("send header");
        live.client
            .send_bulk(BulkMessage::MutationPatch(
                connetto_core::messages::MutationPatch {
                    client_seq: seq,
                    patchset_zstd: payload,
                },
            ))
            .await
            .expect("send patch");
        let ControlMessage::MutationReject(_) = next_control(&mut live.client).await else {
            panic!("the policy denies every write, so every one is rejected");
        };
    }

    assert!(
        ban_row(fixture.admin(), "ivan").await.is_none(),
        "{FLUSHED} rejected writes must stay well clear of the shipped threshold"
    );

    live.client.close().await.expect("close");
    live.server.await.expect("join server");
}

/// A person's tally survives signing out and back in, which is the whole reason
/// the detector names the person rather than the handle.
///
/// The two grants resolve to one user and two different handles, exactly as two
/// logins do, so a tally keyed on the handle would start over on the second and
/// never cross.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_persons_tally_survives_signing_out_and_back_in() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(3, 2), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);

    let mut first = connect(&manager, "judy", &["user:judy#one"]).await;
    probe(&mut first.client, "ghost-0").await;
    probe(&mut first.client, "ghost-1").await;
    assert!(
        ban_row(fixture.admin(), "judy").await.is_none(),
        "two of three is under the threshold"
    );
    first.client.close().await.expect("close");
    first.server.await.expect("join server");

    // A new login: same person, a handle they have never held before.
    let mut second = connect(&manager, "judy", &["user:judy#two"]).await;
    probe(&mut second.client, "ghost-2").await;
    let (_, expires_at) = await_ban(fixture.admin(), "judy").await;
    assert!(expires_at.is_none());
    expect_dropped(second).await;
}

/// Two connections of one person accumulate once, and a ban ends both, since a
/// person holds one connection per device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn one_person_on_two_connections_accumulates_once_and_both_close() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(3, 2), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);

    let mut laptop = connect(&manager, "ken-laptop", &["user:ken#laptop"]).await;
    let mut phone = connect(&manager, "ken-phone", &["user:ken#phone"]).await;
    probe(&mut laptop.client, "ghost-0").await;
    probe(&mut laptop.client, "ghost-1").await;
    probe(&mut phone.client, "ghost-2").await;

    let (_, expires_at) = await_ban(fixture.admin(), "ken").await;
    assert!(expires_at.is_none());
    expect_dropped(phone).await;
    expect_dropped(laptop).await;
}

/// Revoking a share produces no refusal at all, which is the correction this
/// phase rests on.
///
/// The per-connection refusal threshold is one, so a single refusal would close
/// this connection. The withdrawn key still checks out, so the handshake
/// completes, the caller counts nothing, and the rows simply stop matching.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn revoking_a_share_produces_no_grant_refusal() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let guard = guard(&fixture, limits(2, 1), None);
    let manager = manager(&fixture, PermissiveAuth, &guard);

    let mut live = connect(&manager, "holder", &[REVOKED_KEY]).await;
    let settled = subscribe(&mut live.client, "shared", QUERY).await;
    assert!(
        matches!(settled, ControlMessage::SnapshotEnd(_)),
        "the subscription resolves, got {settled:?}"
    );

    // Still open after the handshake and the read, so nothing was counted: one
    // refusal at these thresholds would have closed the connection.
    live.client
        .send_control(ControlMessage::Ping(connetto_core::messages::Ping {
            nonce: 3,
        }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut live.client).await else {
        panic!("expected a pong, so the run survived the withdrawn key");
    };
    assert_eq!(pong.nonce, 3);
    assert!(
        ban_row(fixture.admin(), REVOKED_KEY).await.is_none(),
        "a withdrawn share is the application deleting its own relation, never a ban"
    );

    live.client.close().await.expect("close");
    live.server.await.expect("join server");
}

/// Tripping the credential rate limit must not erase the refusals it counted.
///
/// R19 closes a caller that presents bad keys faster than its allowance, and the
/// count travelled to the detector with the handshake outcome, which a refused
/// handshake never returns. So the caller spraying keys fastest was the one this
/// phase could not see, while a slower one crossed the threshold: a rate limit is
/// meant to cap how fast a signal accumulates, never to erase what it saw.
///
/// The login grant comes first so the identity resolves before the loop stops,
/// which is the realistic shape: a signed-in caller working through a list of
/// keys it should not hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_tripped_credential_limit_still_counts_its_refusals() {
    let fixture = Fixture::acquire().await;
    reset_tables(&fixture).await;
    let abuse = AbuseLimits::new()
        .person(PersonLimits::new().refused_grants(4, WINDOW))
        .connection(ConnectionLimits::new().refused_grants(3))
        .build()
        .expect("valid thresholds");
    let guard = throttled_guard(
        &fixture,
        ThrottleConfig::new().anonymous(TierLimits::anonymous().credential_refusals(2, WINDOW)),
        abuse,
        None,
    );
    let manager = manager(&fixture, PermissiveAuth, &guard);

    // Each attempt spends its whole credential allowance and is closed for it,
    // so nothing here ever reaches the run loop.
    for attempt in 0..2 {
        let (server_end, mut client) = loopback();
        let serving = Arc::clone(&manager);
        let server = tokio::spawn(async move {
            let _ = serving.serve(server_end).await;
        });
        let mut handshake =
            Handshake::new(PROTOCOL_VERSION, "mallory").with_grant(Grant::new("user:mallory#one"));
        for nth in 0..5 {
            handshake = handshake.with_grant(Grant::new(format!("forged-{attempt}-{nth}")));
        }
        client
            .send_control(ControlMessage::Handshake(handshake))
            .await
            .expect("send handshake");
        let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
            panic!("a caller past its credential limit is closed, not acknowledged");
        };
        assert!(matches!(
            fatal.reason,
            connetto_core::messages::FatalErrorReason::RateLimited { .. }
        ));
        drop(client);
        server.await.expect("join server");
    }

    let (_, expires_at) = await_ban(fixture.admin(), "mallory").await;
    assert!(
        expires_at.is_none(),
        "six refusals across two closed handshakes cross a threshold of four"
    );
}
