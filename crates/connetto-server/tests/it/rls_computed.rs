//! R85: per-viewer re-execution over a Row-Level-Security table, end to end.
//!
//! An aggregate over an RLS table cannot share one fold across viewers, so
//! subql refuses it at registration. connetto answers the refusal by
//! re-registering with per-consumer database reads under the asking viewer's
//! own identity binding, so two viewers subscribing the same statistic each
//! receive their own answer over the rows their policies grant, a change to
//! one viewer's rows moves only that viewer's number, and an unidentified
//! caller keeps the refusal because there is nobody to read as.
//!
//! Needs Docker: the fixture starts its own Postgres. Like every RLS test,
//! the reads must run as a non-superuser role that does not own the table,
//! since a superuser or the owner bypasses RLS silently: the test creates
//! `app_reader` for the connector and does privileged setup as admin.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{AggregateUpdate, ControlMessage, SUBSCRIPTION_REFUSED};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    AbuseConfig, Materializer, PgReadConnector, PgSnapshotSource, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, ThrottleConfig, TierLimits, loopback,
    pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture, RosterAuth, pool_for, with_user};
use subql::{CdcSource, PgSqliteEmuSource};

/// The catalog DDL carries the RLS marker: subql classifies the table from
/// the parsed DDL, and without it the aggregate registers as a shared fold
/// and nothing here fires.
const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT); \
                      ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";
/// The emulated change source runs plain SQLite DDL, no policy machinery.
const EMU_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT);";
const QUERY: &str = "SELECT COUNT(*) FROM notes";

/// A manager whose computed reads run as `app_reader`, subject to RLS.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoWatermark, PgReadConnector>;

/// Provision the RLS table and the reader role, then build the manager whose
/// connector reads as that role.
async fn manager(fixture: &Fixture) -> Arc<Manager> {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
             THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT)",
            "ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY notes_p ON notes USING ( \
               owner = current_setting('app.user_id', true))",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT SELECT ON notes TO app_reader",
        ])
        .await;
    let reader = pool_for(&with_user(fixture.admin_url(), "app_reader", "app_reader")).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(Duration::from_secs(30))),
        AbuseConfig::default(),
    ));
    let admin = fixture.admin().clone();
    SessionManager::with_connector(
        Materializer::with_read_connector(
            PG_DDL,
            RuntimeWritableCatalog::default(),
            None,
            None,
            PgReadConnector::with_session_setup(reader.clone()),
        )
        .expect("build materializer"),
        PgSnapshotSource::from_ddl(admin.clone(), PG_DDL).expect("snapshot source"),
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(reader),
        pg_write_target::<ConnettoWatermark>(admin, PG_DDL).expect("build write target"),
        guard,
        SessionConfig::default(),
    )
}

/// One in-process client on its own session.
fn connect(manager: &Arc<Manager>) -> Client {
    let (server_end, client_end) = loopback();
    let session = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = session.serve(server_end).await;
    });
    Client::new(client_end)
}

/// The next aggregate frame for `sub_id`.
async fn next_aggregate(client: &mut Client, sub_id: &str) -> AggregateUpdate {
    let ControlMessage::AggregateUpdate(update) = client.next_control().await else {
        panic!("expected an aggregate frame for {sub_id}");
    };
    assert_eq!(update.sub_id, sub_id);
    update
}

/// The count a computed answer carries, whichever shape served it: a bare
/// scalar body, or the whole re-read's one-object row array.
fn count_of(update: &AggregateUpdate) -> i64 {
    let body = update.result_json.as_deref().expect("an answer has a body");
    let value: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    let scalar = match &value {
        serde_json::Value::Array(rows) => {
            assert_eq!(rows.len(), 1, "a count re-read answers one row: {body}");
            rows[0]
                .as_object()
                .and_then(|row| row.values().next())
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        }
        other => other.clone(),
    };
    scalar
        .as_i64()
        .or_else(|| scalar.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("no count in {body}"))
}

/// Run `sql` on the emulated source and dispatch every event it produced.
async fn apply(source: &mut PgSqliteEmuSource, manager: &Arc<Manager>, sql: &str) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
}

/// The R85 done-when: two viewers subscribing the same aggregate over an RLS
/// table each receive their own value, and a change to one viewer's rows
/// changes only the affected viewer's result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_viewers_get_their_own_statistic_over_an_rls_table() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    fixture
        .exec("INSERT INTO notes VALUES (1, 'alice'), (2, 'alice'), (3, 'alice'), (10, 'bob')")
        .await;

    let mut alice = connect(&manager);
    alice.handshake_with("alice", "user:alice").await;
    alice.subscribe("mine", QUERY).await;
    let seed = next_aggregate(&mut alice, "mine").await;
    assert_eq!(count_of(&seed), 3, "alice counts only her own rows");

    let mut bob = connect(&manager);
    bob.handshake_with("bob", "user:bob").await;
    bob.subscribe("mine", QUERY).await;
    let seed = next_aggregate(&mut bob, "mine").await;
    assert_eq!(count_of(&seed), 1, "bob counts only his own row");

    // A change to alice's rows: her count moves, bob's does not. The
    // re-execution reads the source, so the fixture moves first and the
    // emulated change stream then triggers the per-viewer re-reads.
    fixture.exec("INSERT INTO notes VALUES (4, 'alice')").await;
    let mut source = PgSqliteEmuSource::open_in_memory(EMU_DDL).expect("open emu source");
    apply(
        &mut source,
        &manager,
        "INSERT INTO notes VALUES (4, 'alice')",
    )
    .await;
    let moved = next_aggregate(&mut alice, "mine").await;
    assert_eq!(count_of(&moved), 4, "alice's own statistic moved");

    // Bob's answer, whether or not his re-read emitted a frame, still counts
    // one row: drain everything ahead of a ping fence and assert each frame.
    match bob.barrier(7).await {
        ControlMessage::Pong(pong) => assert_eq!(pong.nonce, 7),
        ControlMessage::AggregateUpdate(update) => {
            assert_eq!(
                count_of(&update),
                1,
                "a change to alice's rows must not move bob's statistic"
            );
            let ControlMessage::Pong(pong) = bob.next_control().await else {
                panic!("one re-read emits at most one frame before the fence");
            };
            assert_eq!(pong.nonce, 7);
        }
        other => panic!("unexpected frame ahead of the fence: {other:?}"),
    }
}

/// The refusal half: a caller whose handshake resolved no identity cannot be
/// read as, so the aggregate over the RLS table keeps its refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unidentified_caller_keeps_the_rls_aggregate_refusal() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;

    let mut anon = connect(&manager);
    anon.handshake_unidentified("anon").await;
    anon.subscribe("mine", QUERY).await;
    let ControlMessage::NonFatalError(refusal) = anon.next_control().await else {
        panic!("an unidentified caller's RLS aggregate must be refused");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
}
