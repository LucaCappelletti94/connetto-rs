//! Phase R39: a strict reserved share of the reader pool for identified
//! callers, asserted against a real pool because the property is contention.
//!
//! Two properties, each the phase's own words:
//!
//! * with the reserve set and every other connection held by unidentified
//!   callers, an identified caller still completes a handshake and a snapshot,
//!   while an unidentified caller over the share draws R19's refusal shape at
//!   both boundaries (the nonfatal `RateLimited` on a subscribe, the fatal one
//!   on a handshake);
//! * with no identified caller present, unidentified callers reach the full
//!   non-reserved share and are not capped below it.
//!
//! The contention rig is a row-level-security policy that sleeps: a read of
//! `slow_rows` as the reader role holds its pooled connection for the whole
//! sleep, which is the snapshot-transfer shape the reserve exists to survive.
//! The identified caller reads `fast_rows`, which carries no such policy.
//!
//! `#[ignore]` by default. It needs a running Postgres. Point `DATABASE_URL` at
//! one and run with `--ignored` after explicit approval.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalErrorReason, Grant, Handshake, MutationHeader, MutationPatch,
    Ping, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_server::{
    AbuseConfig, LoopbackTransport, Materializer, PermissiveAuth, PgSnapshotSource, ReaderReserve,
    RequestGuard, RuntimeWritableCatalog, SessionConfig, SessionManager, ThrottleConfig, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, with_user};
use diesel::prelude::*;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};

/// The reader pool under test: three connections, one held for identified
/// callers, so the unidentified share is exactly two.
const TOTAL: u32 = 3;
const RESERVED: u32 = 1;

const PG_DDL: &str = "CREATE TABLE slow_rows (id INT PRIMARY KEY, body TEXT); \
    CREATE TABLE fast_rows (id INT PRIMARY KEY, body TEXT);";

diesel::table! {
    /// The slow table, its read gated by the sleeping policy.
    slow_rows (id) {
        /// Primary key.
        id -> Int4,
        /// Payload column.
        body -> Nullable<Text>,
    }
}

diesel::table! {
    /// The fast table the identified caller reads.
    fast_rows (id) {
        /// Primary key.
        id -> Int4,
        /// Payload column.
        body -> Nullable<Text>,
    }
}

diesel::table! {
    /// The columns of Postgres's own activity view this test reads. A system
    /// view, so the typed schema is declared here rather than migrated.
    pg_stat_activity (pid) {
        /// The backend's process id.
        pid -> Int4,
        /// The backend's state, `active` while inside a statement.
        state -> Nullable<Text>,
        /// The statement the backend is running.
        query -> Nullable<Text>,
    }
}

async fn sized_pool(url: &str, size: u32) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder()
        .max_size(size)
        .build(manager)
        .await
        .expect("build pool")
}

/// Provision the two tables, the sleeping policy, and the reader role, and
/// return the reader pool sized to [`TOTAL`]. Raw statements are DDL, role,
/// policy, and function provisioning, the sanctioned case. The seed rows go
/// through the typed DSL below.
async fn setup(fixture: &Fixture, snail_secs: f64) -> Pool<AsyncPgConnection> {
    let snail = format!(
        "CREATE OR REPLACE FUNCTION reserve_snail() RETURNS boolean LANGUAGE plpgsql \
         AS $$ BEGIN PERFORM pg_sleep({snail_secs}); RETURN true; END $$"
    );
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS slow_rows CASCADE",
            "DROP TABLE IF EXISTS fast_rows CASCADE",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reserve') \
             THEN CREATE ROLE app_reserve LOGIN PASSWORD 'app_reserve'; END IF; END $$",
            &snail,
            "CREATE TABLE slow_rows (id INT PRIMARY KEY, body TEXT)",
            "CREATE TABLE fast_rows (id INT PRIMARY KEY, body TEXT)",
            "ALTER TABLE slow_rows ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY slow_p ON slow_rows FOR SELECT USING (reserve_snail())",
            "GRANT USAGE ON SCHEMA public TO app_reserve",
            "GRANT SELECT ON slow_rows, fast_rows TO app_reserve",
            "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_reserve",
        ])
        .await;
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel::insert_into(slow_rows::table)
        .values((slow_rows::id.eq(1), slow_rows::body.eq("molasses")))
        .execute(&mut *conn)
        .await
        .expect("seed slow_rows");
    diesel::insert_into(fast_rows::table)
        .values((fast_rows::id.eq(1), fast_rows::body.eq("quick")))
        .execute(&mut *conn)
        .await
        .expect("seed fast_rows");
    drop(conn);
    sized_pool(
        &with_user(fixture.admin_url(), "app_reserve", "app_reserve"),
        TOTAL,
    )
    .await
}

type Manager = Arc<SessionManager<PgSnapshotSource, PermissiveAuth, ConnettoWatermark>>;

/// Build a manager over the reader pool whose only unusual setting is the
/// reserve, wired exactly as the binary wires it: the snapshot source, the
/// write target (the handshake watermark read), and the gate all over the one
/// pool under test.
fn manager(reader: &Pool<AsyncPgConnection>) -> Manager {
    let authority: Arc<dyn HandshakeAuthority> = Arc::new(TestGrantChecker);
    let guard = RequestGuard::new(ThrottleConfig::default(), AbuseConfig::default())
        .with_reader_gate(ReaderReserve::new().total(TOTAL).reserved(RESERVED).gate());
    SessionManager::new(
        Materializer::with_write_catalog(
            PG_DDL,
            RuntimeWritableCatalog::builder()
                .writable("fast_rows")
                .build(),
        )
        .expect("build materializer"),
        PgSnapshotSource::from_ddl(reader.clone(), PG_DDL).expect("build snapshot source"),
        PermissiveAuth,
        authority,
        pg_write_target::<ConnettoWatermark>(reader.clone(), PG_DDL).expect("build write target"),
        Arc::new(guard),
        SessionConfig::default(),
    )
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        match transport.recv().await.expect("recv") {
            Some(IncomingFrame::Control(msg)) => return msg,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("connection closed while waiting for a control frame"),
        }
    }
}

/// Open a connection presenting `grants` and complete the handshake.
async fn connect(
    manager: &Manager,
    client_id: &str,
    grants: &[&str],
) -> (LoopbackTransport, tokio::task::JoinHandle<()>) {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    let handle = tokio::spawn(async move {
        let _ = server.serve(server_end).await;
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
        panic!("expected handshake ack for {client_id}");
    };
    (client, handle)
}

/// Send a `Subscribe` without waiting for it to settle, so several snapshots
/// can be put in flight at once.
async fn send_subscribe<T: Transport>(client: &mut T, sub_id: &str, query: &str) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: sub_id.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
}

/// Read frames until the subscription settles: a `SnapshotEnd` when served, or
/// the refusal that turned it away.
async fn settle<T: Transport>(client: &mut T) -> ControlMessage {
    let settled = async {
        loop {
            match next_control(client).await {
                ControlMessage::SnapshotBegin(_) => {}
                settled => return settled,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), settled)
        .await
        .expect("subscription settles within a minute")
}

/// Upload one insert of `fast_rows` row 2 as `client_seq`, without waiting.
async fn send_mutation<T: Transport>(client: &mut T, client_seq: u64) {
    let table = SimpleTable::new("fast_rows", &["id", "body"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(2))
        .expect("set id")
        .set(1, Value::Text("deferred".to_owned()))
        .expect("set body");
    let changeset = ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build();
    let payload = zstd::encode_all(changeset.as_slice(), 3).expect("compress");
    client
        .send_control(ControlMessage::MutationHeader(MutationHeader::new(
            client_seq, 1,
        )))
        .await
        .expect("send header");
    client
        .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(
            client_seq, payload,
        )))
        .await
        .expect("send patch");
}

/// How many backends are inside the slow read right now, seen as admin so no
/// policy hides them. The filter excludes this probe's own statement.
async fn slow_reads_in_flight(fixture: &Fixture) -> i64 {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    pg_stat_activity::table
        .filter(pg_stat_activity::state.eq("active"))
        .filter(pg_stat_activity::query.ilike("%slow_rows%"))
        .filter(pg_stat_activity::query.not_ilike("%pg_stat_activity%"))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("read pg_stat_activity")
}

/// Wait until `want` backends hold the slow read, which is the moment the
/// unidentified share is genuinely occupied rather than merely asked for.
async fn wait_for_slow_reads(fixture: &Fixture, want: i64) {
    for _ in 0..200 {
        if slow_reads_in_flight(fixture).await >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("never saw {want} concurrent slow reads");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn an_identified_caller_completes_under_anonymous_saturation() {
    let fixture = Fixture::acquire().await;
    let reader = setup(&fixture, 8.0).await;
    let manager = manager(&reader);

    // Three anonymous callers handshake while the share is free. The third
    // exists to probe the subscribe boundary once the share is full.
    let (mut anon_a, _a) = connect(&manager, "anon-a", &[]).await;
    let (mut anon_b, _b) = connect(&manager, "anon-b", &[]).await;
    let (mut anon_c, _c) = connect(&manager, "anon-c", &[]).await;

    // The first two occupy the whole unidentified share (two connections),
    // each holding its pooled connection for the policy's sleep.
    send_subscribe(&mut anon_a, "anon-a-slow", "SELECT * FROM slow_rows").await;
    send_subscribe(&mut anon_b, "anon-b-slow", "SELECT * FROM slow_rows").await;
    wait_for_slow_reads(&fixture, 2).await;

    // The subscribe boundary: over the share, R19's nonfatal shape, and the
    // session survives it.
    send_subscribe(&mut anon_c, "anon-c-slow", "SELECT * FROM slow_rows").await;
    let refused = settle(&mut anon_c).await;
    let ControlMessage::RateLimited(limited) = refused else {
        panic!("an over-share subscribe draws the rate-limit shape, got {refused:?}");
    };
    assert_eq!(limited.related_to.as_deref(), Some("anon-c-slow"));
    assert!(
        limited.retry_after_ms > 0,
        "the refusal states how long to wait"
    );

    // The mutation boundary: the apply's checkout is refused in the same
    // shape, correlated by the client sequence, and the session survives to
    // answer a ping, so the deferral is nonfatal.
    send_mutation(&mut anon_c, 1).await;
    let deferred = settle(&mut anon_c).await;
    let ControlMessage::RateLimited(deferral) = deferred else {
        panic!("an over-share mutation is deferred in the rate-limit shape, got {deferred:?}");
    };
    assert_eq!(deferral.related_to.as_deref(), Some("1"));
    anon_c
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut anon_c).await else {
        panic!("expected pong after the deferral");
    };
    assert_eq!(pong.nonce, 7);

    // The handshake boundary: a fresh unidentified caller cannot even read its
    // watermark, so it draws R19's fatal shape.
    let (server_end, mut anon_d) = loopback();
    let manager_for_d = Arc::clone(&manager);
    let _d = tokio::spawn(async move {
        let _ = manager_for_d.serve(server_end).await;
    });
    anon_d
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "anon-d",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::FatalError(fatal) = next_control(&mut anon_d).await else {
        panic!("an over-share handshake is closed rather than acknowledged");
    };
    assert!(matches!(fatal.reason, FatalErrorReason::RateLimited { .. }));

    // The phase's own sentence: with every other connection held by
    // unidentified callers, an identified caller still completes a handshake
    // and a snapshot.
    let (mut alice, _alice) = connect(&manager, "alice", &["user:alice"]).await;
    send_subscribe(&mut alice, "alice-fast", "SELECT * FROM fast_rows").await;
    let served = settle(&mut alice).await;
    assert!(
        matches!(served, ControlMessage::SnapshotEnd(_)),
        "the identified snapshot completes on the reserve, got {served:?}"
    );
    assert_eq!(
        slow_reads_in_flight(&fixture).await,
        2,
        "the identified caller completed while the share was still fully occupied"
    );

    // The occupants themselves were served, not harmed: the reserve refused
    // only what exceeded the share.
    let served_a = settle(&mut anon_a).await;
    assert!(matches!(served_a, ControlMessage::SnapshotEnd(_)));
    let served_b = settle(&mut anon_b).await;
    assert!(matches!(served_b, ControlMessage::SnapshotEnd(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn anonymous_callers_reach_the_full_unreserved_share() {
    let fixture = Fixture::acquire().await;
    let reader = setup(&fixture, 4.0).await;
    let manager = manager(&reader);

    let (mut anon_a, _a) = connect(&manager, "anon-a", &[]).await;
    let (mut anon_b, _b) = connect(&manager, "anon-b", &[]).await;
    send_subscribe(&mut anon_a, "anon-a-slow", "SELECT * FROM slow_rows").await;
    send_subscribe(&mut anon_b, "anon-b-slow", "SELECT * FROM slow_rows").await;

    // Both reads in flight at once: the share is the total less the reserve,
    // not something smaller, so strictness costs exactly the reserve.
    wait_for_slow_reads(&fixture, 2).await;

    let served_a = settle(&mut anon_a).await;
    assert!(
        matches!(served_a, ControlMessage::SnapshotEnd(_)),
        "the first anonymous snapshot is served, got {served_a:?}"
    );
    let served_b = settle(&mut anon_b).await;
    assert!(
        matches!(served_b, ControlMessage::SnapshotEnd(_)),
        "the second anonymous snapshot is served, got {served_b:?}"
    );
}
