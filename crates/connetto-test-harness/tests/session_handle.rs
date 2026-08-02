//! R2 acceptance: the session layer's own durable identity.
//!
//! One handle covers one unbroken run of one caller. It is the key the
//! exactly-once watermark records against, the key the connection registry
//! addresses for revocation and supersession, and it survives a reconnect
//! where the per-connection counter never could.
//!
//! `#[ignore]` by default: it needs a Postgres started with
//! `wal_level=logical`. Run under Docker with `DATABASE_URL` pointed at it and
//! `-- --ignored`.

use std::str::FromStr as _;
use std::time::Duration;

use connetto_core::SessionId;
use connetto_core::messages::{ControlMessage, FatalErrorReason};
use connetto_server::watermark_schema::check_watermark_shape;
use connetto_server::{PgSnapshotSource, RuntimeWritableCatalog, SessionConfig};
use connetto_test_harness::{
    ConnettoWatermark, Fixture, HarnessAuth, Server, ServerConfig, insert_changeset, pool_for,
    provision_watermark, spawn_server,
};
use sqlite_diff_rs::Value;

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";

/// Provision the fixture and serve it. Writes go through the admin pool: this
/// suite's subject is the session handle, not Row-Level Security, which
/// `smoke.rs` covers.
async fn serve(fixture: &Fixture) -> Server {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP PUBLICATION IF EXISTS connetto_pub",
            "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT)",
            "ALTER TABLE notes REPLICA IDENTITY FULL",
        ])
        .await;
    provision_watermark(fixture.admin()).await;
    fixture.start_replication(&["notes"]).await;
    let snapshot =
        PgSnapshotSource::from_ddl(fixture.admin().clone(), PG_DDL).expect("snapshot source");
    spawn_server(
        ServerConfig {
            pg_ddl: PG_DDL.to_owned(),
            writable: RuntimeWritableCatalog::builder()
                .versioned("notes", "edited_at")
                .build(),
            admin_url: fixture.admin_url().to_owned(),
            session: SessionConfig::default(),
        },
        snapshot,
        HarnessAuth::permissive(),
        fixture.admin().clone(),
        fixture.admin().clone(),
    )
}

/// One insert of `id`, as a client uploads it.
fn note(id: i64, body: &str) -> Vec<u8> {
    insert_changeset(
        "notes",
        &["id", "body", "edited_at"],
        &[0],
        vec![
            Value::Integer(id),
            Value::Text(body.to_owned()),
            Value::Text("t1".to_owned()),
        ],
    )
}

/// Revoking a session closes its live connection rather than only refusing its
/// next handshake, and it does so for a connection holding no subscription at
/// all. That is the case the per-subscription route map cannot serve, so it is
/// the one that proves the connection registry exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn revocation_closes_an_idle_connection() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut client = server.connect();
    let ack = client.handshake_with("conn-label", "alice").await;
    let handle = SessionId::from_str(&ack.session_token).expect("the ack carries the handle");

    assert!(
        server
            .manager()
            .close_session(handle, FatalErrorReason::SessionRevoked)
            .await,
        "the registry holds a connection with no subscription"
    );
    match client.next_control().await {
        ControlMessage::FatalError(fatal) => {
            assert_eq!(fatal.reason, FatalErrorReason::SessionRevoked);
        }
        other => panic!("expected a revocation close, got {other:?}"),
    }
    drop(server);
}

/// The same, with the connection subscribed, which the route map could have
/// served. Both directions are proven so a future change cannot quietly move
/// revocation back onto the routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn revocation_closes_a_subscribed_connection() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut client = server.connect();
    let ack = client.handshake_with("conn-label", "alice").await;
    let handle = SessionId::from_str(&ack.session_token).expect("the ack carries the handle");
    client.subscribe("notes", "SELECT * FROM notes").await;
    let _ = client.expect_snapshot("notes").await;

    assert!(
        server
            .manager()
            .close_session(handle, FatalErrorReason::SessionRevoked)
            .await
    );
    match client.next_control().await {
        ControlMessage::FatalError(fatal) => {
            assert_eq!(fatal.reason, FatalErrorReason::SessionRevoked);
        }
        other => panic!("expected a revocation close, got {other:?}"),
    }
    drop(server);
}

/// One live connection per handle, newer wins. Two connections must not share
/// a handle, because the handle keys the per-subscription cursors and the
/// pending buffer, and two readers would each consume the other's changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn a_second_connection_on_one_handle_supersedes_the_first() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut first = server.connect();
    let first_ack = first.handshake_with("first", "alice").await;

    // A second connection presenting the same credential resolves to the same
    // durable handle, so it takes the session over.
    let mut second = server.connect();
    let second_ack = second.handshake_with("second", "alice").await;
    assert_eq!(
        first_ack.session_token, second_ack.session_token,
        "one caller, one handle, regardless of how many sockets it opens"
    );
    assert_ne!(
        first_ack.connection_id, second_ack.connection_id,
        "the per-socket label still differs"
    );

    match first.next_control().await {
        ControlMessage::FatalError(fatal) => {
            assert_eq!(fatal.reason, FatalErrorReason::ConnectionSuperseded);
        }
        other => panic!("the older connection must be superseded, got {other:?}"),
    }

    // The survivor is fully live: it subscribes and receives its snapshot.
    second.subscribe("notes", "SELECT * FROM notes").await;
    let _ = second.expect_snapshot("notes").await;
    second.close().await;
    drop(server);
}

/// A handle covers one unbroken run of ONE caller. A different caller gets a
/// different handle and inherits nothing, which is what stops the next person
/// on a shared device from resuming the previous one's session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn a_handle_does_not_survive_a_change_of_caller() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut alice = server.connect();
    let alice_ack = alice.handshake_with("shared-device", "alice").await;
    alice.subscribe("notes", "SELECT * FROM notes").await;
    let _ = alice.expect_snapshot("notes").await;
    alice.close().await;

    // The same device, the same client label, a different caller.
    let mut bob = server.connect();
    let bob_ack = bob.handshake_with("shared-device", "bob").await;
    assert_ne!(
        alice_ack.session_token, bob_ack.session_token,
        "a change of caller starts a new run"
    );
    assert_eq!(
        bob_ack.last_applied_seq, None,
        "bob inherits no watermark from alice"
    );

    // Superseding alice's handle would have closed bob, so prove bob is live.
    bob.subscribe("notes", "SELECT * FROM notes").await;
    let _ = bob.expect_snapshot("notes").await;
    bob.close().await;
    drop(server);
}

/// The exactly-once watermark keys on the handle, so a reconnect that resolves
/// to the same session sees its own applied sequence and replays nothing,
/// while a different caller starts clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn the_watermark_resumes_on_the_handle_across_a_reconnect() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut first = server.connect();
    let first_ack = first.handshake_with("socket-one", "alice").await;
    assert_eq!(
        first_ack.last_applied_seq, None,
        "a fresh session has applied nothing"
    );
    first.upload(1, note(1, "mine")).await;
    match first.next_control().await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("the upload should apply, got {other:?}"),
    }
    first.close().await;

    // A fresh socket, a new per-connection label, the same caller. The handle
    // is the same, so the server reports the sequence it already applied and
    // the client retires that pending record instead of replaying it.
    let mut second = server.connect();
    let second_ack = second.handshake_with("socket-two", "alice").await;
    assert_eq!(
        second_ack.session_token, first_ack.session_token,
        "the handle survives the reconnect"
    );
    assert_eq!(
        second_ack.last_applied_seq,
        Some(1),
        "the watermark resumes on the handle, so seq 1 is never re-applied"
    );
    second.close().await;

    // A different caller shares none of it.
    let mut other = server.connect();
    let other_ack = other.handshake_with("socket-three", "carol").await;
    assert_eq!(
        other_ack.last_applied_seq, None,
        "another caller's watermark is its own"
    );
    other.close().await;
    drop(server);
}

/// connetto emits no server DDL, so the watermark trait is the only contract,
/// and an unchecked contract lets a server run while mis-keying its
/// exactly-once records, silently, until a replay happens. Starting against
/// the pre-R2 table refuses and names what is wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker)"]
async fn startup_refuses_a_pre_r2_watermark_table() {
    let fixture = Fixture::acquire().await;
    let pool = pool_for(fixture.admin_url()).await;

    // The shape this build keys on passes.
    {
        let mut conn = pool.get().await.expect("admin connection");
        check_watermark_shape::<ConnettoWatermark>(&mut conn)
            .await
            .expect("the current shape is accepted");
    }

    // The pre-R2 shape, keyed on (user_id, session_id), is refused by name.
    fixture
        .exec("DROP TABLE IF EXISTS _connetto_mutations")
        .await;
    fixture
        .exec(
            "CREATE TABLE _connetto_mutations (user_id TEXT NOT NULL, \
             session_id UUID NOT NULL, last_seq BIGINT NOT NULL, \
             PRIMARY KEY (user_id, session_id))",
        )
        .await;
    let mut conn = pool.get().await.expect("admin connection");
    let err = check_watermark_shape::<ConnettoWatermark>(&mut conn)
        .await
        .expect_err("the pre-R2 shape must refuse startup");
    let message = err.to_string();
    assert!(
        message.contains("user_id"),
        "the refusal names the leftover column, got: {message}"
    );

    // A missing table refuses too, and says who owns it.
    fixture
        .exec("DROP TABLE IF EXISTS _connetto_mutations")
        .await;
    let err = check_watermark_shape::<ConnettoWatermark>(&mut conn)
        .await
        .expect_err("a missing watermark table must refuse startup");
    let message = err.to_string();
    assert!(
        message.contains("does not exist"),
        "the refusal names the missing table, got: {message}"
    );
    provision_watermark(fixture.admin()).await;
}

/// The handle the ack carries is the one the client presents on reconnect, so
/// a resumed connection is recognisably the same run rather than a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn the_ack_carries_a_parseable_durable_handle() {
    let fixture = Fixture::acquire().await;
    let server = serve(&fixture).await;

    let mut client = server.connect();
    let ack = client.handshake_with("labelled", "alice").await;
    assert!(
        SessionId::from_str(&ack.session_token).is_ok(),
        "the handle is a durable session id, not a per-connection label: {}",
        ack.session_token
    );
    assert_ne!(
        ack.session_token, ack.connection_id,
        "the handle and the socket label are different values"
    );
    // A pointless timeout guard so a hang fails loudly rather than blocking.
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close");
    drop(server);
}
