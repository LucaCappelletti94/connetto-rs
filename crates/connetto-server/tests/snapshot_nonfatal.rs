//! A snapshot failure must not kill the session: it surfaces as a
//! `NonFatalError` scoped to the one subscription, the registration is
//! rolled back, and the session keeps serving (the pong after the failure
//! proves the run loop is alive).

use std::sync::Arc;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{ControlMessage, Handshake, Ping, Subscribe, SubscriptionSpec};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    Materializer, PermissiveAuth, SessionConfig, SessionManager, Snapshot, SnapshotSource,
    loopback, sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// A snapshot source that always fails, standing in for an unreachable or
/// misbehaving backing store.
struct BrokenSnapshot;

impl SnapshotSource for BrokenSnapshot {
    type Error = String;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Err("backing store unreachable".to_owned())
    }
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_failure_is_nonfatal_and_the_session_survives() {
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        BrokenSnapshot,
        PermissiveAuth,
        sqlite_write_target(client_replica()),
        SessionConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = Arc::clone(&manager);
    let serve = tokio::spawn(async move { server.serve(server_end).await });

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "nonfatal-client",
            "token",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "broken".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");

    // The snapshot begins, fails inside the source, and the failure comes
    // back scoped to the subscription instead of ending the session.
    let mut saw_nonfatal = false;
    for _ in 0..4 {
        match next_control(&mut client).await {
            ControlMessage::NonFatalError(err) => {
                assert_eq!(err.related_to.as_deref(), Some("broken"));
                assert!(
                    err.detail.contains("snapshot failed"),
                    "detail names the snapshot: {}",
                    err.detail
                );
                saw_nonfatal = true;
                break;
            }
            ControlMessage::SnapshotBegin(_) => {}
            other => panic!("unexpected frame before the non-fatal error: {other:?}"),
        }
    }
    assert!(saw_nonfatal, "the snapshot failure surfaces as non-fatal");

    // The run loop is alive: control frames still round-trip in order.
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut client).await else {
        panic!("expected pong after the non-fatal error");
    };
    assert_eq!(pong.nonce, 7);

    // A clean close ends the session without an error.
    client.close().await.expect("close");
    serve
        .await
        .expect("serve task")
        .expect("session ends cleanly after a non-fatal snapshot failure");
}
