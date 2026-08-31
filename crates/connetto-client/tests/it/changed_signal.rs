//! R45 step 2: connetto's own bookkeeping stays out of the changed-tables
//! signal the application reads and the live-query refresh consults.
//!
//! The update hook that feeds the signal records every table a write touches on
//! the replica connection, connetto's own included. So persisting a resume
//! cursor put `_connetto_meta` in the set, and queueing a mutation put
//! `_connetto_pending` there, on every applied frame. The application was told
//! internals had changed, and the refresh pass walked the whole live-query
//! registry to match nothing.
//!
//! An empty set is what proves no refresh happened: `refresh_changed` returns
//! before touching the registry when the drain comes back empty.

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_core::Cursor;
use connetto_core::messages::{
    ControlMessage, HandshakeAck, SnapshotBegin, SnapshotEnd, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;

const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT);";

diesel::table! {
    /// Synced test table.
    orders (id) {
        /// Order identifier, the primary key.
        id -> Integer,
        /// Free-text status.
        status -> Nullable<Text>,
    }
}

fn client_config() -> ClientConfig {
    ClientConfig::new("r45-changed-signal")
        .with_login(Some(connetto_client::Grant::new("user:changed")))
}

/// A server that answers the handshake and then advances the resume cursor
/// twice, carrying no rows either time. A `SnapshotEnd` with a non-empty
/// cursor is the smallest frame that persists one, so nothing an application
/// owns changes while it is applied.
fn cursor_only_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "changed".to_owned(),
                session_token: "changed".to_owned(),
                resume_token: "changed".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack");
        for tick in 1..=2u8 {
            server
                .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                    sub_id: "sub".to_owned(),
                    priority: SubscriptionPriority::default(),
                }))
                .await
                .expect("begin");
            server
                .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                    sub_id: "sub".to_owned(),
                    cursor: Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, tick]),
                }))
                .await
                .expect("end");
        }
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
}

/// Drive steps until the next `SnapshotEnd`, returning every table reported
/// changed along the way. Accumulated rather than read off the last step: a
/// step reports what changed while it ran, and which step that is depends on
/// how the server's frames happened to batch.
async fn step_to_snapshot_end(conn: &mut ConnettoConnection<LoopbackTransport>) -> Vec<String> {
    let mut changed: Vec<String> = Vec::new();
    loop {
        let step = conn.next_event().await.expect("step");
        changed.extend(step.changed_tables);
        match step.event {
            ClientEvent::SnapshotEnd { .. } => {
                changed.sort();
                changed.dedup();
                return changed;
            }
            ClientEvent::Closed => panic!("closed before the cursor arrived"),
            _ => {}
        }
    }
}

/// Persisting a resume cursor reports nothing changed, and a write the
/// application made still reports its own table.
///
/// Both halves in one test on purpose: reporting nothing at all would pass the
/// first assertion while making the signal useless, which is the failure mode a
/// filter invites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_persist_reports_no_changed_table_and_a_write_still_does() {
    let mut conn = ConnettoConnection::connect(
        cursor_only_server(),
        &Replica::in_memory(),
        SQLITE_DDL,
        &client_config(),
        None,
    )
    .await
    .expect("connect");

    assert!(
        step_to_snapshot_end(&mut conn).await.is_empty(),
        "advancing the resume cursor changed nothing the application owns",
    );

    // A local write, which also queues a pending mutation, so the step that
    // reports it writes `_connetto_pending` too.
    diesel::insert_into(orders::table)
        .values((orders::id.eq(1), orders::status.eq("paid")))
        .execute(conn.conn())
        .expect("write");
    assert_eq!(
        step_to_snapshot_end(&mut conn).await,
        vec!["orders".to_owned()],
        "the application's own write is still reported, and only it",
    );
}
