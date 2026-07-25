//! Aggregate delivery, the parts the relay depends on.
//!
//! Phase 1 of the relay-parity plan makes aggregate subscriptions transparent
//! through the browser relay hub. The hub forwards the worker client's
//! `ClientEvent::Aggregate` back down to the owning tab as an
//! `AggregateUpdate`, so the event MUST carry every field the wire message
//! does, not just the JSON payload. The direct server only ever emits a
//! single-group full result (`group_key: None`, `is_full_result: true`), so
//! faithful forwarding of a grouped delta (`group_key: Some`,
//! `is_full_result: false`) can only be proven with a hand-crafted frame. This
//! test drives the client's decode with exactly that frame over a loopback.

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::messages::{AggregateUpdate, ControlMessage, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, SchemaVersion};
use connetto_server::{LoopbackTransport, loopback};

const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER);";

/// Complete the wire handshake as a fake server, then push one aggregate
/// update carrying a group key and a delta (not-full) flag.
fn aggregate_pusher(update: AggregateUpdate) -> LoopbackTransport {
    let (mut fake_server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) =
            fake_server.recv().await
        else {
            return;
        };
        let _ = fake_server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                session_id: "agg".to_owned(),
                session_token: "agg".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: SchemaVersion::default(),
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await;
        let _ = fake_server
            .send_control(ControlMessage::AggregateUpdate(update))
            .await;
        while let Ok(Some(_)) = fake_server.recv().await {}
    });
    client_end
}

fn config(client_id: &str) -> ClientConfig {
    ClientConfig {
        client_id: client_id.to_owned(),
        auth_token: "token".to_owned(),
        schema_version: connetto_core::SchemaVersion::default(),
    }
}

// The decoded event mirrors the wire AggregateUpdate field for field, so a
// relay can rebuild a faithful frame, including a grouped delta the direct
// server never emits today.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_update_decodes_group_key_and_delta_flag() {
    let transport = aggregate_pusher(AggregateUpdate {
        sub_id: "by-region".to_owned(),
        group_key: Some(b"region=eu".to_vec()),
        result_json: "{\"count\":3}".to_owned(),
        is_full_result: false,
    });
    let mut conn =
        ConnettoConnection::connect(transport, ":memory:", SQLITE_DDL, &config("t"), None)
            .await
            .expect("connect");

    let event = conn.pump_one().await.expect("pump");
    assert_eq!(
        event,
        ClientEvent::Aggregate {
            sub_id: "by-region".to_owned(),
            result_json: "{\"count\":3}".to_owned(),
            group_key: Some(b"region=eu".to_vec()),
            is_full_result: false,
        },
    );
}
