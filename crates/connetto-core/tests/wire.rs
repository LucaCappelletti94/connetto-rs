//! Round-trip integration tests for every wire variant.
//!
//! Each variant is encoded with `rmp-serde` (via the crate's [`codec`] helpers)
//! and decoded back through both the raw payload path and the length-prefixed
//! framed path. Any change to a serde annotation or a field type that would
//! silently break the wire will fail one of these tests.

use connetto_core::{
    Cursor, SchemaVersion,
    codec::{
        DEFAULT_MAX_FRAME_LEN, decode_bulk, decode_bulk_framed, decode_control,
        decode_control_framed, encode_bulk, encode_bulk_framed, encode_control,
        encode_control_framed,
    },
    messages::{
        AckCredits, AggregateUpdate, BulkMessage, ControlMessage, FatalError, FatalErrorReason,
        FullResyncReason, FullResyncRequired, Handshake, HandshakeAck, LivePatch, MutationConflict,
        MutationHeader, MutationPatch, MutationReject, MutationRejectReason, NonFatalError, Ping,
        Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionPriority,
        SubscriptionSpec, Unsubscribe,
    },
    version::PROTOCOL_VERSION,
};

fn round_trip_control(message: &ControlMessage) {
    let payload = encode_control(message).expect("encode_control");
    let decoded = decode_control(&payload).expect("decode_control");
    assert_eq!(
        *message, decoded,
        "raw MessagePack payload round-trip mismatch"
    );

    let framed = encode_control_framed(message).expect("encode_control_framed");
    let (framed_back, consumed) = decode_control_framed(&framed).expect("decode_control_framed");
    assert_eq!(
        consumed,
        framed.len(),
        "framed decoder must consume everything"
    );
    assert_eq!(*message, framed_back, "framed round-trip mismatch");
    assert!(consumed <= DEFAULT_MAX_FRAME_LEN);
}

fn round_trip_bulk(message: &BulkMessage) {
    let payload = encode_bulk(message).expect("encode_bulk");
    let decoded = decode_bulk(&payload).expect("decode_bulk");
    assert_eq!(*message, decoded, "raw bulk payload round-trip mismatch");

    let framed = encode_bulk_framed(message).expect("encode_bulk_framed");
    let (framed_back, consumed) = decode_bulk_framed(&framed).expect("decode_bulk_framed");
    assert_eq!(
        consumed,
        framed.len(),
        "framed bulk decoder must consume everything"
    );
    assert_eq!(*message, framed_back, "framed bulk round-trip mismatch");
}

#[test]
fn handshake_and_ack_round_trip() {
    round_trip_control(&ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "client-a", "auth-token")
            .with_session_token("prior-session")
            .with_cursor(Cursor::new(vec![0xde, 0xad, 0xbe, 0xef])),
    ));
    round_trip_control(&ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "connection-1".into(),
        session_token: "opaque".into(),
        current_cursor: Cursor::new(vec![1, 2, 3, 4]),
        schema_version: Some(SchemaVersion::from_hash(vec![0xab, 0xcd])),
        initial_credits: 128,
        last_applied_seq: Some(41),
    }));
}

#[test]
fn subscription_lifecycle_round_trips() {
    round_trip_control(&ControlMessage::Subscribe(Subscribe {
        sub_id: "sub-orders".into(),
        spec: SubscriptionSpec::new("SELECT * FROM orders WHERE user_id = 1")
            .with_priority(SubscriptionPriority::HIGHEST),
    }));
    round_trip_control(&ControlMessage::Subscribe(Subscribe {
        sub_id: "sub-count".into(),
        spec: SubscriptionSpec::new("SELECT region, COUNT(*) FROM orders GROUP BY region")
            .with_priority(SubscriptionPriority::new(2)),
    }));
    round_trip_control(&ControlMessage::Unsubscribe(Unsubscribe {
        sub_id: "sub-orders".into(),
    }));
    round_trip_control(&ControlMessage::SnapshotBegin(SnapshotBegin {
        sub_id: "sub-orders".into(),
        priority: SubscriptionPriority::HIGHEST,
    }));
    round_trip_control(&ControlMessage::SnapshotEnd(SnapshotEnd {
        sub_id: "sub-orders".into(),
        cursor: Cursor::new(vec![9, 8, 7]),
    }));
}

#[test]
fn mutation_control_frames_round_trip() {
    round_trip_control(&ControlMessage::MutationHeader(MutationHeader::new(17, 4)));
    round_trip_control(&ControlMessage::MutationReject(MutationReject {
        client_seq: 17,
        reason: MutationRejectReason::Constraint {
            detail: "unique_violation on orders.uid".into(),
        },
    }));
    round_trip_control(&ControlMessage::MutationConflict(MutationConflict {
        client_seq: 17,
        table: "orders".into(),
        server_updated_at: "2026-07-09T10:44:00Z".into(),
        server_row_json: r#"{"id":1,"amount":42}"#.into(),
    }));
}

#[test]
fn aggregate_update_round_trip() {
    round_trip_control(&ControlMessage::AggregateUpdate(AggregateUpdate {
        sub_id: "sub-count".into(),
        group_key: Some(b"region=eu".to_vec()),
        result_json: r#"{"count":42}"#.into(),
        is_full_result: false,
    }));
    round_trip_control(&ControlMessage::AggregateUpdate(AggregateUpdate {
        sub_id: "sub-total".into(),
        group_key: None,
        result_json: r#"{"total":9001}"#.into(),
        is_full_result: true,
    }));
}

#[test]
fn resync_control_round_trips() {
    for reason in [
        FullResyncReason::CursorOutsideRetention,
        FullResyncReason::SessionExpired,
        FullResyncReason::SchemaIncompatible,
        FullResyncReason::Other {
            detail: "corrupt".into(),
        },
    ] {
        round_trip_control(&ControlMessage::FullResyncRequired(FullResyncRequired {
            sub_id: "sub-orders".into(),
            reason,
        }));
    }
}

#[test]
fn flow_control_round_trip() {
    round_trip_control(&ControlMessage::Ping(Ping { nonce: 1 }));
    round_trip_control(&ControlMessage::Pong(Pong { nonce: 1 }));
    round_trip_control(&ControlMessage::AckCredits(AckCredits { credits: 32 }));
}

#[test]
fn error_control_round_trips() {
    round_trip_control(&ControlMessage::NonFatalError(NonFatalError {
        related_to: Some("sub-orders".into()),
        detail: "malformed WHERE".into(),
    }));
    for reason in [
        FatalErrorReason::ProtocolVersionMismatch {
            expected: PROTOCOL_VERSION,
            got: 999,
        },
        FatalErrorReason::AuthenticationFailed,
        FatalErrorReason::SessionRevoked,
        FatalErrorReason::ProtocolViolation {
            detail: "unexpected control after fatal".into(),
        },
        FatalErrorReason::ServerShuttingDown,
        FatalErrorReason::Other {
            detail: "boom".into(),
        },
    ] {
        round_trip_control(&ControlMessage::FatalError(FatalError::new(reason)));
    }
}

#[test]
fn bulk_frames_round_trip() {
    round_trip_bulk(&BulkMessage::SnapshotPatch(SnapshotPatch::new(
        "sub-orders",
        vec![0xff; 128],
    )));
    round_trip_bulk(&BulkMessage::LivePatch(LivePatch::new(
        "sub-orders",
        Cursor::new(vec![0xa1, 0xa2, 0xa3]),
        vec![0x11, 0x22, 0x33],
    )));
    round_trip_bulk(&BulkMessage::MutationPatch(MutationPatch::new(
        99,
        vec![0x77, 0x88],
    )));
}
