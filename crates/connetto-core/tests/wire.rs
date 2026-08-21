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
        AckCredits, AggregateUpdate, BulkMessage, ConflictRow, ControlMessage, FatalError,
        FatalErrorReason, FullResyncReason, FullResyncRequired, Grant, Handshake, HandshakeAck,
        LivePatch, MutationConflict, MutationHeader, MutationPatch, MutationReject,
        MutationRejectReason, NonFatalError, PauseCause, Ping, Pong, RateLimited, SnapshotBegin,
        SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionPriority, SubscriptionSpec, Unsubscribe,
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
        Handshake::new(PROTOCOL_VERSION, "client-a")
            .with_grants([Grant::new("login-token"), Grant::new("share-key")])
            .with_resume_token("prior-run")
            .with_cursor(Cursor::new(vec![0xde, 0xad, 0xbe, 0xef])),
    ));
    round_trip_control(&ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        "client-a",
    )));
    round_trip_control(&ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "connection-1".into(),
        session_token: "opaque-handle".into(),
        resume_token: "opaque-credential".into(),
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
        server_row: Some(ConflictRow {
            updated_at: "2026-07-09T10:44:00Z".into(),
            row_json: r#"{"id":1,"amount":42}"#.into(),
        }),
    }));
    // The row is gone, which is the case an empty string used to stand in for.
    round_trip_control(&ControlMessage::MutationConflict(MutationConflict {
        client_seq: 18,
        table: "orders".into(),
        server_row: None,
    }));
    round_trip_control(&ControlMessage::MutationReject(MutationReject {
        client_seq: 18,
        reason: MutationRejectReason::Indeterminate,
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

/// Every [`FullResyncReason`], each one a replacement the server actually
/// asks for. The wildcard-free match is the guard: adding a variant stops this
/// file compiling until it is listed here, and listing it is the moment to
/// notice that nothing sends it.
fn every_resync_reason() -> Vec<FullResyncReason> {
    let reasons = vec![
        // SessionManager::subscribe_row, when the resume cursor has fallen out
        // of the retained window.
        FullResyncReason::CursorOutsideRetention,
        // SessionManager::keep_store_current, when a grant reaching the
        // subscription's table moved (R7).
        FullResyncReason::AuthorizationChange,
        // SessionManager::fan_out_rows and catch_up_row, when a table the
        // subscription reads was emptied and the patchset folded for it carries
        // no operations (R48).
        FullResyncReason::TableTruncated {
            table: "orders".to_owned(),
        },
        // SessionManager::restart_or_refuse, when a page of an initial read
        // failed part way through and the read starts again (R58).
        FullResyncReason::SnapshotInterrupted,
    ];
    for reason in &reasons {
        match reason {
            FullResyncReason::CursorOutsideRetention
            | FullResyncReason::AuthorizationChange
            | FullResyncReason::SnapshotInterrupted
            | FullResyncReason::TableTruncated { .. } => {}
        }
    }
    reasons
}

#[test]
fn resync_control_round_trips() {
    for reason in every_resync_reason() {
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

/// Every `FatalErrorReason`, each one a close the server actually performs.
///
/// The wildcard-free match is the guard: adding a variant to the enum stops
/// this file compiling until it is listed here, and listing it is the moment
/// to notice that nothing sends it. The comment beside each names where the
/// server constructs it, so an unsendable variant cannot be added quietly.
fn every_fatal_reason() -> Vec<FatalErrorReason> {
    let reasons = vec![
        // SessionManager::run_handshake, on a version the server cannot speak.
        FatalErrorReason::ProtocolVersionMismatch {
            expected: PROTOCOL_VERSION,
            got: 999,
        },
        // SessionManager::close_session, from the auth service's revoke hook.
        FatalErrorReason::SessionRevoked,
        // SessionManager::register_connection, on a second live handshake.
        FatalErrorReason::ConnectionSuperseded,
        // SessionManager::serve, on a duplicate handshake mid-session.
        FatalErrorReason::ProtocolViolation {
            detail: "duplicate handshake".into(),
        },
        // SessionManager::shutdown, walking the connection registry.
        FatalErrorReason::ServerShuttingDown,
        // SessionManager::run_handshake, on a caller over its connection or
        // credential-refusal limit (R19).
        FatalErrorReason::RateLimited {
            retry_after_ms: 30_000,
        },
        // SessionManager::reconcile_stream, when the change feed resumed past
        // what it had delivered (R32).
        FatalErrorReason::ChangeStreamGap,
    ];
    for reason in &reasons {
        match reason {
            FatalErrorReason::ProtocolVersionMismatch { .. }
            | FatalErrorReason::SessionRevoked
            | FatalErrorReason::ConnectionSuperseded
            | FatalErrorReason::ProtocolViolation { .. }
            | FatalErrorReason::ServerShuttingDown
            | FatalErrorReason::RateLimited { .. }
            | FatalErrorReason::ChangeStreamGap => {}
        }
    }
    reasons
}

#[test]
fn error_control_round_trips() {
    round_trip_control(&ControlMessage::NonFatalError(NonFatalError {
        related_to: Some("sub-orders".into()),
        detail: "malformed WHERE".into(),
    }));
    round_trip_control(&ControlMessage::RateLimited(RateLimited {
        related_to: Some("sub-orders".into()),
        retry_after_ms: 1_500,
    }));
    round_trip_control(&ControlMessage::RateLimited(RateLimited {
        related_to: None,
        retry_after_ms: 0,
    }));
    for reason in every_fatal_reason() {
        round_trip_control(&ControlMessage::FatalError(FatalError::new(reason)));
    }
}

/// Every [`PauseCause`] value. The wildcard-free match below ensures a new
/// variant stops this file compiling until it is listed here, and listing it
/// is the moment to add its round-trip assertion.
fn every_pause_cause() -> Vec<PauseCause> {
    let causes = vec![
        // R5b: authorization service unreachable during the change path.
        PauseCause::AuthServiceUnreachable,
        // R5b: change feed connected but silent (absence of events).
        PauseCause::ChangeStreamStalled,
    ];
    for cause in &causes {
        match cause {
            PauseCause::AuthServiceUnreachable | PauseCause::ChangeStreamStalled => {}
        }
    }
    causes
}

#[test]
fn delivery_pause_round_trips() {
    for cause in every_pause_cause() {
        round_trip_control(&ControlMessage::DeliveryPaused { cause });
    }
    round_trip_control(&ControlMessage::DeliveryResumed);
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
