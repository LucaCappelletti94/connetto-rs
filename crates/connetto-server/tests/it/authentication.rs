//! Phase 1 authentication acceptance tests.
//!
//! The handshake resolves identity through the [`HandshakeAuthority`] seam over
//! presented grants, never from the client-supplied `client_id`. These tests
//! prove the spoofing hole is closed: a refused grant does not close the
//! connection but yields an unidentified run whose snapshot sees no identity,
//! while a verified grant yields exactly the [`AuthContext`] the authority
//! resolved even when the client claims a different id. The stand-in
//! [`TestGrantChecker`] is used where no live identity provider is needed.

use std::sync::{Arc, Mutex};

use connetto_core::auth::AuthContext;
use connetto_core::messages::{ControlMessage, Grant, Handshake, Subscribe, SubscriptionSpec};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{
    GrantCheckFuture, GrantRefused, HandleError, HandshakeAuthority, IncomingFrame, Transport,
};
use connetto_core::{Cursor, PROTOCOL_VERSION, Principal, SessionId, Subject, VerifiedSession};
use connetto_server::{
    Materializer, PageSpec, RequestGuard, SessionConfig, SessionManager, SnapshotEstimate,
    SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// Records the identity the session presents to the snapshot read, so a test
/// can inspect the [`AuthContext`] the authority resolved. Returns no rows.
#[derive(Clone, Default)]
struct CapturingSnapshot {
    seen: Arc<Mutex<Option<AuthContext>>>,
}

impl SnapshotSource for CapturingSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        *self.seen.lock().expect("capture lock") = caller.identity().cloned();
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

/// An authority that resolves every grant to one fixed identity, standing in
/// for a real authority that derives identity from a trusted credential rather
/// than the client-supplied id.
struct FixedVerifier(AuthContext);

impl HandshakeAuthority for FixedVerifier {
    fn check_grant<'a>(&'a self, _grant: &'a Grant) -> GrantCheckFuture<'a> {
        let context = self.0.clone();
        Box::pin(async move {
            Ok(Subject::Identity(VerifiedSession {
                context,
                // A fixed id so every connection this stub verifies shares one
                // watermark key, which is what the exactly-once assertions rely on.
                session_id: SessionId::from_token_hash("fixed-session"),
            }))
        })
    }

    fn mint_handle(&self, session_id: SessionId) -> Result<String, HandleError> {
        Ok(format!("run:{session_id}"))
    }

    fn read_handle(&self, blob: &str) -> Result<SessionId, HandleError> {
        blob.strip_prefix("run:")
            .and_then(|handle| handle.parse().ok())
            .ok_or_else(|| HandleError(format!("not a test handle: {blob:?}")))
    }
}

/// An authority that refuses every grant, standing in for a real authority
/// rejecting a forged credential.
struct AlwaysReject;

impl HandshakeAuthority for AlwaysReject {
    fn check_grant<'a>(&'a self, _grant: &'a Grant) -> GrantCheckFuture<'a> {
        Box::pin(async move { Err(GrantRefused::Invalid("forged token".to_owned())) })
    }

    fn mint_handle(&self, session_id: SessionId) -> Result<String, HandleError> {
        Ok(format!("run:{session_id}"))
    }

    fn read_handle(&self, blob: &str) -> Result<SessionId, HandleError> {
        blob.strip_prefix("run:")
            .and_then(|handle| handle.parse().ok())
            .ok_or_else(|| HandleError(format!("not a test handle: {blob:?}")))
    }
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

/// A handshake with no grants succeeds; the run is unidentified because there
/// is nothing to check. R3 removed `AuthenticationFailed`: a missing credential
/// never closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_grant_yields_an_unidentified_run() {
    let fixture = Fixture::acquire().await;
    let capture = CapturingSnapshot::default();
    let seen = Arc::clone(&capture.seen);
    // Rows come from a snapshot stub, not the change path. The policy is never consulted.
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        capture,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    // No grants presented: handshake still succeeds.
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "any-client",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // A subscribe drives the snapshot read which captures the caller's identity.
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let Some(IncomingFrame::Bulk(_)) = client.recv().await.expect("recv") else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };

    let captured = seen.lock().expect("capture lock").clone();
    assert!(
        captured.is_none(),
        "a run with no grants is unidentified, got {captured:?}",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// A refused grant does not close the connection. The run continues
/// unidentified and the snapshot sees no identity. R3 removed
/// `AuthenticationFailed`: refusals are not fatal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_grant_yields_an_unidentified_run() {
    let fixture = Fixture::acquire().await;
    let capture = CapturingSnapshot::default();
    let seen = Arc::clone(&capture.seen);
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        capture,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(AlwaysReject),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    // AlwaysReject refuses the grant; the connection stays open.
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "any-client").with_grant(Grant::new("user:forger")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // The refused grant leaves the run unidentified.
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let Some(IncomingFrame::Bulk(_)) = client.recv().await.expect("recv") else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };

    let captured = seen.lock().expect("capture lock").clone();
    assert!(
        captured.is_none(),
        "a refused grant leaves the run unidentified, got {captured:?}",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// A verified grant resolves to the authority's identity regardless of what
/// the client claims as its id. The spoofing hole is closed: identity comes
/// from the checked grant, not from the client-supplied `client_id`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_identity_ignores_a_spoofed_client_id() {
    let fixture = Fixture::acquire().await;
    // The authority resolves the identity, and the client claims a different id.
    let resolved = AuthContext::new("resolved-user");
    let capture = CapturingSnapshot::default();
    let seen = Arc::clone(&capture.seen);
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        capture,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(FixedVerifier(resolved.clone())),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    // The client claims to be "spoofer", but identity comes from the authority.
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "spoofer").with_grant(Grant::new("user:spoofer")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // Subscribing drives the snapshot read, which records the resolved identity.
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let Some(IncomingFrame::Bulk(_)) = client.recv().await.expect("recv") else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };

    let captured = seen.lock().expect("capture lock").clone();
    assert_eq!(
        captured,
        Some(resolved),
        "the session identity is the authority's AuthContext, not the spoofed client id",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
