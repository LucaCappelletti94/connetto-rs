//! Phase 1 authentication acceptance tests.
//!
//! The handshake must resolve identity through the [`SessionVerifier`] seam over
//! `Handshake.auth_token`, never from the client-supplied `client_id`. These
//! tests prove the spoofing hole is closed: an absent or forged credential is
//! refused with [`FatalErrorReason::AuthenticationFailed`] and the session dies
//! before any subscription work, while a verified credential yields exactly the
//! [`AuthContext`] the verifier resolved even when the client claims a different
//! id. The stand-in [`TestSessionVerifier`] is used where no live identity
//! provider is needed.

use std::sync::{Arc, Mutex};

use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    ControlMessage, FatalErrorReason, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestSessionVerifier;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{
    Cursor, PROTOCOL_VERSION, SessionVerifier, SessionVerifyError, SessionVerifyFuture,
};
use connetto_server::{
    Materializer, PermissiveAuth, SessionConfig, SessionError, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// Records the identity the session presents to the snapshot read, so a test
/// can inspect the [`AuthContext`] the verifier resolved. Returns no rows.
#[derive(Clone, Default)]
struct CapturingSnapshot {
    seen: Arc<Mutex<Option<AuthContext>>>,
}

impl SnapshotSource for CapturingSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        auth: &AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        *self.seen.lock().expect("capture lock") = Some(auth.clone());
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

/// A verifier that resolves every token to one fixed identity, standing in for a
/// real verifier that derives identity from a trusted credential rather than the
/// client-supplied id.
struct FixedVerifier(AuthContext);

impl SessionVerifier for FixedVerifier {
    fn verify_session<'a>(&'a self, _auth_token: &'a str) -> SessionVerifyFuture<'a> {
        let context = self.0.clone();
        Box::pin(async move {
            Ok(connetto_core::VerifiedSession {
                context,
                // A fixed id, so every connection this stub verifies shares one
                // watermark key, which is what the exactly-once assertions rely on.
                session_id: connetto_core::SessionId::from_token_hash("fixed-session"),
            })
        })
    }
}

/// A verifier that refuses every credential, standing in for a real verifier
/// rejecting a forged token.
struct AlwaysReject;

impl SessionVerifier for AlwaysReject {
    fn verify_session<'a>(&'a self, _auth_token: &'a str) -> SessionVerifyFuture<'a> {
        Box::pin(async move { Err(SessionVerifyError::Invalid("forged token".to_owned())) })
    }
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn absent_credential_is_rejected_with_authentication_failed() {
    let fixture = Fixture::acquire().await;
    // TestSessionVerifier refuses an empty token as an absent credential.
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        CapturingSnapshot::default(),
        PermissiveAuth,
        Arc::new(TestSessionVerifier),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "any-client",
            "",
        )))
        .await
        .expect("send handshake");

    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("expected fatal error");
    };
    assert_eq!(fatal.reason, FatalErrorReason::AuthenticationFailed);

    let outcome = server.await.expect("join server");
    assert!(
        matches!(outcome, Err(SessionError::Authentication(_))),
        "serve terminates with an authentication error, got {outcome:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn forged_credential_is_rejected_with_authentication_failed() {
    let fixture = Fixture::acquire().await;
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        CapturingSnapshot::default(),
        PermissiveAuth,
        Arc::new(AlwaysReject),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "any-client",
            "forged-token",
        )))
        .await
        .expect("send handshake");

    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("expected fatal error");
    };
    assert_eq!(fatal.reason, FatalErrorReason::AuthenticationFailed);

    let outcome = server.await.expect("join server");
    assert!(
        matches!(outcome, Err(SessionError::Authentication(_))),
        "serve terminates with an authentication error, got {outcome:?}",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn verified_identity_ignores_a_spoofed_client_id() {
    let fixture = Fixture::acquire().await;
    // The verifier resolves the identity, and the client claims a different id.
    let resolved = AuthContext::new("resolved-user");
    let capture = CapturingSnapshot::default();
    let seen = Arc::clone(&capture.seen);
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        capture,
        PermissiveAuth,
        Arc::new(FixedVerifier(resolved.clone())),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    // The client claims to be "spoofer", but identity comes from the verifier.
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "spoofer",
            "any-token",
        )))
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
        "the session identity is the verifier's AuthContext, not the spoofed client id",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
