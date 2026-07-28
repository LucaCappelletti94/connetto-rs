//! Phase 1 authentication acceptance tests.
//!
//! The handshake must resolve identity through the [`SessionVerifier`] seam over
//! `Handshake.auth_token`, never from the client-supplied `client_id`. These
//! tests prove the spoofing hole is closed: an absent or forged credential is
//! refused with [`FatalErrorReason::AuthenticationFailed`] and the session dies
//! before any subscription work, while a verified credential yields exactly the
//! [`AuthContext`] the verifier resolved even when the client claims a different
//! id. The permissive [`TrustingSessionVerifier`] keeps the Docker-free loop
//! running with no live identity provider.

use std::sync::{Arc, Mutex};

use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    ControlMessage, FatalErrorReason, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{
    Cursor, PROTOCOL_VERSION, SessionVerifier, SessionVerifyError, SessionVerifyFuture,
};
use connetto_server::{
    Materializer, PermissiveAuth, SessionConfig, SessionError, SessionManager, Snapshot,
    SnapshotSource, loopback, sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";
const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);";

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
                session_id: "fixed-session".to_owned(),
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

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    // Migration-style DDL, which the typed DSL does not express.
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_credential_is_rejected_with_authentication_failed() {
    // The default TrustingSessionVerifier refuses an empty token as an absent
    // credential.
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        CapturingSnapshot::default(),
        PermissiveAuth,
        sqlite_write_target(client_replica()),
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
async fn forged_credential_is_rejected_with_authentication_failed() {
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        CapturingSnapshot::default(),
        PermissiveAuth,
        sqlite_write_target(client_replica()),
        SessionConfig::default(),
    )
    .with_session_verifier(Arc::new(AlwaysReject));
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
async fn verified_identity_ignores_a_spoofed_client_id() {
    // The verifier resolves the identity, and the client claims a different id.
    let resolved = AuthContext::new("resolved-user")
        .with_tenant("tenant-7")
        .with_roles(["admin"]);
    let capture = CapturingSnapshot::default();
    let seen = Arc::clone(&capture.seen);
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        capture,
        PermissiveAuth,
        sqlite_write_target(client_replica()),
        SessionConfig::default(),
    )
    .with_session_verifier(Arc::new(FixedVerifier(resolved.clone())));
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
