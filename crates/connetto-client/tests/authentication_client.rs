//! Phase 6 client-side authentication (docs/architecture/11-authentication.md):
//! a rejected credential at the handshake surfaces as [`ClientError::Auth`] so
//! the driver routes to re-login, and the replica enforces identity continuity
//! so a re-authentication to a different `user_id` is an account switch rather
//! than a resume onto another identity's data.

use std::collections::VecDeque;
use std::time::Duration;

use connetto_client::{
    AccessTokenSource, ClientConfig, ClientError, ClientEvent, ConnettoClient, ConnettoConnection,
    ReconnectPolicy, SqlFunctions, TokioSleeper,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, SchemaVersion};

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The reply a [`FakeTransport`] sends back the moment it sees a handshake.
#[derive(Clone, Copy)]
enum HandshakeReply {
    /// A well-formed acknowledgement: the handshake succeeds.
    Accept,
    /// `FatalError(AuthenticationFailed)`: the credential is rejected.
    Reject,
}

/// A transport that answers a handshake with a canned reply and otherwise
/// drops sends on the floor. Enough to drive `connect`/`resume` without a
/// server.
struct FakeTransport {
    reply: HandshakeReply,
    inbox: VecDeque<IncomingFrame>,
}

impl FakeTransport {
    fn new(reply: HandshakeReply) -> Self {
        Self {
            reply,
            inbox: VecDeque::new(),
        }
    }

    fn ack() -> IncomingFrame {
        IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
            session_id: "session-fake".to_owned(),
            session_token: "token-fake".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None::<SchemaVersion>,
            initial_credits: 64,
            last_applied_seq: None,
        }))
    }
}

/// The fake never fails a send or recv, but the trait needs a concrete typed
/// error, so this stands in for "the peer is gone".
#[derive(Debug, thiserror::Error)]
#[error("fake transport closed")]
struct FakeClosed;

impl Transport for FakeTransport {
    type Error = FakeClosed;

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeClosed> {
        if matches!(message, ControlMessage::Handshake(_)) {
            let frame = match self.reply {
                HandshakeReply::Accept => Self::ack(),
                HandshakeReply::Reject => IncomingFrame::Control(ControlMessage::FatalError(
                    FatalError::new(FatalErrorReason::AuthenticationFailed),
                )),
            };
            self.inbox.push_back(frame);
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeClosed> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeClosed> {
        Ok(self.inbox.pop_front())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), FakeClosed> {
        Ok(())
    }
}

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "phase6".to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

#[tokio::test]
async fn handshake_rejection_surfaces_as_auth_error() {
    let transport = FakeTransport::new(HandshakeReply::Reject);
    let result =
        ConnettoConnection::connect(transport, ":memory:", SQLITE_DDL, &config(), None).await;
    match result {
        Err(ClientError::Auth(_)) => {}
        Err(other) => panic!("expected ClientError::Auth, got {other:?}"),
        Ok(_) => panic!("expected the handshake to be rejected"),
    }
}

#[tokio::test]
async fn replica_enforces_identity_continuity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("replica.sqlite");
    let path = path.to_str().expect("utf8 path");

    // First connect stamps nothing yet: a fresh replica has no owner and no
    // unsynced work.
    let mut conn = ConnettoConnection::connect(
        FakeTransport::new(HandshakeReply::Accept),
        path,
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("connect");
    assert_eq!(conn.identity().expect("identity"), None, "unbound at first");
    assert!(
        conn.unsynced().is_empty(),
        "no unsynced work on a fresh replica"
    );

    // Binding stamps the replica, and a rebind to the same id is an idempotent
    // resume.
    conn.bind_identity("alice").expect("first bind stamps");
    assert_eq!(conn.identity().expect("identity").as_deref(), Some("alice"));
    conn.bind_identity("alice").expect("same-id rebind resumes");

    // A different id is an account switch, refused so the caller purges rather
    // than adopting another identity's replica.
    match conn.bind_identity("bob") {
        Err(ClientError::IdentityMismatch { stored, presented }) => {
            assert_eq!(stored, "alice");
            assert_eq!(presented, "bob");
        }
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }

    // The stamp is durable: reopening the same replica file still refuses a
    // different identity.
    drop(conn);
    let mut reopened = ConnettoConnection::connect_existing(
        FakeTransport::new(HandshakeReply::Accept),
        path,
        &config(),
        None,
    )
    .await
    .expect("reconnect existing");
    assert_eq!(
        reopened.identity().expect("identity").as_deref(),
        Some("alice")
    );
    assert!(matches!(
        reopened.bind_identity("bob"),
        Err(ClientError::IdentityMismatch { .. })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_routes_rejected_credential_to_relogin() {
    // The live session drops, and every reconnect attempt is met with a
    // rejected credential: the driver must stop retrying and signal re-login.
    let initial = FakeTransport::new(HandshakeReply::Accept);
    let conn = ConnettoConnection::connect(initial, ":memory:", SQLITE_DDL, &config(), None)
        .await
        .expect("initial connect");
    let factory =
        || async { Ok::<FakeTransport, FakeClosed>(FakeTransport::new(HandshakeReply::Reject)) };
    let policy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        max_attempts: Some(5),
    };
    let (client, pump) = ConnettoClient::with_reconnect(conn, factory, TokioSleeper, policy);
    let mut events = client.events();
    tokio::spawn(pump);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("re-login signal before timeout")
            .expect("event stream open");
        match event {
            ClientEvent::AuthenticationRequired => break,
            ClientEvent::Closed => panic!("closed instead of routing to re-login"),
            _ => {}
        }
    }
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_retries_a_transient_refresh_fault() {
    // The live session drops and every reconnect refreshes the access token
    // through a token source that fails transiently, as a network blip or a 5xx
    // from /auth/refresh would. The driver must keep retrying and eventually
    // exhaust its attempts, never routing a transient fault to interactive
    // re-login.
    let initial = FakeTransport::new(HandshakeReply::Accept);
    let conn = ConnettoConnection::connect(initial, ":memory:", SQLITE_DDL, &config(), None)
        .await
        .expect("initial connect")
        .with_token_source(AccessTokenSource::new(|| async {
            Err(ClientError::Transport(
                "refresh endpoint returned 503".to_owned(),
            ))
        }));
    let factory =
        || async { Ok::<FakeTransport, FakeClosed>(FakeTransport::new(HandshakeReply::Accept)) };
    let policy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        max_attempts: Some(3),
    };
    let (client, pump) = ConnettoClient::with_reconnect(conn, factory, TokioSleeper, policy);
    let mut events = client.events();
    tokio::spawn(pump);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_reconnecting = false;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("an event before timeout")
            .expect("event stream open");
        match event {
            ClientEvent::Reconnecting { .. } => saw_reconnecting = true,
            ClientEvent::AuthenticationRequired => {
                panic!("a transient refresh fault must not force re-login")
            }
            // Exhausting the retry budget ends in a plain close, not re-login.
            ClientEvent::Closed => break,
            _ => {}
        }
    }
    assert!(saw_reconnecting, "the driver retried before giving up");
    drop(client);
}
