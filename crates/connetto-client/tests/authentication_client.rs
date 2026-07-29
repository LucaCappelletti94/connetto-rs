//! Client-side authentication (docs/architecture/11-authentication.md): a
//! rejected credential at the handshake surfaces as [`ClientError::Auth`] so
//! the driver routes to re-login, and identity continuity is enforced by which
//! replica file the client opens, so a re-authentication to a different
//! `user_id` is an account switch onto its own replica rather than a resume
//! onto another identity's data.

use std::collections::VecDeque;
use std::time::Duration;

use connetto_client::{
    AccessTokenSource, ClientConfig, ClientError, ClientEvent, ConnettoClient, ConnettoConnection,
    ReconnectPolicy, Replica, SqlFunctions, TokioSleeper, replica_db_name,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, SchemaVersion};
use diesel::prelude::*;

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

diesel::table! {
    items (id) {
        id -> Integer,
        label -> Nullable<Text>,
    }
}

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
            connection_id: "connection-fake".to_owned(),
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
        ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
            .await;
    match result {
        Err(ClientError::Auth(_)) => {}
        Err(other) => panic!("expected ClientError::Auth, got {other:?}"),
        Ok(_) => panic!("expected the handshake to be rejected"),
    }
}

#[tokio::test]
async fn each_identity_opens_its_own_replica() {
    let dir = tempfile::tempdir().expect("tempdir");
    let prefix = dir
        .path()
        .join("replica")
        .to_str()
        .expect("utf8")
        .to_owned();

    // The replica an identity owns is named from the id itself, so two
    // identities on one device never name the same file.
    let alice = replica_db_name(&prefix, "alice").expect("derive alice");
    let bob = replica_db_name(&prefix, "bob").expect("derive bob");
    assert_ne!(alice, bob, "distinct identities select distinct replicas");
    assert_eq!(
        alice,
        replica_db_name(&prefix, "alice").expect("derive alice again"),
        "one identity always returns to the same replica",
    );

    // Alice syncs a row into her replica.
    let mut conn = ConnettoConnection::connect(
        FakeTransport::new(HandshakeReply::Accept),
        &Replica::PlaintextFile { path: &alice },
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("connect alice");
    assert!(
        conn.unsynced().is_empty(),
        "no unsynced work on a fresh replica"
    );
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("alice-row")))
        .execute(conn.conn())
        .expect("insert");
    drop(conn);

    // Bob authenticates on the same device. His boot derives a different file,
    // so he starts on an empty replica and can neither read Alice's rows nor
    // inherit her pending mutations.
    let mut conn = ConnettoConnection::connect(
        FakeTransport::new(HandshakeReply::Accept),
        &Replica::PlaintextFile { path: &bob },
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("connect bob");
    let seen: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read bob");
    assert!(seen.is_empty(), "bob's replica holds none of alice's rows");
    drop(conn);

    // Alice's own replica is untouched by the switch and resumes with her data.
    let mut conn = ConnettoConnection::connect_existing(
        FakeTransport::new(HandshakeReply::Accept),
        &Replica::PlaintextFile { path: &alice },
        &config(),
        None,
    )
    .await
    .expect("reconnect alice");
    let seen: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read alice");
    assert_eq!(seen, vec![Some("alice-row".to_owned())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_routes_rejected_credential_to_relogin() {
    // The live session drops, and every reconnect attempt is met with a
    // rejected credential: the driver must stop retrying and signal re-login.
    let initial = FakeTransport::new(HandshakeReply::Accept);
    let conn =
        ConnettoConnection::connect(initial, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
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
    let conn =
        ConnettoConnection::connect(initial, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
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
