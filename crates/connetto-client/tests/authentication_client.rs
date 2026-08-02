//! Client-side authentication (docs/architecture/11-authentication.md): a
//! rejected credential at the handshake surfaces as [`ClientError::Auth`] so
//! the driver routes to re-login, and identity continuity is enforced by which
//! replica file the client opens, so a re-authentication to a different
//! `user_id` is an account switch onto its own replica rather than a resume
//! onto another identity's data.

use std::time::Duration;

use connetto_client::{
    AccessTokenSource, ClientConfig, ClientError, ClientEvent, ConnettoClient, ConnettoConnection,
    ReconnectPolicy, Replica, ReplicaKey, SqlFunctions, TokioSleeper, replica_db_name,
};
use connetto_core::messages::FatalErrorReason;
use connetto_core::test_support::{FakeClosed, FakeTransport};
use diesel::prelude::*;

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

diesel::table! {
    items (id) {
        id -> Integer,
        label -> Nullable<Text>,
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
    let transport = FakeTransport::rejecting();
    let result =
        ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
            .await;
    match result {
        Err(ClientError::Auth(_)) => {}
        Err(other) => panic!("expected ClientError::Auth, got {other:?}"),
        Ok(_) => panic!("expected the handshake to be rejected"),
    }
}

/// First-boot `replica`, write `label`, and leave the captured mutation queued,
/// since the fake server acknowledges the handshake and nothing else. Returns the
/// pending sequence numbers, captured before the connection drops.
async fn first_boot_with_a_queued_row(replica: &Replica<'_>, label: &str) -> Vec<u64> {
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting(),
        replica,
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("first connect");
    assert!(
        conn.unsynced().is_empty(),
        "no unsynced work on a fresh replica"
    );
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq(label)))
        .execute(conn.conn())
        .expect("insert");
    conn.push().await.expect("upload the captured mutation");
    let unsynced = conn.unsynced();
    assert!(
        !unsynced.is_empty(),
        "the unacknowledged mutation stays pending"
    );
    unsynced
}

/// Phase E4 acceptance, the native half of the account switch.
///
/// Each identity owns a replica named from its own id, encrypted under its own
/// key. A switch opens a different file, so the arriving identity can read none
/// of the departing one's rows and inherit none of its pending mutations, the
/// departing replica is neither deleted nor readable with the arriving key, and
/// switching back resumes from the file that was left alone.
///
/// The keys here are two fixed values rather than minted ones, because the link
/// from an identity to its own key is what `native_auth.rs` and `teardown.rs`
/// prove. What this test owes is that the two replicas are mutually opaque given
/// distinct keys.
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

    let alice_key = ReplicaKey::from_bytes([0x11; ReplicaKey::LEN]);
    let bob_key = ReplicaKey::from_bytes([0x22; ReplicaKey::LEN]);
    let alice_replica = Replica::EncryptedFile {
        path: &alice,
        key: alice_key.clone(),
    };
    let bob_replica = Replica::EncryptedFile {
        path: &bob,
        key: bob_key,
    };

    // Alice syncs a row into her replica and leaves a mutation queued, since the
    // fake server acknowledges the handshake and nothing else.
    let alice_unsynced = first_boot_with_a_queued_row(&alice_replica, "alice-row").await;

    // Bob authenticates on the same device. His boot derives a different file,
    // so he starts on an empty replica and can neither read Alice's rows nor
    // inherit her pending mutations.
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting(),
        &bob_replica,
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
    assert!(
        conn.unsynced().is_empty(),
        "and none of her pending mutations either"
    );
    drop(conn);

    // Neither replica was deleted by the switch: a returning identity resumes
    // rather than re-syncing, which is why a wipe has to be explicit.
    assert!(
        std::path::Path::new(&alice).exists() && std::path::Path::new(&bob).exists(),
        "a switch deletes nothing"
    );

    // The files are mutually opaque. Naming the other identity's replica while
    // holding this identity's key does not read it, so a switch cannot degrade
    // into a cross-identity resume even if the file selection were wrong.
    let crossed = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &Replica::EncryptedFile {
            path: &bob,
            key: alice_key.clone(),
        },
        &config(),
        None,
    )
    .await;
    match crossed {
        Err(ClientError::ReplicaUndecryptable(_)) => {}
        Err(other) => panic!("expected ReplicaUndecryptable, got {other:?}"),
        Ok(_) => panic!("one identity's key must not open another's replica"),
    }

    // Alice's own replica is untouched by the switch and resumes with her data
    // and her queued mutation, which is the fast return the per-replica key
    // exists to make possible.
    let mut conn = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &alice_replica,
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
    assert_eq!(
        conn.unsynced(),
        alice_unsynced,
        "her unuploaded mutation survived the switch and replays"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_routes_rejected_credential_to_relogin() {
    // The live session drops, and every reconnect attempt is met with a
    // rejected credential: the driver must stop retrying and signal re-login.
    let initial = FakeTransport::accepting();
    let conn =
        ConnettoConnection::connect(initial, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
            .await
            .expect("initial connect");
    let factory = || async { Ok::<FakeTransport, FakeClosed>(FakeTransport::rejecting()) };
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

/// A session revoked mid-connection reaches the application as its own event
/// carrying the reason, and the driver then routes to re-login.
///
/// Before this, the client classified any mid-session close as a protocol
/// violation and its pump exited silently, so the app learned nothing and never
/// reconnected. The reason is the whole point: it is what tells a restart apart
/// from a sign-out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mid_session_close_surfaces_its_reason_then_routes_to_relogin() {
    let initial = FakeTransport::accepting_then_closing(FatalErrorReason::SessionRevoked);
    let conn =
        ConnettoConnection::connect(initial, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
            .await
            .expect("initial connect");
    // A revoked session's next handshake is refused, which is what turns the
    // close into an interactive re-login rather than an endless retry.
    let factory = || async { Ok::<FakeTransport, FakeClosed>(FakeTransport::rejecting()) };
    let policy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
        max_attempts: Some(5),
    };
    let (client, pump) = ConnettoClient::with_reconnect(conn, factory, TokioSleeper, policy);
    let mut events = client.events();
    tokio::spawn(pump);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut closed_because = None;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the close and the re-login signal before timeout")
            .expect("event stream open");
        match event {
            ClientEvent::ServerClosed { reason } => closed_because = Some(reason),
            ClientEvent::AuthenticationRequired => break,
            ClientEvent::Closed => panic!("the pump gave up instead of routing to re-login"),
            _ => {}
        }
    }
    assert_eq!(
        closed_because,
        Some(FatalErrorReason::SessionRevoked),
        "the app is told why the server closed, not merely that it did"
    );
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_retries_a_transient_refresh_fault() {
    // The live session drops and every reconnect refreshes the access token
    // through a token source that fails transiently, as a network blip or a 5xx
    // from /auth/refresh would. The driver must keep retrying and eventually
    // exhaust its attempts, never routing a transient fault to interactive
    // re-login.
    let initial = FakeTransport::accepting();
    let conn =
        ConnettoConnection::connect(initial, &Replica::Ephemeral, SQLITE_DDL, &config(), None)
            .await
            .expect("initial connect")
            .with_token_source(AccessTokenSource::new(|| async {
                Err(ClientError::Transport(
                    "refresh endpoint returned 503".to_owned(),
                ))
            }));
    let factory = || async { Ok::<FakeTransport, FakeClosed>(FakeTransport::accepting()) };
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
