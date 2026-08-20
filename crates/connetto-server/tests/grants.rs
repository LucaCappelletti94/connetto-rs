//! Grants and the principal they resolve to (R3), plus the refused-grant log
//! line (R12 part B).
//!
//! The handshake carries zero or more grants, each checked on its own. What
//! survives is a [`Principal`] carrying an identity, or capabilities, or both,
//! or neither, and those four arrival cases are the whole space this file
//! covers one test each.
//!
//! The other half is what a refusal does, and the answer is nothing visible: it
//! does not close the connection and the reply says not one thing about it. So
//! a checker that refuses everything and one that accepts everything are
//! indistinguishable from the client, and the log line asserted at the bottom
//! is the only place the truth shows up. That is why it is asserted here rather
//! than eyeballed.

use std::sync::{Arc, Mutex};

use connetto_core::auth::Principal;
use connetto_core::messages::{ControlMessage, Handshake, Subscribe, SubscriptionSpec};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SessionId};
use connetto_server::{
    Materializer, RequestGuard, SessionConfig, SessionManager, Snapshot, SnapshotSource, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// Records the principal the session presents to the snapshot read, which is
/// the one place a test can see what the grants resolved to.
#[derive(Clone, Default)]
struct CapturingSnapshot {
    seen: Arc<Mutex<Option<Principal>>>,
}

impl CapturingSnapshot {
    fn caller(&self) -> Principal {
        self.seen
            .lock()
            .expect("capture lock")
            .clone()
            .expect("the snapshot ran, so a principal reached it")
    }
}

impl SnapshotSource for CapturingSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
    ) -> Result<Snapshot, Self::Error> {
        *self.seen.lock().expect("capture lock") = Some(caller.clone());
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}
async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        match transport.recv().await.expect("recv frame") {
            Some(IncomingFrame::Control(msg)) => return msg,
            // The snapshot rides bulk frames, which nothing here inspects.
            Some(IncomingFrame::Bulk(_)) => {}
            other => panic!("expected a frame, got {other:?}"),
        }
    }
}

/// What one handshake produced: the ack the server sent, and the principal the
/// grants resolved to.
struct Arrival {
    session_token: String,
    resume_token: String,
    caller: Principal,
}

/// Run one handshake presenting `grants` and the optional resume credential,
/// then subscribe so the snapshot captures the principal.
async fn arrive(
    fixture: &Fixture,
    client_id: &str,
    grants: &[&str],
    resume_token: Option<&str>,
) -> Arrival {
    let snapshot = CapturingSnapshot::default();
    let authority: Arc<dyn HandshakeAuthority> = Arc::new(TestGrantChecker);
    // Rows come from a snapshot stub, not the change path. The policy is never consulted.
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        snapshot.clone(),
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        authority,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));

    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id).with_grants(
        grants
            .iter()
            .map(|grant| connetto_core::messages::Grant::new(*grant)),
    );
    if let Some(token) = resume_token {
        handshake = handshake.with_resume_token(token);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(ack) = next_control(&mut client).await else {
        panic!("the handshake was acknowledged");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    // Drain to the snapshot end so the capture has certainly happened.
    loop {
        match next_control(&mut client).await {
            ControlMessage::SnapshotEnd(_) => break,
            ControlMessage::FatalError(fatal) => panic!("the session closed: {fatal:?}"),
            _ => {}
        }
    }
    drop(client);
    let _ = server.await;

    Arrival {
        session_token: ack.session_token,
        resume_token: ack.resume_token,
        caller: snapshot.caller(),
    }
}

// The four arrival cases, one test each. Together they are the acceptance
// surface of the phase: the type has to make each of them representable, and
// nothing else.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presenting_nothing_arrives_with_neither_identity_nor_capability() {
    let fixture = Fixture::acquire().await;
    let arrival = arrive(&fixture, "visitor", &[], None).await;

    assert!(
        arrival.caller.identity().is_none(),
        "nobody presented a login, so nobody is signed in"
    );
    assert!(arrival.caller.capabilities().is_empty());
    assert!(
        arrival.session_token.parse::<SessionId>().is_ok(),
        "a run with no identity still has a handle: {}",
        arrival.session_token
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presenting_a_login_arrives_with_an_identity_and_no_capability() {
    let fixture = Fixture::acquire().await;
    let arrival = arrive(&fixture, "alice-client", &["user:alice"], None).await;

    assert_eq!(
        arrival.caller.identity().expect("signed in").user_id,
        "alice"
    );
    assert!(arrival.caller.capabilities().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presenting_a_key_arrives_with_a_capability_and_no_identity() {
    let fixture = Fixture::acquire().await;
    let arrival = arrive(&fixture, "bearer", &["key:abc123"], None).await;

    assert!(
        arrival.caller.identity().is_none(),
        "a key authorizes without identifying anybody"
    );
    let held: Vec<&str> = arrival
        .caller
        .capabilities()
        .iter()
        .map(|subject| subject.key().as_str())
        .collect();
    assert_eq!(held, ["key:abc123"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presenting_both_arrives_with_both() {
    let fixture = Fixture::acquire().await;
    let arrival = arrive(
        &fixture,
        "alice-client",
        &["user:alice", "key:abc123"],
        None,
    )
    .await;

    assert_eq!(
        arrival.caller.identity().expect("signed in").user_id,
        "alice"
    );
    assert_eq!(arrival.caller.capabilities().len(), 1);
}

// What a refusal does, which is the half no client can observe.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_good_grant_beside_one_bad_one_signs_in_and_sees_less() {
    let fixture = Fixture::acquire().await;
    let both = arrive(
        &fixture,
        "alice-client",
        &["user:alice", "not-a-grant-at-all"],
        None,
    )
    .await;

    assert_eq!(
        both.caller.identity().expect("signed in").user_id,
        "alice",
        "the refusal beside it changed nothing about what did resolve"
    );
    assert!(
        both.caller.capabilities().is_empty(),
        "the refused grant granted nothing"
    );

    // And the reply says nothing about it. Compared against the same handshake
    // without the bad grant, every field that could carry a hint is identical,
    // so not allowed, no longer allowed and never existed are one thing here.
    let clean = arrive(&fixture, "alice-client", &["user:alice"], None).await;
    assert_eq!(
        both.session_token, clean.session_token,
        "the same login is the same run whether or not a bad grant rode along"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_logins_leave_the_caller_unidentified_whichever_arrived_first() {
    let fixture = Fixture::acquire().await;
    let alice_first = arrive(&fixture, "confused", &["user:alice", "user:bob"], None).await;
    let bob_first = arrive(&fixture, "confused", &["user:bob", "user:alice"], None).await;

    assert!(
        alice_first.caller.identity().is_none() && bob_first.caller.identity().is_none(),
        "a run has one identity, and picking whichever was checked first would \
         make the order of checks decide the caller"
    );
}

// The handle a run with no identity comes back on.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unidentified_run_resumes_on_the_handle_it_was_given() {
    let fixture = Fixture::acquire().await;
    let first = arrive(&fixture, "visitor", &[], None).await;
    let again = arrive(&fixture, "visitor", &[], Some(&first.resume_token)).await;

    assert_eq!(
        again.session_token, first.session_token,
        "the run continues, so its cursor, its buffer and its write counter do too"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invented_handle_is_refused_and_a_fresh_run_starts() {
    let fixture = Fixture::acquire().await;
    let victim = arrive(&fixture, "visitor", &[], None).await;
    // The handle in the clear is not the credential. Presenting it bare is
    // exactly what an attacker who read one off a log would try.
    let thief = arrive(&fixture, "thief", &[], Some(&victim.session_token)).await;

    assert_ne!(
        thief.session_token, victim.session_token,
        "a run is resumed only on a credential this server signed, so a handle \
         somebody obtained buys nothing"
    );
}

// R12 part B. The connection stays open and the reply is silent, so this line
// is the whole visibility story and it is asserted rather than eyeballed.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_grant_names_the_caller_and_which_grant_in_the_log() {
    let fixture = Fixture::acquire().await;
    let buffer = logging::install_once();

    // A client id unique to this test, so the assertion holds while the rest of
    // the file runs in parallel against the same process-global destination.
    let client_id = "refusal-probe";
    let arrival = arrive(
        &fixture,
        client_id,
        &["user:alice", "not-a-grant-at-all"],
        None,
    )
    .await;
    assert_eq!(
        arrival.caller.identity().expect("signed in").user_id,
        "alice",
        "the refusal did not end anything"
    );

    let refusal = buffer
        .lines()
        .into_iter()
        .find(|line| line["message"] == "grant refused" && line["client_id"] == client_id)
        .expect("the refusal reached the log");

    assert_eq!(
        refusal["grant"], 1,
        "which grant, by its position in what the caller presented"
    );
    assert_eq!(refusal["reason"], "invalid");
    assert!(
        refusal["span"]["session"].is_string(),
        "inside the connection context, so the run it belongs to rides along: {refusal}"
    );
}

/// The process-global log destination, installed once and read back.
mod logging {
    use std::io::Write;
    use std::sync::{Arc, Mutex, OnceLock};

    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    pub struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        /// Every line written so far, each parsed as one JSON object.
        pub fn lines(&self) -> Vec<serde_json::Value> {
            String::from_utf8_lossy(&self.0.lock().expect("buffer poisoned"))
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    static BUFFER: OnceLock<Buffer> = OnceLock::new();

    /// Install the destination the first time and hand back the buffer. A
    /// subscriber is process-global, so a second install would be refused and
    /// the test would read an empty buffer.
    pub fn install_once() -> Buffer {
        BUFFER
            .get_or_init(|| {
                let buffer = Buffer::default();
                connetto_core::logging::install(buffer.clone(), "warn");
                buffer
            })
            .clone()
    }
}
