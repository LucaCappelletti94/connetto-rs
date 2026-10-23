//! The share-key protocol as a consumer sees it (R95).
//!
//! A replacement answer alone never publishes durable coverage, a known empty
//! checkpoint stays distinct from unknown, a change back to the starting set
//! still replaces, every open delivery keeps coverage unknown until it ends,
//! a replay fence is what lets coverage publish after a declaration, and a
//! rate-limited replacement arms the server's delay without losing the
//! accepted set.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_client::{ClientBuilder, ClientEvent, ConnettoConnection, Grant, SyncSchema};
use connetto_core::Cursor;
use connetto_core::auth::CapabilitySubject;
use connetto_core::messages::{
    AggregateUpdate, BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, Handshake,
    HandshakeAck, Pong, RateLimited, ReplaceShareKeys, ShareKeysReplaced, SnapshotBegin,
    SnapshotEnd, WriterGrant,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use parking_lot::Mutex;
use thiserror::Error;

/// The resume cursor the scripted snapshots stamp.
const CURSOR: [u8; 8] = [0, 0, 0, 0, 0, 0, 1, 7];

diesel::table! {
    _connetto_meta (id) {
        id -> Integer,
        cursor -> Binary,
        cursor_subjects -> Nullable<Binary>,
    }
}

/// A scripted transport that records what the client sends and serves the
/// frames a test queues, idling while none are queued.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    handshakes: Arc<Mutex<Vec<Handshake>>>,
    replacements: Arc<Mutex<Vec<ReplaceShareKeys>>>,
    pings: Arc<Mutex<Vec<u64>>>,
    closed: Arc<AtomicBool>,
}

#[derive(Debug, Error)]
enum Gone {
    #[error("the scripted socket is gone")]
    Closed,
}

impl Script {
    fn say(&self, frame: IncomingFrame) {
        self.frames.lock().push_back(frame);
    }
}

impl Transport for Script {
    type Error = Gone;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        match &message {
            ControlMessage::Handshake(handshake) => self.handshakes.lock().push(handshake.clone()),
            ControlMessage::ReplaceShareKeys(replacement) => {
                self.replacements.lock().push(replacement.clone());
            }
            ControlMessage::Ping(ping) => self.pings.lock().push(ping.nonce),
            _ => {}
        }
        if self.closed.load(Ordering::Acquire) {
            ready(Err(Gone::Closed))
        } else {
            ready(Ok(()))
        }
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        super::support::scripted_recv(&self.frames, &self.closed)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.closed.store(true, Ordering::Release);
        ready(Ok(()))
    }
}

fn ack() -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "script".to_owned(),
        session_token: "script".to_owned(),
        resume_token: "script".to_owned(),
        current_cursor: Cursor::from(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        writer: Some(WriterGrant {
            number: 1,
            frontier: 0,
        }),
    }))
}

fn pong(nonce: u64) -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::Pong(Pong { nonce }))
}

fn resnapshot(sub_id: &str) -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::FullResyncRequired(FullResyncRequired {
        sub_id: sub_id.to_owned(),
        reason: FullResyncReason::AuthorizationChange,
    }))
}

fn snapshot_begin(sub_id: &str) -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::SnapshotBegin(SnapshotBegin {
        sub_id: sub_id.to_owned(),
        priority: connetto_core::messages::SubscriptionPriority::default(),
    }))
}

fn snapshot_end(sub_id: &str) -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::SnapshotEnd(SnapshotEnd {
        sub_id: sub_id.to_owned(),
        cursor: Cursor::from(CURSOR.to_vec()),
    }))
}

fn schema() -> SyncSchema {
    SyncSchema::new(connetto_core::SchemaBundle::new(
        "",
        "",
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
         CREATE VIEW visible AS SELECT * FROM notes \
         WHERE owner = current_app_user() \
            OR instr(',' || current_app_subjects() || ',', ',' || owner || ',') > 0;",
        Vec::<(String, String)>::new(),
        vec!["visible".to_owned()],
        None::<&str>,
    ))
}

/// base64url without padding, for minting the JWT-shaped grants this suite holds.
fn b64(text: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        // byte to u32 is a lossless widening, and every slice below is 6 bits.
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (shift, kept) in [
            (18u32, true),
            (12, true),
            (6, chunk.len() > 1),
            (0, chunk.len() > 2),
        ] {
            if !kept {
                break;
            }
            let index = (value >> shift) % 64;
            debug_assert!(index < 64, "a 6-bit slice stays inside the alphabet");
            let index = usize::try_from(index).expect("the bound is asserted above");
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}

/// A grant with the `exp` claim in seconds, or none to read at all.
fn mint(exp: Option<i64>) -> Grant {
    let payload = match exp {
        Some(exp) => format!("{{\"exp\":{exp}}}"),
        None => "{}".to_owned(),
    };
    Grant::new(format!("h.{body}.s", body = b64(&payload)))
}

/// The compact JSON the replica stores for a known subject set.
fn known(subjects: &[&str]) -> Vec<u8> {
    let items: Vec<String> = subjects
        .iter()
        .map(|subject| format!("\"{subject}\""))
        .collect();
    format!("[{}]", items.join(",")).into_bytes()
}

fn coverage(conn: &mut ConnettoConnection<Script>) -> Option<Vec<u8>> {
    match _connetto_meta::table
        .select(_connetto_meta::cursor_subjects)
        .filter(_connetto_meta::id.eq(1))
        .first::<Option<Vec<u8>>>(conn.conn())
    {
        Ok(subjects) => subjects,
        Err(diesel::result::Error::NotFound) => None,
        Err(err) => panic!("the replica answers: {err}"),
    }
}

/// Open an in-memory client under the given keys and attach it to a scripted
/// server that acknowledges the handshake.
async fn client(keys: Vec<(Grant, String)>) -> (ConnettoConnection<Script>, Script) {
    let script = Script::default();
    script.say(ack());
    let subjects: Vec<(Grant, CapabilitySubject<String>)> = keys
        .into_iter()
        .map(|(grant, subject)| (grant, CapabilitySubject::<String>::new(subject)))
        .collect();
    let mut conn = ClientBuilder::new(schema(), super::support::NeverDial::<Script>::default())
        .with_share_keys(subjects)
        .signed_in(super::support::held("tester"))
        .open_driven()
        .expect("the builder opens the replica");
    conn.attach(script.clone())
        .await
        .expect("the handshake completes");
    (conn, script)
}

async fn pump(conn: &mut ConnettoConnection<Script>, bound: Duration) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        let event = tokio::time::timeout_at(deadline, conn.pump_one())
            .await
            .expect("the pump yields in time")
            .expect("the frame applies");
        // Notices drain before the frame a test queued for it.
        if !matches!(event, ClientEvent::SyncStatus(_)) {
            return event;
        }
    }
}

/// One pump step that may idle when the script queued no frame, so a step's
/// sends can be observed without an answer arriving.
async fn step_or_idle(conn: &mut ConnettoConnection<Script>) {
    let _ = tokio::time::timeout(Duration::from_millis(100), conn.pump_one()).await;
}

/// The last replacement this script was sent, and its keys' order.
fn replacement(script: &Script) -> ReplaceShareKeys {
    script
        .replacements
        .lock()
        .last()
        .cloned()
        .expect("a replacement was sent")
}

/// Complete the initial row delivery of `s1`.
async fn first_sync(conn: &mut ConnettoConnection<Script>, script: &Script) {
    script.say(snapshot_begin("s1"));
    pump(conn, Duration::from_secs(5)).await;
    script.say(snapshot_end("s1"));
    pump(conn, Duration::from_secs(5)).await;
}

/// The answer to the replacement in flight, plus its resends, in the server's
/// order, each pumped.
async fn settle(conn: &mut ConnettoConnection<Script>, script: &Script) {
    let id = replacement(script).request_id;
    script.say(resnapshot("s1"));
    script.say(snapshot_begin("s1"));
    script.say(snapshot_end("s1"));
    script.say(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
        ShareKeysReplaced { request_id: id },
    )));
    pump(conn, Duration::from_secs(5)).await;
    pump(conn, Duration::from_secs(5)).await;
    pump(conn, Duration::from_secs(5)).await;
    pump(conn, Duration::from_secs(5)).await;
}

/// The answer arrives while its snapshot is still credit-gated, so the answer
/// alone must not publish durable coverage.
#[tokio::test]
async fn a_replacement_answer_alone_never_publishes_coverage() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));

    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add a key");
    step_or_idle(&mut conn).await;
    assert_eq!(replacement(&script).keys.len(), 2);

    // The resend instruction and its begun snapshot land, then the answer,
    // and the snapshot's completion never does.
    script.say(resnapshot("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_begin("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    let id = replacement(&script).request_id;
    script.say(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
        ShareKeysReplaced { request_id: id },
    )));
    let event = pump(&mut conn, Duration::from_secs(5)).await;
    assert!(
        matches!(event, ClientEvent::ShareKeysReplaced { .. }),
        "the answer is surfaced, got {event:?}"
    );
    assert_eq!(
        coverage(&mut conn),
        None,
        "the credit-gated snapshot keeps coverage unknown"
    );
}

/// A reconnect presents the accepted keys and waits for its replay before publishing coverage.
#[tokio::test]
async fn a_lost_connection_resends_the_unsettled_set() {
    let (mut conn, mut script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;

    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add a key");
    step_or_idle(&mut conn).await;
    let first = replacement(&script);

    script.close().await.expect("the script closes");
    let event = pump(&mut conn, Duration::from_secs(5)).await;
    assert!(
        matches!(event, ClientEvent::Closed),
        "the close is announced, got {event:?}"
    );

    let second = Script::default();
    second.say(ack());
    conn.attach(second.clone())
        .await
        .expect("the redial handshakes");
    let handshake = second
        .handshakes
        .lock()
        .last()
        .cloned()
        .expect("handshake sent");
    let mut expected = first.keys;
    expected.insert(0, Grant::new("user:tester"));
    assert_eq!(handshake.grants, expected);
    assert_eq!(coverage(&mut conn), None);
    second.say(snapshot_end("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a", "b"])));
}

/// A metered replacement keeps the desired set, arms the server's delay on
/// the key timer, and resends the whole set once it elapses.
#[tokio::test]
async fn a_rate_limited_replacement_arms_its_delay_and_keeps_its_set() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;

    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add a key");
    step_or_idle(&mut conn).await;
    let first = replacement(&script);

    script.say(IncomingFrame::Control(ControlMessage::RateLimited(
        RateLimited {
            related_to: Some(first.request_id.clone()),
            retry_after_ms: 300,
        },
    )));
    let event = pump(&mut conn, Duration::from_secs(5)).await;
    assert!(
        matches!(event, ClientEvent::RateLimited { .. }),
        "the metering is surfaced, got {event:?}"
    );
    let timer = conn
        .share_key_timer()
        .expect("the delay arms the key timer");
    assert!(
        timer.wait() <= Duration::from_millis(300),
        "the timer holds the server's delay, got {:?}",
        timer.wait()
    );
    assert_eq!(script.replacements.lock().len(), 1, "nothing retries early");

    tokio::time::sleep(Duration::from_millis(400)).await;
    step_or_idle(&mut conn).await;
    let resent = replacement(&script);
    assert_ne!(resent.request_id, first.request_id, "a fresh request id");
    assert_eq!(resent.keys, first.keys, "the desired set is preserved");
    assert!(
        conn.share_key_timer()
            .expect("replacement answer deadline")
            .wait()
            >= Duration::from_secs(20),
        "the expired retry delay cannot keep the pump waking immediately",
    );

    script.say(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
        ShareKeysReplaced {
            request_id: resent.request_id,
        },
    )));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a", "b"])));
}

/// A completed sync of a caller holding no key commits the known empty set,
/// and a later handshake presents it, which is what keeps the catch-up plain.
#[tokio::test]
async fn a_known_empty_checkpoint_is_presented_on_the_next_handshake() {
    let (mut conn, script) = client(Vec::new()).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&[])));

    conn.disconnect();
    let second = Script::default();
    second.say(ack());
    conn.attach(second.clone())
        .await
        .expect("the redial handshakes");
    let handshake = second
        .handshakes
        .lock()
        .last()
        .cloned()
        .expect("the handshake was sent");
    assert_eq!(
        handshake.last_cursor,
        Some(Cursor::from(CURSOR.to_vec())),
        "the resume cursor travels"
    );
    assert_eq!(
        handshake.cursor_subjects,
        Some(Vec::<String>::new()),
        "the known empty set is distinct from unknown"
    );
    assert_eq!(
        coverage(&mut conn),
        None,
        "replay keeps durable coverage unknown"
    );
    second.say(snapshot_end("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&[])));
}

/// A change that restores the starting set still sends a replacement, because
/// the change itself, not the set, is what the generation counts.
#[tokio::test]
async fn a_change_back_to_the_starting_set_still_replaces() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;

    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add a key");
    step_or_idle(&mut conn).await;
    settle(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a", "b"])));

    conn.remove_share_key(&CapabilitySubject::<String>::new("b"))
        .await
        .expect("remove the key");
    step_or_idle(&mut conn).await;
    let resent = replacement(&script);
    assert_eq!(resent.keys.len(), 1, "the restored set is sent whole");

    settle(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

/// One owed resend keeps coverage unknown while a sibling's has settled, and
/// the replay fence is what lets the last settlement publish.
#[tokio::test]
async fn coverage_waits_for_every_owed_resend() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the first subscription");
    conn.subscribe("s2", "SELECT id, owner FROM notes")
        .await
        .expect("declare the second subscription");

    // The first resend completes while the second is still owed.
    script.say(resnapshot("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_begin("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_end("s1"));
    let event = pump(&mut conn, Duration::from_secs(5)).await;
    assert!(
        matches!(event, ClientEvent::SnapshotEnd { .. }),
        "the first settlement lands, got {event:?}"
    );
    assert_eq!(coverage(&mut conn), None, "the second resend is still owed");

    script.say(resnapshot("s2"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_begin("s2"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_end("s2"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

/// A computed declaration rests its bootstrap behind an ordered fence, and
/// the matching Pong is what lets coverage publish.
#[tokio::test]
async fn a_computed_declaration_is_fenced_before_publication() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare rows");
    first_sync(&mut conn, &script).await;
    conn.subscribe("agg", "SELECT COUNT(*) FROM notes")
        .await
        .expect("declare the computed subscription");

    // The synchronous bootstrap arrives, and the fence goes with it.
    script.say(IncomingFrame::Control(ControlMessage::AggregateUpdate(
        AggregateUpdate {
            sub_id: "agg".to_owned(),
            group_key: None,
            group_values_json: None,
            result_json: Some("3".to_owned()),
            is_full_result: true,
        },
    )));
    pump(&mut conn, Duration::from_secs(5)).await;
    let nonce = script
        .pings
        .lock()
        .first()
        .copied()
        .expect("the fence is sent");
    assert!(matches!(
        conn.ping(nonce).await,
        Err(connetto_client::ClientError::Protocol(_))
    ));
    let application_nonce = (1_u64 << 63) - 1;
    conn.ping(application_nonce)
        .await
        .expect("send an application ping");
    assert_eq!(*script.pings.lock(), vec![nonce, application_nonce]);
    script.say(pong(application_nonce));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(
        coverage(&mut conn),
        None,
        "the unfenced bootstrap keeps coverage unknown"
    );

    script.say(pong(nonce));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

/// An authorization resend persists unknown coverage before it clears a row,
/// and the replacement settlement re-publishes the set it covered.
#[tokio::test]
async fn an_authorization_resync_persists_unknown_before_clearing() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));

    script.say(resnapshot("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(
        coverage(&mut conn),
        None,
        "unknown is persisted before the rows move"
    );

    script.say(snapshot_begin("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    script.say(snapshot_end("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

/// A grant already past its expiry leaves the desired set on the first pass
/// and is absent from the replacement the connection sends.
#[tokio::test]
async fn an_expired_key_is_dropped_before_the_first_replacement() {
    let live = mint(None);
    let dead = mint(Some(1));
    let (mut conn, script) = client(vec![
        (live.clone(), "a".to_owned()),
        (dead, "gone".to_owned()),
    ])
    .await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("declare the row subscription");
    first_sync(&mut conn, &script).await;

    // The expired grant was dropped by the first pass, so the replacement
    // presents the live grant alone and settles the generation.
    step_or_idle(&mut conn).await;
    let sent = replacement(&script);
    assert_eq!(
        sent.keys,
        vec![live],
        "the expired grant is not presented again"
    );
    settle(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

#[cfg(feature = "native-transport")]
#[tokio::test]
async fn a_rejected_secret_write_sends_no_replacement_and_preserves_local_access() {
    use connetto_client::{
        ClientError, MemoryRefreshStore, ShareKeyFuture, ShareKeySet, ShareKeyStore,
    };

    struct RefusingStore {
        inner: MemoryRefreshStore,
        refuse: Arc<AtomicBool>,
    }

    impl ShareKeyStore for RefusingStore {
        type Error = ClientError;

        fn load<'a>(
            &'a self,
            record: &'a str,
        ) -> ShareKeyFuture<'a, Option<ShareKeySet>, ClientError> {
            ShareKeyStore::load(&self.inner, record)
        }

        fn save<'a>(
            &'a self,
            record: &'a str,
            set: &'a ShareKeySet,
        ) -> ShareKeyFuture<'a, (), ClientError> {
            if self.refuse.load(Ordering::Acquire) {
                Box::pin(ready(Err(ClientError::Auth(
                    "secret write refused".to_owned(),
                ))))
            } else {
                ShareKeyStore::save(&self.inner, record, set)
            }
        }

        fn clear<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, (), ClientError> {
            ShareKeyStore::clear(&self.inner, record)
        }

        fn protection(&self) -> connetto_core::custody::Custody {
            ShareKeyStore::protection(&self.inner)
        }
    }

    let credential = super::support::held("tester");
    let keys = super::support::key_store(&credential).await;
    let directory = tempfile::tempdir().expect("replica directory");
    let refuse = Arc::new(AtomicBool::new(false));
    let mut conn = ClientBuilder::new(schema(), super::support::NeverDial::<Script>::default())
        .with_share_keys([(mint(None), CapabilitySubject::<String>::new("a"))])
        .signed_in(credential)
        .durable(
            connetto_client::DataDir::new(directory.path().to_path_buf()),
            keys,
            RefusingStore {
                inner: MemoryRefreshStore::default(),
                refuse: Arc::clone(&refuse),
            },
        )
        .open_driven()
        .await
        .expect("open durable replica");
    let script = Script::default();
    script.say(ack());
    conn.attach(script.clone()).await.expect("attach");
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe");
    first_sync(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));

    refuse.store(true, Ordering::Release);
    assert!(matches!(
        conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
            .await,
        Err(ClientError::Auth(_))
    ));
    step_or_idle(&mut conn).await;
    assert!(
        script.replacements.lock().is_empty(),
        "a rejected change sends no replacement"
    );

    refuse.store(false, Ordering::Release);
    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("c"))
        .await
        .expect("accept another subject");
    step_or_idle(&mut conn).await;
    assert_eq!(replacement(&script).keys, vec![mint(None), mint(None)]);
    assert_eq!(
        diesel::select(current_app_subjects())
            .get_result::<Option<String>>(conn.conn())
            .expect("read accepted subjects"),
        Some("a,c".to_owned()),
    );
}

diesel::define_sql_function! {
    fn current_app_subjects() -> diesel::sql_types::Nullable<diesel::sql_types::Text>;
}

#[tokio::test]
async fn a_failed_coverage_write_must_be_retried_before_accepting_a_key() {
    use diesel::connection::SimpleConnection as _;

    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe");
    first_sync(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER refuse_coverage BEFORE UPDATE ON _connetto_meta \
         WHEN NEW.cursor_subjects IS NULL \
         BEGIN SELECT RAISE(ABORT, 'coverage refused'); END;",
        )
        .expect("refuse the metadata write");
    let subject = CapabilitySubject::<String>::new("b");
    assert!(matches!(
        conn.add_share_key(&mint(None), &subject).await,
        Err(connetto_client::ClientError::Protocol(_))
    ));
    conn.conn()
        .batch_execute("DROP TRIGGER refuse_coverage")
        .expect("allow metadata writes");
    conn.add_share_key(&mint(None), &subject)
        .await
        .expect("accept the key after recovery");
    assert_eq!(
        coverage(&mut conn),
        None,
        "unknown is durable before the key is accepted"
    );
}

#[tokio::test]
async fn expiry_retries_failed_coverage_before_replacing_the_held_set() {
    use diesel::connection::SimpleConnection as _;

    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_secs()
        + 2;
    let (mut conn, script) = client(vec![(
        mint(Some(i64::try_from(expires).expect("expiry fits"))),
        "a".to_owned(),
    )])
    .await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe");
    first_sync(&mut conn, &script).await;
    conn.conn()
        .batch_execute(
            "CREATE TRIGGER refuse_expiry BEFORE UPDATE ON _connetto_meta \
         WHEN NEW.cursor_subjects IS NULL \
         BEGIN SELECT RAISE(ABORT, 'coverage refused'); END;",
        )
        .expect("refuse the metadata write");
    tokio::time::sleep(
        conn.share_key_timer().expect("expiry timer").wait() + Duration::from_millis(20),
    )
    .await;
    assert!(conn.process_share_keys(true).await.is_err());
    conn.conn()
        .batch_execute("DROP TRIGGER refuse_expiry")
        .expect("allow metadata writes");
    assert!(
        conn.process_share_keys(true)
            .await
            .expect("retry the expiry")
    );
    assert_eq!(
        diesel::select(current_app_subjects())
            .get_result::<Option<String>>(conn.conn())
            .expect("read subjects")
            .unwrap_or_default(),
        "",
    );
    assert_eq!(coverage(&mut conn), None);
    step_or_idle(&mut conn).await;
    assert_eq!(replacement(&script).keys, [] as [Grant; 0]);
}

#[tokio::test]
async fn offline_changes_present_only_the_accepted_set_on_the_next_handshake() {
    let removed = Grant::new("opaque-removed");
    let retained = Grant::new("opaque-retained");
    let (mut conn, script) = client(vec![(removed, "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe");
    first_sync(&mut conn, &script).await;
    conn.disconnect();
    conn.remove_share_key(&CapabilitySubject::<String>::new("a"))
        .await
        .expect("remove offline");
    conn.add_share_key(&retained, &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add offline");

    let next = Script::default();
    next.say(ack());
    tokio::time::timeout(Duration::from_secs(5), conn.attach(next.clone()))
        .await
        .expect("bounded handshake")
        .expect("attach");
    let handshake = next
        .handshakes
        .lock()
        .last()
        .cloned()
        .expect("handshake sent");
    assert_eq!(handshake.grants, vec![Grant::new("user:tester"), retained]);
    assert_eq!(handshake.last_cursor, Some(Cursor::from(CURSOR.to_vec())));
    assert_eq!(handshake.cursor_subjects, None);
    assert_eq!(coverage(&mut conn), None);
    next.say(snapshot_end("s1"));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["b"])));
}

fn aggregate_bootstrap() -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::AggregateUpdate(AggregateUpdate {
        sub_id: "agg".to_owned(),
        group_key: None,
        group_values_json: None,
        result_json: Some("3".to_owned()),
        is_full_result: true,
    }))
}

#[tokio::test]
async fn a_replacement_answer_does_not_settle_a_later_computed_declaration() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add");
    step_or_idle(&mut conn).await;
    let request_id = replacement(&script).request_id;
    conn.subscribe("agg", "SELECT COUNT(*) FROM notes")
        .await
        .expect("subscribe computed");
    step_or_idle(&mut conn).await;
    let nonce = *script.pings.lock().last().expect("declaration fence sent");
    script.say(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
        ShareKeysReplaced { request_id },
    )));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), None);
    script.say(aggregate_bootstrap());
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), None);
    script.say(pong(nonce));
    pump(&mut conn, Duration::from_secs(5)).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a", "b"])));
}

#[tokio::test]
async fn refused_computed_declarations_keep_coverage_unknown_until_retired() {
    for response in [
        ControlMessage::NonFatalError(connetto_core::messages::NonFatalError {
            related_to: Some("agg".to_owned()),
            detail: "subscription refused".to_owned(),
        }),
        ControlMessage::RateLimited(RateLimited {
            related_to: Some("agg".to_owned()),
            retry_after_ms: 100,
        }),
    ] {
        let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
        conn.subscribe("s1", "SELECT * FROM notes")
            .await
            .expect("subscribe rows");
        first_sync(&mut conn, &script).await;
        conn.subscribe("agg", "SELECT COUNT(*) FROM notes")
            .await
            .expect("subscribe computed");
        script.say(IncomingFrame::Control(response));
        pump(&mut conn, Duration::from_secs(5)).await;
        let nonce = *script.pings.lock().last().expect("declaration fence sent");
        script.say(pong(nonce));
        pump(&mut conn, Duration::from_secs(5)).await;
        assert_eq!(coverage(&mut conn), None);
        conn.unsubscribe("agg")
            .await
            .expect("retire the refused declaration");
        step_or_idle(&mut conn).await;
        assert_eq!(coverage(&mut conn), Some(known(&["a"])));
    }
}

#[tokio::test]
async fn an_elapsed_retry_waits_for_the_declaration_fence_without_spinning() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add a key");
    step_or_idle(&mut conn).await;
    let first = replacement(&script);
    script.say(IncomingFrame::Control(ControlMessage::RateLimited(
        RateLimited {
            related_to: Some(first.request_id.clone()),
            retry_after_ms: 300,
        },
    )));
    pump(&mut conn, Duration::from_secs(5)).await;
    conn.subscribe("agg", "SELECT COUNT(*) FROM notes")
        .await
        .expect("subscribe computed");
    script.say(aggregate_bootstrap());
    pump(&mut conn, Duration::from_secs(5)).await;
    let nonce = *script.pings.lock().last().expect("declaration fence");
    tokio::time::sleep(
        conn.share_key_timer().expect("retry timer").wait() + Duration::from_millis(20),
    )
    .await;
    conn.process_share_keys(true)
        .await
        .expect("process elapsed retry");
    assert!(
        conn.share_key_timer().expect("fence deadline").wait() >= Duration::from_secs(20),
        "an elapsed retry must wait for the outstanding fence"
    );
    assert_eq!(script.replacements.lock().len(), 1);
    script.say(pong(nonce));
    pump(&mut conn, Duration::from_secs(5)).await;
    step_or_idle(&mut conn).await;
    let retried = replacement(&script);
    assert_ne!(retried.request_id, first.request_id);
    assert_eq!(retried.keys, first.keys);
    assert_eq!(script.replacements.lock().len(), 2);
}

#[tokio::test]
async fn refused_row_declarations_keep_coverage_unknown_until_retired() {
    for response in [
        ControlMessage::NonFatalError(connetto_core::messages::NonFatalError {
            related_to: Some("refused".to_owned()),
            detail: "subscription refused".to_owned(),
        }),
        ControlMessage::RateLimited(RateLimited {
            related_to: Some("refused".to_owned()),
            retry_after_ms: 100,
        }),
    ] {
        let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
        conn.subscribe("s1", "SELECT * FROM notes")
            .await
            .expect("subscribe rows");
        first_sync(&mut conn, &script).await;
        conn.subscribe("refused", "SELECT id FROM notes")
            .await
            .expect("declare another query");
        script.say(IncomingFrame::Control(response));
        pump(&mut conn, Duration::from_secs(5)).await;
        assert_eq!(coverage(&mut conn), None);
        conn.unsubscribe("refused")
            .await
            .expect("retire refused query");
        step_or_idle(&mut conn).await;
        assert_eq!(coverage(&mut conn), Some(known(&["a"])));
    }
}

#[tokio::test]
async fn unrelated_replacement_answers_cannot_settle_the_current_generation() {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    for with_request in [false, true] {
        if with_request {
            conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
                .await
                .expect("add a key");
            step_or_idle(&mut conn).await;
        }
        script.say(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
            ShareKeysReplaced {
                request_id: "foreign-replacement".to_owned(),
            },
        )));
        let result = tokio::time::timeout(Duration::from_secs(5), conn.pump_one())
            .await
            .expect("bounded foreign answer");
        assert!(matches!(
            result,
            Err(connetto_client::ClientError::Protocol(_))
        ));
        assert_eq!(
            coverage(&mut conn),
            if with_request {
                None
            } else {
                Some(known(&["a"]))
            }
        );
    }
    settle(&mut conn, &script).await;
    assert_eq!(coverage(&mut conn), Some(known(&["a", "b"])));
    assert_eq!(script.replacements.lock().len(), 1);
}

#[tokio::test]
async fn identical_additions_and_absent_removals_preserve_completed_coverage() {
    let held = mint(None);
    let (mut conn, script) = client(vec![(held.clone(), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    conn.add_share_key(&held, &CapabilitySubject::<String>::new("a"))
        .await
        .expect("add an identical pair");
    conn.remove_share_key(&CapabilitySubject::<String>::new("absent"))
        .await
        .expect("remove an absent subject");
    step_or_idle(&mut conn).await;
    assert!(script.replacements.lock().is_empty());
    assert_eq!(coverage(&mut conn), Some(known(&["a"])));
}

async fn unanswered_request_disconnects(computed: bool) {
    let (mut conn, script) = client(vec![(mint(None), "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    if computed {
        conn.subscribe("agg", "SELECT COUNT(*) FROM notes")
            .await
            .expect("subscribe computed");
    } else {
        conn.add_share_key(&mint(None), &CapabilitySubject::<String>::new("b"))
            .await
            .expect("add a key");
    }
    step_or_idle(&mut conn).await;
    assert_eq!(coverage(&mut conn), None);
    let timer = conn.share_key_timer().expect("answer deadline");
    tokio::time::timeout(Duration::from_secs(35), async {
        tokio::time::sleep(timer.wait() + Duration::from_millis(20)).await;
        conn.process_share_keys(true)
            .await
            .expect("process unanswered request");
    })
    .await
    .expect("bounded request timeout");
    assert!(matches!(
        conn.ping(42).await,
        Err(connetto_client::ClientError::NotConnected)
    ));
    assert_eq!(coverage(&mut conn), None);
    let next = Script::default();
    next.say(ack());
    tokio::time::timeout(Duration::from_secs(5), conn.attach(next.clone()))
        .await
        .expect("bounded reattach")
        .expect("reattach after timeout");
    assert_eq!(
        next.handshakes
            .lock()
            .last()
            .expect("resume handshake")
            .cursor_subjects,
        None
    );
}

#[tokio::test]
async fn unanswered_replacements_and_fences_disconnect_without_publishing_coverage() {
    tokio::join!(
        unanswered_request_disconnects(false),
        unanswered_request_disconnects(true)
    );
}

#[tokio::test]
async fn expiry_preempts_a_rate_limit_without_retrying_the_replacement_early() {
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_secs()
        + 3;
    let expiring = mint(Some(i64::try_from(expires).expect("expiry fits")));
    let retained = Grant::new("retained");
    let (mut conn, script) = client(vec![(expiring, "a".to_owned())]).await;
    conn.subscribe("s1", "SELECT * FROM notes")
        .await
        .expect("subscribe rows");
    first_sync(&mut conn, &script).await;
    conn.add_share_key(&retained, &CapabilitySubject::<String>::new("b"))
        .await
        .expect("add retained key");
    step_or_idle(&mut conn).await;
    let first = replacement(&script);
    script.say(IncomingFrame::Control(ControlMessage::RateLimited(
        RateLimited {
            related_to: Some(first.request_id),
            retry_after_ms: 5000,
        },
    )));
    pump(&mut conn, Duration::from_secs(5)).await;
    let timer = conn.share_key_timer().expect("expiry before retry");
    assert!(timer.wait() <= Duration::from_secs(3));
    tokio::time::sleep(timer.wait() + Duration::from_millis(20)).await;
    assert!(
        conn.process_share_keys(true)
            .await
            .expect("expire held key")
    );
    assert_eq!(
        diesel::select(current_app_subjects())
            .get_result::<Option<String>>(conn.conn())
            .expect("read live subjects"),
        Some("b".to_owned()),
    );
    step_or_idle(&mut conn).await;
    assert_eq!(script.replacements.lock().len(), 1);
    let retry = conn.share_key_timer().expect("remaining retry delay");
    tokio::time::sleep(retry.wait() + Duration::from_millis(20)).await;
    conn.process_share_keys(true)
        .await
        .expect("process retry deadline");
    step_or_idle(&mut conn).await;
    assert_eq!(replacement(&script).keys, vec![retained]);
    assert_eq!(script.replacements.lock().len(), 2);
}
