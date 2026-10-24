//! Share keys changed on a running session (R95): the live swap, its metering,
//! a key dying at its expiry, and a resume whose keys changed while away.
//!
//! The snapshot stub writes the keys each read ran under into its patchset, so
//! a delivered page says which set it was read for. Needs Docker for the write
//! target the handshake reads its watermark from.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, Grant,
    Handshake, Ping, RateLimited, ReplaceShareKeys, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    AbuseConfig, InMemoryOplog, LoopbackTransport, ManagerBuilder, Materializer, NoConnector,
    PageSpec, Position, RequestGuard, SessionConfig, SessionManager, SnapshotEstimate,
    SnapshotPage, SnapshotSource, ThrottleConfig, TierLimits, TimelineHistory, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use subql::backend::CdcEvent;
use subql::{CdcSource, PgSqliteEmuSource, SourceItem};
use tracing::Instrument;

use super::share_key_clock::ExpiryClock;

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// Reads one page whose bytes are the keys the read ran under, and records
/// every caller it read for.
#[derive(Clone, Default)]
struct KeyedSnapshot {
    callers: Arc<Mutex<Vec<Principal>>>,
}

impl KeyedSnapshot {
    fn reads(&self) -> usize {
        self.callers.lock().expect("capture lock").len()
    }
    fn last(&self) -> Principal {
        self.callers
            .lock()
            .expect("capture lock")
            .last()
            .cloned()
            .expect("a read ran")
    }
}

fn keys_of(caller: &Principal) -> Vec<String> {
    caller
        .capabilities()
        .iter()
        .map(|key| key.key().clone())
        .collect()
}

impl SnapshotSource for KeyedSnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 1.0,
            width: 8,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        self.callers
            .lock()
            .expect("capture lock")
            .push(caller.clone());
        let patchset = keys_of(caller).join(",").into_bytes();
        let bytes = u64::try_from(patchset.len()).expect("a page length fits u64");
        Ok(SnapshotPage {
            patchset,
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: bytes,
            rows: 1,
            bytes,
        })
    }
}

type Manager = Arc<SessionManager<KeyedSnapshot, RosterAuth, ConnettoDefaults>>;

/// What one test changes about an otherwise default manager.
#[derive(Default)]
struct Settings {
    throttle: Option<ThrottleConfig>,
    initial_credits: Option<u32>,
    oplog: Option<InMemoryOplog>,
    session: Option<SessionConfig>,
}

fn manager(fixture: &Fixture, snapshot: &KeyedSnapshot, settings: Settings) -> Manager {
    let mut builder = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        snapshot.clone(),
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    );
    if let Some(throttle) = settings.throttle {
        builder = builder.with_guard(Arc::new(RequestGuard::new(
            throttle,
            AbuseConfig::default(),
        )));
    }
    let mut session = settings.session.unwrap_or_default();
    if let Some(credits) = settings.initial_credits {
        session = session.with_initial_credits(credits);
    }
    builder = builder.with_session(session);
    match settings.oplog {
        Some(oplog) => builder.with_oplog(oplog).build(),
        None => builder.build(),
    }
}

async fn next_frame<T: Transport>(transport: &mut T) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(10), transport.recv())
        .await
        .expect("a frame within ten seconds")
        .expect("recv frame")
        .expect("the connection is open")
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        if let IncomingFrame::Control(msg) = next_frame(transport).await {
            return msg;
        }
    }
}

/// Handshake with `grants`, resuming from `resume` taken under `cursor_subjects`.
async fn connect(
    manager: &Manager,
    grants: &[&str],
    resume: Option<(Cursor, &[&str])>,
) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(
        async move { server.serve(server_end).await }.instrument(tracing::Span::current()),
    );
    let mut handshake = Handshake::new(PROTOCOL_VERSION, "share-keys")
        .with_grants(grants.iter().map(|grant| Grant::new(*grant)));
    if let Some((cursor, subjects)) = resume {
        handshake = handshake
            .with_cursor(cursor)
            .with_cursor_subjects(subjects.iter().copied());
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected the handshake ack");
    };
    client
}

async fn subscribe<T: Transport>(client: &mut T, label: &str) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: label.to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
}

async fn swap<T: Transport>(client: &mut T, request_id: &str, keys: &[&str]) {
    client
        .send_control(ControlMessage::ReplaceShareKeys(ReplaceShareKeys {
            request_id: request_id.to_owned(),
            keys: keys.iter().map(|key| Grant::new(*key)).collect(),
        }))
        .await
        .expect("send swap");
}
/// The control frames up to and including the first `stop` accepts.
async fn controls_until<T: Transport>(
    client: &mut T,
    stop: impl Fn(&ControlMessage) -> bool,
) -> Vec<ControlMessage> {
    let mut seen = Vec::new();
    loop {
        let msg = next_control(client).await;
        let done = stop(&msg);
        seen.push(msg);
        if done {
            return seen;
        }
    }
}

fn is_answer(request_id: &str) -> impl Fn(&ControlMessage) -> bool + '_ {
    move |msg| matches!(msg, ControlMessage::ShareKeysReplaced(answer) if answer.request_id == request_id)
}
fn is_end(msg: &ControlMessage) -> bool {
    matches!(msg, ControlMessage::SnapshotEnd(_))
}

fn resync_of(label: &str) -> ControlMessage {
    ControlMessage::FullResyncRequired(FullResyncRequired {
        sub_id: label.to_owned(),
        reason: FullResyncReason::AuthorizationChange,
    })
}

/// The kind of each control frame, for asserting an order.
fn kinds(frames: &[ControlMessage]) -> Vec<&'static str> {
    frames
        .iter()
        .map(|frame| match frame {
            ControlMessage::FullResyncRequired(_) => "resync",
            ControlMessage::SnapshotBegin(_) => "begin",
            ControlMessage::SnapshotEnd(_) => "end",
            ControlMessage::ShareKeysReplaced(_) => "answer",
            ControlMessage::RateLimited(_) => "limited",
            ControlMessage::NonFatalError(_) => "refused",
            ControlMessage::Pong(_) => "pong",
            _ => "other",
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_swap_resends_the_subscription_under_the_new_keys_before_answering() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let manager = manager(&fixture, &snapshot, Settings::default());
    let mut client = connect(&manager, &["user:alice", "key:a"], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    swap(&mut client, "swap-1", &["key:b"]).await;
    let frames = controls_until(&mut client, is_answer("swap-1")).await;

    assert_eq!(kinds(&frames), ["resync", "begin", "end", "answer"]);
    assert_eq!(frames[0], resync_of("items"));
    let caller = snapshot.last();
    assert_eq!(keys_of(&caller), ["key:b"]);
    assert_eq!(
        caller.identity().map(|identity| identity.user_id.as_str()),
        Some("alice"),
        "a swap keeps the identity the handshake resolved"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_key_set_is_answered_without_a_resend() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let manager = manager(&fixture, &snapshot, Settings::default());
    let mut client = connect(&manager, &["key:a", "key:b"], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;
    let reads = snapshot.reads();

    swap(&mut client, "same", &["key:b", "key:a", "key:a"]).await;

    assert_eq!(
        kinds(&controls_until(&mut client, is_answer("same")).await),
        ["answer"]
    );
    assert_eq!(snapshot.reads(), reads, "nothing was read again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_grant_in_a_swap_is_dropped_without_a_word() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let manager = manager(&fixture, &snapshot, Settings::default());
    let mut client = connect(&manager, &["user:alice", "key:a"], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    swap(
        &mut client,
        "mixed",
        &["not-a-grant", "user:mallory", "key:b"],
    )
    .await;
    let frames = controls_until(&mut client, is_answer("mixed")).await;

    assert_eq!(kinds(&frames), ["resync", "begin", "end", "answer"]);
    let caller = snapshot.last();
    assert_eq!(keys_of(&caller), ["key:b"]);
    assert_eq!(
        caller.identity().map(|identity| identity.user_id.as_str()),
        Some("alice"),
        "a person named in a swap does not replace the one signed in"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_swap_over_the_subscription_limit_keeps_the_old_keys() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let window = Duration::from_secs(600);
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            throttle: Some(
                ThrottleConfig::new()
                    .with_anonymous(TierLimits::anonymous().with_subscriptions(1, window)),
            ),
            ..Settings::default()
        },
    );
    let mut client = connect(&manager, &["key:a"], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    swap(&mut client, "over", &["key:b"]).await;
    let refusal = next_control(&mut client).await;
    let ControlMessage::RateLimited(RateLimited { related_to, .. }) = refusal else {
        panic!("expected the swap to be limited, got {refusal:?}");
    };
    assert_eq!(related_to.as_deref(), Some("over"));

    // The old set still stands, so presenting it again changes nothing.
    swap(&mut client, "again", &["key:a"]).await;
    assert_eq!(
        kinds(&controls_until(&mut client, is_answer("again")).await),
        ["answer"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_key_leaves_the_session_at_its_expiry() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = ExpiryClock::new();
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(&manager, &[&clock.grant("key:a"), "key:b"], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;
    clock.advance(Duration::from_secs(1));

    let frames = controls_until(&mut client, is_end).await;

    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    assert_eq!(keys_of(&snapshot.last()), ["key:b"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_frames_of_an_expired_key_never_follow_the_resend() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = ExpiryClock::new();
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            initial_credits: Some(0),
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(&manager, &[&clock.grant("key:a"), "key:b"], None).await;
    subscribe(&mut client, "items").await;
    // With no credit the page and its end wait in the queue behind the begin.
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected the snapshot to begin");
    };
    clock.advance(Duration::from_secs(1));

    let frames = controls_until(&mut client, |msg| {
        matches!(msg, ControlMessage::SnapshotBegin(_))
    })
    .await;
    assert_eq!(kinds(&frames), ["resync", "begin"]);
    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 16 }))
        .await
        .expect("grant credit");

    let mut pages = Vec::new();
    loop {
        match next_frame(&mut client).await {
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) => pages.push(
                String::from_utf8(zstd::decode_all(patch.patchset_zstd.as_slice()).expect("zstd"))
                    .expect("utf-8"),
            ),
            IncomingFrame::Control(ControlMessage::SnapshotEnd(_)) => break,
            _ => {}
        }
    }
    assert_eq!(
        pages,
        ["key:b"],
        "only the page read under the keys left arrives"
    );
}

/// A cursor at the first change the oplog holds, so a resume catches up.
async fn resumable(manager: &Manager) -> Cursor {
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO items (id, label) VALUES (1, 'one')")
        .expect("execute dml");
    let mut first = None;
    while let Some(item) = source.next_item().await.expect("poll source") {
        let SourceItem::Event(event) = item else {
            continue;
        };
        manager.dispatch_event(&event).await.expect("dispatch");
        first = first.or_else(|| event.checkpoint());
    }
    Cursor::new(
        Position {
            system: TimelineHistory::default().system(),
            timeline: 1,
            at: first.expect("one event"),
        }
        .to_cursor_bytes(),
    )
}

/// The control frames a subscribe produced, up to the pong a ping behind it draws.
async fn subscribe_and_settle<T: Transport>(client: &mut T) -> Vec<ControlMessage> {
    subscribe(client, "items").await;
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send ping");
    controls_until(client, |msg| matches!(msg, ControlMessage::Pong(_))).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resume_under_other_keys_resends_instead_of_catching_up() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            oplog: Some(InMemoryOplog::default()),
            ..Settings::default()
        },
    );
    let cursor = resumable(&manager).await;

    let mut changed = connect(&manager, &["key:b"], Some((cursor.clone(), &["key:a"]))).await;
    let frames = subscribe_and_settle(&mut changed).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end", "pong"]);
    assert_eq!(frames[0], resync_of("items"));
    drop(changed);

    let reads = snapshot.reads();
    let mut same = connect(&manager, &["key:b"], Some((cursor, &["key:b"]))).await;
    let frames = subscribe_and_settle(&mut same).await;
    assert_eq!(
        kinds(&frames),
        ["end", "pong"],
        "the same keys catch up from the log, and the empty catchup still completes"
    );
    assert_eq!(snapshot.reads(), reads);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbounded_grant_keeps_a_key_held_by_an_earlier_finite_grant() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = super::share_key_clock::ExpiryClock::new();
    let finite = clock.grant("key:a");
    let other = clock.grant("key:c");
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(&manager, &[finite.as_str(), "key:a", other.as_str()], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    clock.advance(Duration::from_secs(1));
    let frames = controls_until(&mut client, is_end).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    assert_eq!(
        keys_of(&snapshot.last()),
        ["key:a"],
        "the unbounded grant outranks the finite one and the other key died"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbounded_grant_keeps_a_key_held_by_a_later_finite_grant() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = super::share_key_clock::ExpiryClock::new();
    let finite = clock.grant("key:a");
    let other = clock.grant("key:c");
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(&manager, &["key:a", finite.as_str(), other.as_str()], None).await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    clock.advance(Duration::from_secs(1));
    let frames = controls_until(&mut client, is_end).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    assert_eq!(
        keys_of(&snapshot.last()),
        ["key:a"],
        "the unbounded grant outranks the later finite one and the other key died"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_finite_grants_die_at_the_latest_expiry() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = super::share_key_clock::ExpiryClock::new();
    // The clock starts at unix second 1000, so the hardcoded expiries spell that fixed start.
    let first = clock.grant("key:a");
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(
        &manager,
        &[first.as_str(), "key:c@1003", "key:u", "key:a@1005"],
        None,
    )
    .await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    clock.advance(Duration::from_secs(4));
    let frames = controls_until(&mut client, is_end).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    assert_eq!(
        keys_of(&snapshot.last()),
        ["key:a", "key:u"],
        "the earlier expiry of the duplicated key lost to the later one"
    );

    clock.advance(Duration::from_secs(2));
    let frames = controls_until(&mut client, is_end).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    assert_eq!(
        keys_of(&snapshot.last()),
        ["key:u"],
        "the later expiry still dies the duplicated key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_and_refused_grants_never_touch_the_key_lifetimes() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = super::share_key_clock::ExpiryClock::new();
    let finite = clock.grant("key:a");
    let other = clock.grant("key:c");
    let manager = manager(
        &fixture,
        &snapshot,
        Settings {
            session: Some(clock.session_config()),
            ..Settings::default()
        },
    );
    let mut client = connect(
        &manager,
        &[
            "junk",
            "user:alice",
            finite.as_str(),
            "key:a",
            other.as_str(),
        ],
        None,
    )
    .await;
    subscribe(&mut client, "items").await;
    controls_until(&mut client, is_end).await;

    clock.advance(Duration::from_secs(1));
    let frames = controls_until(&mut client, is_end).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end"]);
    assert_eq!(frames[0], resync_of("items"));
    let caller = snapshot.last();
    assert_eq!(
        caller.identity().map(|context| context.user_id.as_str()),
        Some("alice"),
        "the identity grant resolved into the caller"
    );
    assert_eq!(
        keys_of(&caller),
        ["key:a"],
        "neither the refused grant nor the identity touched the key's lifetime"
    );
}

#[path = "share_key_admission.rs"]
mod admission;

#[path = "share_key_checkpoint.rs"]
mod checkpoint;
