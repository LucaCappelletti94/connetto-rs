//! Share keys on a running session (R95): a held key leaves the session at its
//! expiry, and every subscription it reached is resent under the keys left.
//!
//! The snapshot stub writes the keys each read ran under into its patchset, so
//! a delivered page says which set it was read for. Needs Docker for the write
//! target the handshake reads its watermark from.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, Grant,
    Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    LoopbackTransport, ManagerBuilder, Materializer, NoConnector, PageSpec, SessionManager,
    SnapshotEstimate, SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
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

fn manager(
    fixture: &Fixture,
    snapshot: &KeyedSnapshot,
    initial_credits: Option<u32>,
    clock: &ExpiryClock,
) -> Manager {
    let builder = ManagerBuilder::new(
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
    match initial_credits {
        Some(credits) => builder
            .with_session(clock.session_config().with_initial_credits(credits))
            .build(),
        None => builder.with_session(clock.session_config()).build(),
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

async fn connect(manager: &Manager, grants: &[&str]) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(
        async move { server.serve(server_end).await }.instrument(tracing::Span::current()),
    );
    let handshake = Handshake::new(PROTOCOL_VERSION, "share-keys")
        .with_grants(grants.iter().map(|grant| Grant::new(*grant)));
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
            _ => "other",
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_key_leaves_the_session_at_its_expiry() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = ExpiryClock::new();
    let manager = manager(&fixture, &snapshot, None, &clock);
    let mut client = connect(&manager, &[&clock.grant("key:a"), "key:b"]).await;
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
    let manager = manager(&fixture, &snapshot, Some(0), &clock);
    let mut client = connect(&manager, &[&clock.grant("key:a"), "key:b"]).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbounded_grant_keeps_a_key_held_by_an_earlier_finite_grant() {
    let fixture = Fixture::acquire().await;
    let snapshot = KeyedSnapshot::default();
    let clock = super::share_key_clock::ExpiryClock::new();
    let finite = clock.grant("key:a");
    let other = clock.grant("key:c");
    let manager = manager(&fixture, &snapshot, None, &clock);
    let mut client = connect(&manager, &[finite.as_str(), "key:a", other.as_str()]).await;
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
    let manager = manager(&fixture, &snapshot, None, &clock);
    let mut client = connect(&manager, &["key:a", finite.as_str(), other.as_str()]).await;
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
    let manager = manager(&fixture, &snapshot, None, &clock);
    let mut client = connect(
        &manager,
        &[first.as_str(), "key:c@1003", "key:u", "key:a@1005"],
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
    let manager = manager(&fixture, &snapshot, None, &clock);
    let mut client = connect(
        &manager,
        &[
            "junk",
            "user:alice",
            finite.as_str(),
            "key:a",
            other.as_str(),
        ],
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
