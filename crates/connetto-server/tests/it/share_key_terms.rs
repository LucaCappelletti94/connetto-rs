//! Subject-dependent membership survives key expiry without retaining expired reach.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::DEFAULT_USER_SETTING;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, Grant, Handshake, Ping, SUBSCRIPTION_REFUSED,
    Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::openfga::Translated;
use connetto_server::{
    LoopbackTransport, ManagerBuilder, Materializer, NoConnector, PgSnapshotSource,
    RuntimeWritableCatalog, SessionManager, loopback, pg_write_target, subject_set_reach,
};
use connetto_test_harness::fanout::caller_mapping;
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth};
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value};
use subql::{CdcSource, PgSqliteEmuSource, SourceItem};

use super::share_key_clock::ExpiryClock;

const DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, team_id INT NOT NULL, label TEXT); \
    CREATE TABLE team_members (team_id INT NOT NULL, member TEXT NOT NULL, \
    PRIMARY KEY (team_id, member));";
const POLICIES: &str = "ALTER TABLE items ENABLE ROW LEVEL SECURITY; \
    CREATE POLICY items_p ON items USING (team_id IN \
    (SELECT team_id FROM team_members WHERE member = ANY(string_to_array(\
    current_setting('app.subjects', true), ','))));";
const PUBLICATION: &str = "share_key_terms_pub";
const LABEL: &str = "member-items";
type Manager = Arc<SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults>>;

async fn manager(fixture: &Fixture, clock: &ExpiryClock) -> Manager {
    fixture
        .setup(&[
            DDL,
            "INSERT INTO items VALUES (11, 1, 'expires'), (22, 2, 'retained')",
            "INSERT INTO team_members VALUES (1, 'key:a'), (2, 'key:b')",
            "CREATE PUBLICATION share_key_terms_pub FOR TABLE items, team_members",
        ])
        .await;
    let (_, translator, _) =
        Translated::of::<String, connetto_core::bots::TextIds>(DDL, POLICIES, DEFAULT_USER_SETTING)
            .expect("the membership policy translates")
            .into_parts();
    ManagerBuilder::new(
        Materializer::builder(DDL)
            .with_write_catalog(RuntimeWritableCatalog::default())
            .with_translator(translator)
            .with_caller(caller_mapping())
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(fixture.admin().clone(), DDL)
            .expect("snapshot source")
            .with_publication(PUBLICATION),
        RosterAuth::granting("key:b"),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), DDL).expect("write target"),
    )
    .with_session(clock.session_config())
    .build()
}

async fn next_frame(client: &mut LoopbackTransport) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(15), client.recv())
        .await
        .expect("a frame within fifteen seconds")
        .expect("receive frame")
        .expect("the session remains open")
}

async fn connect(manager: &Manager, clock: &ExpiryClock) -> LoopbackTransport {
    let (server, mut client) = loopback();
    let manager = Arc::clone(manager);
    tokio::spawn(async move { manager.serve(server).await });
    let dying = clock.grant("key:a");
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "key-terms")
                .with_grants([Grant::new(dying), Grant::new("key:b")]),
        ))
        .await
        .expect("send handshake");
    assert!(matches!(
        next_frame(&mut client).await,
        IncomingFrame::Control(ControlMessage::Challenge(_))
    ));
    assert!(matches!(
        next_frame(&mut client).await,
        IncomingFrame::Control(ControlMessage::HandshakeAck(_))
    ));
    client
}

async fn subscribe(client: &mut LoopbackTransport, label: &str, query: &str) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: label.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("subscribe");
}

fn membership_query() -> String {
    let reach = subject_set_reach("current_app_subjects", "member", ',');
    format!("SELECT * FROM items WHERE team_id IN (SELECT team_id FROM team_members WHERE {reach})")
}

fn inserted_ids(bytes: &[u8]) -> Vec<i64> {
    let bytes = zstd::decode_all(bytes).expect("decompress patch");
    let ParsedDiffSet::Patchset(patch) = ParsedDiffSet::parse(&bytes).expect("parse patch") else {
        panic!("expected patchset");
    };
    patch
        .iter()
        .map(|op| match op {
            PatchsetOp::Insert { values, .. } => match values.first() {
                Some(Value::Integer(id)) => *id,
                other => panic!("expected integer primary key, got {other:?}"),
            },
            other => panic!("expected insert, got {other:?}"),
        })
        .collect()
}

async fn snapshot_ids(client: &mut LoopbackTransport, label: &str) -> Vec<i64> {
    let mut ids = Vec::new();
    loop {
        match next_frame(client).await {
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) if patch.sub_id == label => {
                ids.extend(inserted_ids(&patch.patchset_zstd));
            }
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == label => {
                ids.sort_unstable();
                return ids;
            }
            IncomingFrame::Control(ControlMessage::NonFatalError(err)) => {
                panic!("subscription refused, {err:?}");
            }
            _ => {}
        }
    }
}

async fn through_pong(client: &mut LoopbackTransport, nonce: u64) -> Vec<IncomingFrame> {
    client
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send fence");
    let mut frames = Vec::new();
    loop {
        let frame = next_frame(client).await;
        if let IncomingFrame::Control(ControlMessage::Pong(pong)) = &frame {
            assert_eq!(pong.nonce, nonce);
            return frames;
        }
        frames.push(frame);
    }
}

async fn dispatch(manager: &Manager, statements: &[&str]) {
    let mut source = PgSqliteEmuSource::open_in_memory(DDL).expect("open change source");
    for statement in statements {
        source.execute_sql(statement).expect("execute change");
        while let Some(item) = source.next_item().await.expect("read changes") {
            if let SourceItem::Event(event) = item {
                manager
                    .dispatch_event(&event)
                    .await
                    .expect("dispatch change");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_subject_loses_its_membership_snapshot_and_live_rows() {
    let fixture = Fixture::acquire().await;
    let clock = ExpiryClock::new();
    let manager = manager(&fixture, &clock).await;
    let mut client = connect(&manager, &clock).await;
    subscribe(&mut client, LABEL, &membership_query()).await;
    assert_eq!(snapshot_ids(&mut client, LABEL).await, [11, 22]);
    let initial = through_pong(&mut client, 101).await;
    let hidden = initial
        .iter()
        .find_map(|frame| match frame {
            IncomingFrame::Control(ControlMessage::MembershipOpened(opened)) => {
                Some(opened.sub_id.clone())
            }
            _ => None,
        })
        .expect("the membership mirror opens");
    clock.advance(Duration::from_secs(1));

    let mut notices = Vec::new();
    let mut ended = Vec::new();
    let mut replacement = Vec::new();
    while ended.len() != 2 {
        match next_frame(&mut client).await {
            IncomingFrame::Control(ControlMessage::FullResyncRequired(notice)) => {
                assert!(notice.sub_id == LABEL || notice.sub_id == hidden);
                assert_eq!(notice.reason, FullResyncReason::AuthorizationChange);
                notices.push(notice.sub_id);
            }
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) if patch.sub_id == LABEL => {
                replacement.extend(inserted_ids(&patch.patchset_zstd));
            }
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) => {
                assert!(notices.contains(&end.sub_id));
                assert!(!ended.contains(&end.sub_id));
                ended.push(end.sub_id);
            }
            IncomingFrame::Control(ControlMessage::NonFatalError(err)) => {
                panic!("membership replacement refused, {err:?}");
            }
            _ => {}
        }
    }
    assert_eq!(replacement, [22]);

    dispatch(
        &manager,
        &[
            "INSERT INTO items VALUES (31, 1, 'expired-late')",
            "INSERT INTO items VALUES (32, 2, 'retained-late')",
        ],
    )
    .await;
    let IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) = next_frame(&mut client).await else {
        panic!("the retained subject must still receive live rows");
    };
    assert_eq!(patch.sub_id, LABEL);
    assert_eq!(
        inserted_ids(&patch.patchset_zstd),
        [32],
        "the expired subject cannot admit later rows"
    );
    assert_eq!(through_pong(&mut client, 103).await, []);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_membership_reseed_refuses_the_subscription_and_removes_its_routes() {
    let fixture = Fixture::acquire().await;
    let clock = ExpiryClock::new();
    let manager = manager(&fixture, &clock).await;
    let mut client = connect(&manager, &clock).await;
    subscribe(&mut client, LABEL, &membership_query()).await;
    assert_eq!(snapshot_ids(&mut client, LABEL).await, [11, 22]);
    through_pong(&mut client, 201).await;
    fixture.exec("DROP PUBLICATION share_key_terms_pub").await;
    clock.advance(Duration::from_secs(1));

    let refusal = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let IncomingFrame::Control(ControlMessage::NonFatalError(refusal)) =
                next_frame(&mut client).await
                && refusal.related_to.as_deref() == Some(LABEL)
            {
                break refusal;
            }
        }
    })
    .await
    .expect("expiry refuses the unseedable membership");
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
    subscribe(&mut client, "still-open", "SELECT * FROM items").await;
    assert_eq!(snapshot_ids(&mut client, "still-open").await, [11, 22]);
    dispatch(
        &manager,
        &[
            "INSERT INTO team_members VALUES (3, 'key:b')",
            "INSERT INTO items VALUES (32, 2, 'late')",
        ],
    )
    .await;
    let frame = tokio::time::timeout(Duration::from_secs(10), next_frame(&mut client))
        .await
        .expect("the surviving subscription delivers a live row");
    let IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) = frame else {
        panic!("the surviving subscription must still receive live rows");
    };
    assert_eq!(patch.sub_id, "still-open");
    assert_eq!(inserted_ids(&patch.patchset_zstd), [32]);
    assert_eq!(through_pong(&mut client, 202).await, []);
}
