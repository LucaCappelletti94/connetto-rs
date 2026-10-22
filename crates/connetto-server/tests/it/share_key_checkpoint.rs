use std::collections::BTreeSet;
use std::sync::OnceLock;

use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value};

use super::*;

const ROWS: &str = "INSERT INTO items VALUES (1, 'key:a'), (2, 'key:b'), (3, 'public')";

type CheckpointManager = Arc<SessionManager<SnapshotAtLogPosition, RosterAuth, ConnettoDefaults>>;

struct SnapshotAtLogPosition {
    inner: connetto_server::PgSnapshotSource,
    cursor: Arc<OnceLock<Cursor>>,
}

impl SnapshotSource for SnapshotAtLogPosition {
    type Error = <connetto_server::PgSnapshotSource as SnapshotSource>::Error;

    async fn estimate(
        &self,
        sql: &str,
        binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        self.inner.estimate(sql, binds, caller).await
    }

    async fn snapshot_page(
        &self,
        sql: &str,
        binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let mut page = self.inner.snapshot_page(sql, binds, caller, page).await?;
        page.cursor = self.cursor.get().expect("the fixture has a cursor").clone();
        Ok(page)
    }
}

async fn manager(fixture: &Fixture, credits: u32) -> (CheckpointManager, Cursor) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS items CASCADE",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
            "CREATE TABLE items (id INT PRIMARY KEY, label TEXT)",
            "ALTER TABLE items ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY items_p ON items USING (label = 'public' OR label = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT SELECT ON items TO app_reader",
        ])
        .await;
    fixture.exec(ROWS).await;
    let reader = connetto_test_harness::pool_for(&connetto_test_harness::with_user(
        fixture.admin_url(),
        "app_reader",
        "app_reader",
    ))
    .await;
    let cursor = Arc::new(OnceLock::new());
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL).build().expect("materializer"),
        SnapshotAtLogPosition {
            inner: connetto_server::PgSnapshotSource::from_ddl(reader, PG_DDL)
                .expect("RLS snapshot source"),
            cursor: Arc::clone(&cursor),
        },
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL).expect("write target"),
    )
    .with_oplog(InMemoryOplog::default())
    .with_session(SessionConfig::new().with_initial_credits(credits))
    .build();
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("emulated source");
    source.execute_sql(ROWS).expect("source rows");
    let mut at = None;
    while let Some(item) = source.next_item().await.expect("source event") {
        if let SourceItem::Event(event) = item {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch event");
            at = event.checkpoint();
        }
    }
    let position = Cursor::new(
        Position {
            system: TimelineHistory::default().system(),
            timeline: 1,
            at: at.expect("source position"),
        }
        .to_cursor_bytes(),
    );
    cursor.set(position.clone()).expect("initialize cursor");
    (manager, position)
}

async fn connect(
    manager: &CheckpointManager,
    keys: &[&str],
    resume: Option<(&Cursor, Option<&[&str]>)>,
) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(async move { server.serve(server_end).await });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, "checkpoint")
        .with_grants(keys.iter().map(|key| Grant::new(*key)));
    if let Some((cursor, subjects)) = resume {
        handshake = handshake.with_cursor(cursor.clone());
        if let Some(subjects) = subjects {
            handshake = handshake.with_cursor_subjects(subjects.iter().copied());
        }
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::Challenge(_)
    ));
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::HandshakeAck(_)
    ));
    client
}

fn ids(payload: &[u8]) -> BTreeSet<i64> {
    let bytes = zstd::decode_all(payload).expect("decompress snapshot");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("patchset") else {
        panic!("a snapshot carries a patchset");
    };
    set.iter()
        .filter_map(|op| match op {
            PatchsetOp::Insert { values, .. } => match values.first() {
                Some(Value::Integer(id)) => Some(*id),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

async fn read_query(
    client: &mut LoopbackTransport,
    label: &str,
    sql: &str,
    nonce: u64,
) -> (BTreeSet<i64>, bool) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: label.to_owned(),
            spec: SubscriptionSpec::new(sql),
        }))
        .await
        .expect("send subscription");
    client
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send replay fence");
    let mut rows = BTreeSet::new();
    let mut resynced = false;
    loop {
        match next_frame(client).await {
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) => {
                assert_eq!(patch.sub_id, label);
                rows.extend(ids(&patch.patchset_zstd));
            }
            IncomingFrame::Control(ControlMessage::FullResyncRequired(notice)) => {
                assert_eq!(notice.sub_id, label);
                assert_eq!(notice.reason, FullResyncReason::AuthorizationChange);
                resynced = true;
            }
            IncomingFrame::Control(ControlMessage::Pong(pong)) if pong.nonce == nonce => {
                return (rows, resynced);
            }
            _ => {}
        }
    }
}

async fn swap_without_credit(client: &mut LoopbackTransport, id: &str, keys: &[&str]) {
    swap(client, id, keys).await;
    loop {
        match next_frame(client).await {
            IncomingFrame::Control(ControlMessage::ShareKeysReplaced(answer)) => {
                assert_eq!(answer.request_id, id);
                return;
            }
            IncomingFrame::Bulk(_) | IncomingFrame::Control(ControlMessage::SnapshotEnd(_)) => {
                panic!("replacement delivery waits for credit");
            }
            IncomingFrame::Control(_) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_removal_restores_public_rows_from_an_unknown_checkpoint() {
    let fixture = Fixture::acquire().await;
    let (manager, cursor) = manager(&fixture, 1).await;
    let mut original = connect(&manager, &["key:a"], None).await;
    assert_eq!(
        read_query(&mut original, "items", "SELECT * FROM items", 101)
            .await
            .0,
        BTreeSet::from([1, 3]),
    );
    swap_without_credit(&mut original, "remove", &[]).await;
    drop(original);

    let mut resumed = connect(&manager, &[], Some((&cursor, None))).await;
    let (rows, resynced) = read_query(&mut resumed, "items", "SELECT * FROM items", 102).await;
    assert!(resynced, "unknown coverage requires a replacement");
    assert_eq!(rows, BTreeSet::from([3]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_known_empty_checkpoint_retains_ordinary_catchup() {
    let fixture = Fixture::acquire().await;
    let (manager, cursor) = manager(&fixture, 1).await;
    let mut original = connect(&manager, &[], None).await;
    assert_eq!(
        read_query(&mut original, "items", "SELECT * FROM items", 103)
            .await
            .0,
        BTreeSet::from([3]),
    );
    drop(original);

    let mut resumed = connect(&manager, &[], Some((&cursor, Some(&[])))).await;
    let (rows, resynced) = read_query(&mut resumed, "items", "SELECT * FROM items", 104).await;
    assert!(!resynced);
    assert!(rows.is_empty(), "no changes follow the covered cursor");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_replacements_restore_each_subscription_after_repeated_key_changes() {
    let fixture = Fixture::acquire().await;
    let (manager, cursor) = manager(&fixture, 2).await;
    let left = "SELECT * FROM items WHERE id < 3";
    let right = "SELECT * FROM items WHERE id > 1";
    let mut original = connect(&manager, &["key:a"], None).await;
    assert_eq!(
        read_query(&mut original, "left", left, 105).await.0,
        BTreeSet::from([1])
    );
    assert_eq!(
        read_query(&mut original, "right", right, 106).await.0,
        BTreeSet::from([3])
    );
    swap_without_credit(&mut original, "to-b", &["key:b"]).await;
    drop(original);

    let mut first = connect(&manager, &["key:b"], Some((&cursor, None))).await;
    assert_eq!(
        read_query(&mut first, "left", left, 107).await,
        (BTreeSet::from([2]), true)
    );
    assert_eq!(
        read_query(&mut first, "right", right, 108).await,
        (BTreeSet::from([2, 3]), true)
    );
    swap_without_credit(&mut first, "to-a", &["key:a"]).await;
    swap_without_credit(&mut first, "back-to-b", &["key:b"]).await;
    drop(first);

    let mut second = connect(&manager, &["key:b"], Some((&cursor, None))).await;
    assert_eq!(
        read_query(&mut second, "left", left, 109).await,
        (BTreeSet::from([2]), true)
    );
    assert_eq!(
        read_query(&mut second, "right", right, 110).await,
        (BTreeSet::from([2, 3]), true)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_change_invalidates_known_coverage_for_subscriptions_replayed_later() {
    let fixture = Fixture::acquire().await;
    let (manager, cursor) = manager(&fixture, 2).await;
    let public = "SELECT * FROM items WHERE id = 3";
    let private = "SELECT * FROM items WHERE id < 3";
    let mut original = connect(&manager, &["key:b"], None).await;
    assert_eq!(
        read_query(&mut original, "public", public, 301).await.0,
        BTreeSet::from([3]),
    );
    assert_eq!(
        read_query(&mut original, "private", private, 302).await.0,
        BTreeSet::from([2]),
    );
    drop(original);

    let mut resumed = connect(&manager, &["key:b"], Some((&cursor, Some(&["key:b"])))).await;
    assert_eq!(
        read_query(&mut resumed, "public", public, 303).await,
        (BTreeSet::new(), false),
    );
    for (id, key) in [("away", "key:a"), ("back", "key:b")] {
        swap(&mut resumed, id, &[key]).await;
        controls_until(&mut resumed, is_answer(id)).await;
    }
    resumed
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 4 }))
        .await
        .expect("credit the late subscription");
    assert_eq!(
        read_query(&mut resumed, "private", private, 304).await,
        (BTreeSet::from([2]), true),
    );
}
