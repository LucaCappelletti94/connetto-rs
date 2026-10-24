use connetto_client::{
    ClientBuilder, ClientError, ConnettoClient, ConnettoConnection, Grant, SyncSchema,
};
use connetto_core::auth::CapabilitySubject;
use connetto_core::{LoopbackTransport, SchemaBundle};
use diesel::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

diesel::table! {
    notes (id) {
        id -> BigInt,
        owner -> Text,
    }
}

diesel::table! {
    visible (id) {
        id -> BigInt,
        owner -> Text,
    }
}

fn schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            "-- connetto:major 1",
            "",
            "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
         CREATE VIEW visible AS SELECT * FROM notes \
         WHERE owner = current_app_user() \
            OR instr(',' || current_app_subjects() || ',', ',' || owner || ',') > 0;",
            vec![("visible".to_owned(), "notes".to_owned())],
            vec!["visible".to_owned()],
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

fn seed(conn: &mut ConnettoConnection<LoopbackTransport>) {
    diesel::insert_into(notes::table)
        .values([
            (notes::id.eq(1), notes::owner.eq("alice")),
            (notes::id.eq(2), notes::owner.eq("key:a")),
            (notes::id.eq(3), notes::owner.eq("key:b")),
        ])
        .execute(conn.conn())
        .expect("seed cached rows");
}

fn visible_ids(conn: &mut ConnettoConnection<LoopbackTransport>) -> Vec<i64> {
    visible::table
        .select(visible::id)
        .order(visible::id)
        .load(conn.conn())
        .expect("read policy rows")
}

#[tokio::test]
async fn a_running_replica_reveals_and_hides_cached_rows_when_its_key_changes() {
    let mut conn = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .signed_in(super::support::held("alice"))
    .open_driven()
    .expect("open offline");
    seed(&mut conn);
    assert_eq!(visible_ids(&mut conn), vec![1]);

    let subject = CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("add a key offline");
    assert_eq!(visible_ids(&mut conn), vec![1, 2]);

    conn.remove_share_key(&subject)
        .await
        .expect("remove a key offline");
    assert_eq!(visible_ids(&mut conn), vec![1]);
    assert_eq!(
        notes::table
            .select(notes::id)
            .order(notes::id)
            .load::<i64>(conn.conn())
            .expect("read cached rows"),
        vec![1, 2, 3],
    );
}

#[tokio::test]
async fn removing_a_subject_removes_all_its_grants_and_preserves_other_access() {
    let subject = CapabilitySubject::<String>::new("key:a");
    let mut conn = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .with_share_keys([
        (Grant::new("grant-a-first"), subject.clone()),
        (Grant::new("grant-a-second"), subject.clone()),
        (
            Grant::new("grant-b"),
            CapabilitySubject::<String>::new("key:b"),
        ),
    ])
    .signed_in(super::support::held("alice"))
    .open_driven()
    .expect("open offline");
    seed(&mut conn);
    assert_eq!(visible_ids(&mut conn), vec![1, 2, 3]);

    conn.remove_share_key(&subject)
        .await
        .expect("remove every grant for the subject");
    assert_eq!(visible_ids(&mut conn), vec![1, 3]);
}

#[tokio::test]
async fn an_open_live_query_refreshes_after_an_offline_key_change() {
    let mut conn = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .signed_in(super::support::held("alice"))
    .open_driven()
    .expect("open offline");
    seed(&mut conn);
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let query: connetto_client::LiveQuery<i64> = client
        .watch(visible::table.select(visible::id).order(visible::id))
        .await
        .expect("watch policy rows offline");
    assert_eq!(query.rows(), vec![1]);

    let subject = CapabilitySubject::<String>::new("key:a");
    client
        .add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("accept the local key");
    assert_eq!(query.rows(), vec![1, 2]);
    client
        .remove_share_key(&subject)
        .await
        .expect("remove the local key");
    assert_eq!(query.rows(), vec![1]);

    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close the pump");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump exits")
        .expect("the pump did not panic");
    assert!(matches!(
        client
            .add_share_key(&Grant::new("after-close"), &subject)
            .await,
        Err(ClientError::Stopped(_))
    ));
}

#[tokio::test]
async fn a_pump_without_a_reconnect_driver_expires_a_key_while_offline() {
    let subject = CapabilitySubject::<String>::new("key:a");
    let authority =
        connetto_server::TokenAuthority::generate(&connetto_server::AuthConfig::default())
            .expect("create token authority");
    let grant = authority
        .mint_capability(&subject, SystemTime::now(), Duration::from_secs(2))
        .expect("mint a short-lived share key");
    let mut conn = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .with_share_keys([(Grant::new(grant), subject)])
    .signed_in(super::support::held("alice"))
    .open_driven()
    .expect("open offline");
    seed(&mut conn);
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let mut query: connetto_client::LiveQuery<i64> = client
        .watch(visible::table.select(visible::id).order(visible::id))
        .await
        .expect("watch policy rows offline");
    assert_eq!(query.rows(), vec![1, 2]);

    tokio::time::timeout(Duration::from_secs(5), async {
        while query.rows() != vec![1] {
            query.changed().await.expect("the expiry refresh arrives");
        }
    })
    .await
    .expect("the key expires without a connection or another app call");
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close the pump");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump exits")
        .expect("the pump did not panic");
}

#[derive(Default)]
pub(super) struct TestGate {
    approve: Arc<AtomicBool>,
    open: Arc<AtomicBool>,
}

impl connetto_client::GateMechanism for TestGate {
    fn lock(&self) {
        self.open.store(false, Ordering::Release);
    }

    fn ask(&self) -> connetto_client::GateAskFuture {
        let approve = Arc::clone(&self.approve);
        let open = Arc::clone(&self.open);
        Box::pin(async move {
            if approve.load(Ordering::Acquire) {
                open.store(true, Ordering::Release);
                connetto_client::GateAskOutcome::Approved
            } else {
                connetto_client::GateAskOutcome::Dismissed
            }
        })
    }

    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }
}

impl TestGate {
    pub(super) fn approve(&self) {
        self.approve.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn locked_changes_preserve_the_keys_and_visibility_seen_after_unlock() {
    let subject = CapabilitySubject::<String>::new("key:a");
    let mut conn = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .with_share_keys([(Grant::new("grant-a"), subject.clone())])
    .signed_in(super::support::held("alice"))
    .open_driven()
    .expect("open offline");
    seed(&mut conn);
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let query: connetto_client::LiveQuery<i64> = client
        .watch(visible::table.select(visible::id).order(visible::id))
        .await
        .expect("watch policy rows");
    let gate = Arc::new(TestGate::default());
    let mut events = client.events();
    client.enable_gate(None, gate.clone()).await;

    assert!(matches!(
        client
            .add_share_key(
                &Grant::new("grant-b"),
                &CapabilitySubject::<String>::new("key:b")
            )
            .await,
        Err(ClientError::Locked)
    ));
    assert!(matches!(
        client.remove_share_key(&subject).await,
        Err(ClientError::Locked)
    ));

    gate.approve.store(true, Ordering::Release);
    client.unlock().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                events.recv().await.expect("gate event"),
                connetto_client::ClientEvent::Unlocked
            ) {
                break;
            }
        }
    })
    .await
    .expect("the gate unlocks");
    assert_eq!(query.rows(), vec![1, 2]);
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close the pump");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump exits")
        .expect("the pump did not panic");
}

#[tokio::test]
async fn an_unfinished_redial_does_not_hold_back_key_expiry() {
    let subject = CapabilitySubject::<String>::new("key:a");
    let authority =
        connetto_server::TokenAuthority::generate(&connetto_server::AuthConfig::default())
            .expect("create token authority");
    let grant = authority
        .mint_capability(&subject, SystemTime::now(), Duration::from_secs(3))
        .expect("mint a short-lived key");
    let attempts = Arc::new(AtomicUsize::new(0));
    let (entered, dialing) = tokio::sync::oneshot::channel();
    let mut entered = Some(entered);
    let factory = move || {
        let first = attempts.fetch_add(1, Ordering::Relaxed) == 0;
        let entered = (!first).then(|| entered.take()).flatten();
        async move {
            if first {
                Err(super::support::Unreachable)
            } else {
                if let Some(entered) = entered {
                    let _ = entered.send("r95-expiry-during-dial");
                }
                core::future::pending::<Result<LoopbackTransport, super::support::Unreachable>>()
                    .await
            }
        }
    };
    let (core, pump) = ClientBuilder::new(schema(), factory)
        .with_share_keys([(Grant::new(grant), subject)])
        .with_reconnect(connetto_client::ReconnectPolicy::default())
        .with_sleeper(tokio::time::sleep)
        .signed_in(super::support::held("alice"))
        .connect_with_pump()
        .await
        .expect("a failed first dial leaves the client offline");
    let client = core.client();
    client.with_conn(seed).await.expect("seed cached rows");
    let mut query: connetto_client::LiveQuery<i64> = client
        .watch(visible::table.select(visible::id).order(visible::id))
        .await
        .expect("watch policy rows");
    assert_eq!(query.rows(), vec![1, 2]);
    let pump = tokio::spawn(pump);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), dialing)
            .await
            .expect("the redial starts")
            .expect("the redial signals its request"),
        "r95-expiry-during-dial",
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while query.rows() != vec![1] {
            query.changed().await.expect("the expiry refresh arrives");
        }
    })
    .await
    .expect("the key expires while the dial remains unfinished");
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close interrupts the dial");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump exits")
        .expect("the pump did not panic");
}

diesel::table! {
    papers (id) {
        id -> Integer,
        owner -> Text,
    }
}

async fn wait_for_papers(query: &mut connetto_client::LiveQuery<(i32, String)>, wanted: &[i32]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while query.rows().iter().map(|row| row.0).collect::<Vec<_>>() != wanted {
            query.changed().await.expect("the server refresh arrives");
        }
    })
    .await
    .expect("the server reconciles the share keys");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_key_changes_reconcile_overlapping_subscriptions_without_redial() {
    use connetto_test_harness::fanout::{SHARE_KEY_A, SHARE_KEY_B, keyed_share_fixture};

    let _keyring = connetto_test_harness::isolated_session_keyring();
    let fixture = connetto_test_harness::Fixture::acquire().await;
    let server = keyed_share_fixture(&fixture).await;
    let conn = ClientBuilder::new(
        super::support::bundle(
            "CREATE TABLE papers (id INTEGER PRIMARY KEY, owner TEXT NOT NULL);",
        ),
        super::support::Once::new(server.attach()),
    )
    .connect_driven()
    .await
    .expect("connect anonymously");
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let mut first = client
        .watch(papers::table.filter(papers::id.gt(0)).order(papers::id))
        .await
        .expect("watch papers");
    let mut overlapping = client
        .watch(papers::table.filter(papers::id.ge(2)).order(papers::id))
        .await
        .expect("watch an overlapping predicate");
    assert_eq!(first.rows(), [] as [(i32, String); 0]);
    assert_eq!(overlapping.rows(), [] as [(i32, String); 0]);

    let a = CapabilitySubject::<String>::new(SHARE_KEY_A);
    let b = CapabilitySubject::<String>::new(SHARE_KEY_B);
    client
        .add_share_key(&Grant::new(SHARE_KEY_A), &a)
        .await
        .expect("add the first key");
    wait_for_papers(&mut first, &[1]).await;
    wait_for_papers(&mut overlapping, &[]).await;
    client
        .add_share_key(&Grant::new(SHARE_KEY_B), &b)
        .await
        .expect("add the second key");
    wait_for_papers(&mut first, &[1, 2]).await;
    wait_for_papers(&mut overlapping, &[2]).await;

    client
        .remove_share_key(&a)
        .await
        .expect("remove the first key");
    wait_for_papers(&mut first, &[2]).await;
    wait_for_papers(&mut overlapping, &[2]).await;
    client
        .remove_share_key(&b)
        .await
        .expect("remove the final key");
    wait_for_papers(&mut first, &[]).await;
    wait_for_papers(&mut overlapping, &[]).await;
    assert_eq!(
        client
            .with_conn(|conn| {
                papers::table
                    .select(papers::id)
                    .order(papers::id)
                    .load::<i32>(conn.conn())
            })
            .await
            .expect("read the replica")
            .expect("read physical rows"),
        Vec::<i32>::new(),
    );
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close the pump");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump exits")
        .expect("the pump did not panic");
}

diesel::table! {
    #[sql_name = "_connetto_meta"]
    legacy_meta (id) {
        id -> Integer,
        cursor -> Binary,
    }
}

#[cfg(feature = "native-auth")]
#[tokio::test]
async fn an_existing_cursor_survives_a_replica_without_a_subjects_column() {
    use connetto_client::{DataDir, Gate, MemoryRefreshStore};
    use diesel::connection::SimpleConnection;

    let dir = tempfile::tempdir().expect("replica directory");
    let credential = super::support::held("legacy-checkpoint");
    let mut first = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .signed_in(credential.clone())
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        super::support::key_store(&credential).await,
        MemoryRefreshStore::default(),
    )
    .with_gate(Gate::off())
    .open_driven()
    .await
    .expect("open durable replica");
    first
        .batch_execute("ALTER TABLE _connetto_meta DROP COLUMN cursor_subjects")
        .expect("construct the cursor-only metadata layout");
    diesel::insert_into(legacy_meta::table)
        .values((legacy_meta::id.eq(1), legacy_meta::cursor.eq(vec![0x95_u8])))
        .execute(first.conn())
        .expect("persist a resume position");
    drop(first);

    let reopened = ClientBuilder::new(
        schema(),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .signed_in(credential.clone())
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        super::support::key_store(&credential).await,
        MemoryRefreshStore::default(),
    )
    .with_gate(Gate::off())
    .open_driven()
    .await
    .expect("reopen durable replica");
    assert!(
        reopened.has_ever_synced(),
        "the stored cursor remains usable"
    );
}
