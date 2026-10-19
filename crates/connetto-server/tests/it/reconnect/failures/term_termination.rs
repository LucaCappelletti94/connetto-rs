//! Terminal frame ordering for terms with hidden membership subscriptions.

use std::future::{Future, ready};

use connetto_core::messages::{BindValue, FatalErrorReason, Ping};
use connetto_server::CallerMappings;
use connetto_server::session::TermSeedRead;
use pg2sqlite::prelude::SessionVariableMapping;
use subql::backend::Value as PgValue;

use super::*;

const MEMBER_DDL: &str = "CREATE TABLE order_members (order_id INT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (order_id, user_id)); CREATE TABLE quantity_members (order_id INT NOT NULL, user_id TEXT NOT NULL, PRIMARY KEY (order_id, user_id));";
const TERM_QUERY: &str = "SELECT * FROM orders WHERE id IN (SELECT order_id FROM order_members WHERE user_id = current_app_user()) AND quantity IN (SELECT order_id FROM quantity_members WHERE user_id = current_app_user())";
const POLICIES: &str = "ALTER TABLE orders ENABLE ROW LEVEL SECURITY; CREATE POLICY orders_members ON orders FOR ALL USING (id IN (SELECT order_id FROM order_members WHERE user_id = current_setting('app.user_id', true)) AND quantity IN (SELECT order_id FROM quantity_members WHERE user_id = current_setting('app.user_id', true)));";

type TermManager =
    SessionManager<MembershipSeed, RosterAuth, ConnettoDefaults, NoConnector, ScriptedOplog>;

struct MembershipSeed;

impl SnapshotSource for MembershipSeed {
    type Error = std::convert::Infallible;

    async fn estimate(
        &self,
        sql: &str,
        binds: &[BindValue],
        caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        SeedSnapshot.estimate(sql, binds, caller).await
    }

    async fn snapshot_page(
        &self,
        sql: &str,
        binds: &[BindValue],
        caller: &Principal,
        page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        SeedSnapshot.snapshot_page(sql, binds, caller, page).await
    }

    fn term_seed(
        &self,
        _sql: &str,
        _table: &str,
        _subject: &str,
        _keys: &[String],
        caller: &Principal,
    ) -> impl Future<Output = Result<Option<TermSeedRead>, Self::Error>> {
        ready(Ok(Some(TermSeedRead {
            rows: (1..=3)
                .map(|id| {
                    (
                        PgValue::String(
                            caller
                                .identity()
                                .expect("identified caller")
                                .user_id
                                .clone(),
                        ),
                        vec![PgValue::Int(id)],
                    )
                })
                .collect(),
            published: Some(true),
        })))
    }
}

async fn term_manager(
    fixture: &Fixture,
) -> (Arc<TermManager>, Arc<Mutex<Script>>, Vec<PgChangeEvent>) {
    let ddl = format!("{PG_DDL} {MEMBER_DDL}");
    let translator =
        connetto_server::openfga::Translated::of::<String, connetto_core::bots::TextIds>(
            &ddl,
            POLICIES,
            "app.user_id",
        )
        .expect("membership classifier")
        .into_parts()
        .1;
    let script = Arc::new(Mutex::new(Script::default()));
    let manager = ManagerBuilder::new(
        Materializer::builder(&ddl)
            .with_translator(translator)
            .with_caller(CallerMappings {
                identity: SessionVariableMapping::current_setting(
                    "app.user_id",
                    "current_app_user",
                ),
                subjects: None,
            })
            .build()
            .expect("materializer"),
        MembershipSeed,
        RosterAuth::granting("gone"),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), &ddl).expect("write target"),
    )
    .with_oplog(ScriptedOplog {
        inner: InMemoryOplog::default(),
        script: Arc::clone(&script),
    })
    .build();
    let mut source = PgSqliteEmuSource::open_in_memory(&ddl).expect("source");
    source
        .execute_sql(
            "INSERT INTO orders VALUES (1, 1.0, 1, 'row'), (2, 2.0, 2, 'row'), (3, 3.0, 3, 'row')",
        )
        .expect("orders");
    let mut events = Vec::new();
    while let Some(item) = source.next_item().await.expect("source event") {
        if let SourceItem::Event(event) = item {
            manager.dispatch_event(&event).await.expect("dispatch");
            events.push(event);
        }
    }
    arm(&script, &[], true, None);
    (manager, script, events)
}

async fn term_client(
    manager: &Arc<TermManager>,
    resume: Cursor,
) -> (LoopbackTransport, SessionTask) {
    let (server, mut client) = loopback();
    let serving = Arc::clone(manager);
    let task = tokio::spawn(async move { serving.serve(server).await });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "gone")
                .with_grant(connetto_core::messages::Grant::new("user:gone"))
                .with_cursor(resume),
        ))
        .await
        .expect("handshake");
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::Challenge(_)
    ));
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::HandshakeAck(_)
    ));
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(TERM_QUERY),
        }))
        .await
        .expect("term subscription");
    (client, task)
}

async fn revoke(manager: &TermManager, client: &mut LoopbackTransport) {
    assert!(
        manager
            .close_session(
                connetto_core::SessionId::from_token_hash("user:gone"),
                FatalErrorReason::SessionRevoked,
            )
            .await,
        "the revocation finds the session"
    );
    let ControlMessage::FatalError(fatal) = next_control(client).await else {
        panic!("revocation delivers its fatal");
    };
    assert_eq!(fatal.reason, FatalErrorReason::SessionRevoked);
}

async fn expect_closed(client: &mut LoopbackTransport, task: SessionTask) {
    let trailing = tokio::time::timeout(WAIT, client.recv())
        .await
        .expect("the session closes before the deadline")
        .expect("read terminal closure");
    client.close().await.expect("close peer");
    let ended = tokio::time::timeout(WAIT, task)
        .await
        .expect("the session finishes before the deadline")
        .expect("the session did not panic");
    assert!(
        trailing.is_none(),
        "the terminal outcome has a trailing frame {trailing:?}"
    );
    ended.expect("the session closes cleanly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fatal_during_term_catchup_is_the_last_frame() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events) = term_manager(&fixture).await;
        let (arrived, _release) = hold_page(&script);
        let (mut client, task) = term_client(&manager, cursor_of(&events[0])).await;
        page_arrived(&arrived).await;
        revoke(&manager, &mut client).await;
        expect_closed(&mut client, task).await;
    })
    .await
    .expect("fatal term termination completes before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_close_during_term_catchup_opens_no_memberships() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events) = term_manager(&fixture).await;
        let (arrived, _release) = hold_page(&script);
        let (mut client, task) = term_client(&manager, cursor_of(&events[0])).await;
        page_arrived(&arrived).await;
        assert_eq!(manager.close_person("gone").await, 1);
        expect_closed(&mut client, task).await;
    })
    .await
    .expect("silent term termination completes before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fatal_during_membership_catchup_opens_no_next_membership() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events) = term_manager(&fixture).await;
        let (arrived, release) = hold_page(&script);
        let (mut client, task) = term_client(&manager, cursor_of(&events[0])).await;
        page_arrived(&arrived).await;
        let (member_arrived, _member_release) = hold_page(&script);
        release.notify_one();
        expect_patches_before_truncate(&mut client, &events[1..]).await;
        assert!(matches!(
            next_control(&mut client).await,
            ControlMessage::MembershipOpened(_)
        ));
        page_arrived(&member_arrived).await;
        revoke(&manager, &mut client).await;
        expect_closed(&mut client, task).await;
    })
    .await
    .expect("membership termination completes before the deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_term_opens_each_membership_and_keeps_serving() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(Duration::from_secs(90), async {
        let (manager, script, events) = term_manager(&fixture).await;
        let (arrived, release) = hold_page(&script);
        let (mut client, task) = term_client(&manager, cursor_of(&events[0])).await;
        page_arrived(&arrived).await;
        release.notify_one();
        expect_patches_before_truncate(&mut client, &events[1..]).await;
        let mut mirrored = std::collections::HashSet::new();
        for _ in 0..2 {
            let ControlMessage::MembershipOpened(opened) = next_control(&mut client).await else {
                panic!("the live term opens its membership");
            };
            mirrored.insert(opened.member_table);
        }
        assert_eq!(
            mirrored,
            std::collections::HashSet::from([
                "order_members".to_owned(),
                "quantity_members".to_owned()
            ])
        );
        client
            .send_control(ControlMessage::Ping(Ping { nonce: 42 }))
            .await
            .expect("ping");
        let ControlMessage::Pong(pong) = next_control(&mut client).await else {
            panic!("the live session keeps serving");
        };
        assert_eq!(pong.nonce, 42);
        client.close().await.expect("close live peer");
        tokio::time::timeout(WAIT, task)
            .await
            .expect("live session ends")
            .expect("live task did not panic")
            .expect("live session closes cleanly");
    })
    .await
    .expect("live term completes before the deadline");
}
