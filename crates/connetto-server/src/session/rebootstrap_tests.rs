use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use connetto_core::SessionId;
use connetto_core::auth::{CapabilitySubject, Principal};
use connetto_core::messages::{
    ControlMessage, FullResyncReason, Ping, SUBSCRIPTION_REFUSED, Subscribe, SubscriptionSpec,
    Unsubscribe,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_test_harness::{Fixture, RosterAuth, pool_for, with_user};
use tokio::sync::mpsc;

use super::{HeldInput, Outbound, Resume, SessionState};
use crate::defaults::ConnettoDefaults;
use crate::{
    LoopbackTransport, ManagerBuilder, Materializer, PgReadConnector, PgSnapshotSource,
    RuntimeWritableCatalog, SessionManager, loopback, pg_write_target,
};

const DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, amount BIGINT); \
    ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";
const LABEL: &str = "statistic";
type Manager = Arc<SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>>;
type State = SessionState<String, String>;

async fn manager(fixture: &Fixture) -> Manager {
    fixture
        .setup(&[
            DDL,
            "CREATE ROLE rebootstrap_reader LOGIN PASSWORD 'rebootstrap_reader'",
            "GRANT USAGE ON SCHEMA public TO rebootstrap_reader",
            "GRANT SELECT ON notes TO rebootstrap_reader",
            "CREATE POLICY notes_p ON notes USING \
             (owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
            "INSERT INTO notes VALUES (1, 'key:a', 4), (2, 'key:a', 6), \
             (3, 'key:b', 30), (4, 'key:c', 40)",
        ])
        .await;
    let reader = pool_for(&with_user(
        fixture.admin_url(),
        "rebootstrap_reader",
        "rebootstrap_reader",
    ))
    .await;
    ManagerBuilder::new(
        Materializer::builder(DDL)
            .with_write_catalog(RuntimeWritableCatalog::default())
            .with_read_connector(PgReadConnector::with_session_setup(reader.clone()))
            .build()
            .expect("materializer"),
        PgSnapshotSource::from_ddl(reader.clone(), DDL).expect("snapshot source"),
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(reader),
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), DDL).expect("write target"),
    )
    .build()
}

fn state() -> State {
    let (outbound, receiver) = mpsc::unbounded_channel();
    let session_id = SessionId::from_token_hash("rebootstrap-owner");
    let principal =
        Principal::unidentified(session_id).with_capabilities([CapabilitySubject::new("key:a")]);
    SessionState {
        credits: 64,
        pending: VecDeque::new(),
        input: HeldInput::default(),
        outbound_rx: receiver,
        held_outbound: VecDeque::new(),
        subs: HashMap::new(),
        paging: VecDeque::new(),
        reader_reservation: crate::reserve::ReaderReservation::default(),
        missed: Vec::new(),
        computed_subs: HashMap::new(),
        outbound,
        principal: Arc::new(principal),
        pending_header: None,
        deferred: BTreeMap::new(),
        session_id,
        writer_row: None,
        bind_nonce: [0; 32],
        indeterminate: None,
        resume: Resume::Fresh,
        resume_read_budget: Duration::from_secs(10),
        cursor_subjects: None,
        key_expiry: BTreeMap::new(),
        closing: false,
        enrol_challenge: None,
    }
}

async fn next_control(client: &mut LoopbackTransport) -> ControlMessage {
    let frame = tokio::time::timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("a response within ten seconds")
        .expect("receive response")
        .expect("the session stays open");
    let IncomingFrame::Control(control) = frame else {
        panic!("expected control response, got {frame:?}");
    };
    control
}

async fn subscribe(
    manager: &Manager,
    server: &mut LoopbackTransport,
    state: &mut State,
    sql: &str,
) {
    manager
        .handle_control(
            server,
            ControlMessage::Subscribe(Subscribe {
                sub_id: LABEL.to_owned(),
                spec: SubscriptionSpec::new(sql),
            }),
            state,
        )
        .await
        .expect("subscribe");
}

async fn answer(client: &mut LoopbackTransport, expected: impl Into<serde_json::Value>) {
    let ControlMessage::AggregateUpdate(answer) = next_control(client).await else {
        panic!("expected aggregate answer");
    };
    assert_eq!(answer.sub_id, LABEL);
    let actual: serde_json::Value =
        serde_json::from_str(answer.result_json.as_deref().expect("aggregate body"))
            .expect("aggregate JSON");
    assert_eq!(actual, expected.into());
}

async fn swap(manager: &Manager, state: &mut State, key: &str) {
    let next = state
        .principal
        .with_capabilities([CapabilitySubject::new(key)]);
    let reached = manager.reached_by_keys(state);
    manager.swap_keys(state, next, reached, None).await;
}

async fn queued(receiver: &mut mpsc::UnboundedReceiver<Outbound>) -> Outbound {
    let job = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .expect("a queued re-bootstrap")
        .expect("the queue stays open");
    assert!(matches!(job, Outbound::Rebootstrap { .. }));
    job
}

async fn unsubscribe(manager: &Manager, server: &mut LoopbackTransport, state: &mut State) {
    manager
        .handle_control(
            server,
            ControlMessage::Unsubscribe(Unsubscribe {
                sub_id: LABEL.to_owned(),
            }),
            state,
        )
        .await
        .expect("unsubscribe");
}

async fn assert_no_job_output(
    manager: &Manager,
    server: &mut LoopbackTransport,
    client: &mut LoopbackTransport,
    state: &mut State,
    job: Outbound,
) {
    assert!(
        manager
            .handle_outbound(server, job, state)
            .await
            .expect("handle queued job")
    );
    manager
        .handle_control(server, ControlMessage::Ping(Ping { nonce: 301 }), state)
        .await
        .expect("fence handled job");
    let ControlMessage::Pong(pong) = next_control(client).await else {
        panic!("a cancelled job cannot send another answer");
    };
    assert_eq!(pong.nonce, 301);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_rebootstrap_cannot_resurrect_an_unsubscribed_label() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    let mut state = state();
    let (mut server, mut client) = loopback();
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT COUNT(*) FROM notes",
    )
    .await;
    answer(&mut client, 2).await;
    swap(&manager, &mut state, "key:b").await;
    let job = queued(&mut state.outbound_rx).await;
    unsubscribe(&manager, &mut server, &mut state).await;
    assert_no_job_output(&manager, &mut server, &mut client, &mut state, job).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_rebootstrap_cannot_replace_a_new_subscription_using_the_label() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    let mut state = state();
    let (mut server, mut client) = loopback();
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT COUNT(*) FROM notes",
    )
    .await;
    answer(&mut client, 2).await;
    swap(&manager, &mut state, "key:b").await;
    let job = queued(&mut state.outbound_rx).await;
    unsubscribe(&manager, &mut server, &mut state).await;
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT SUM(amount) FROM notes",
    )
    .await;
    answer(&mut client, "30").await;
    assert_no_job_output(&manager, &mut server, &mut client, &mut state, job).await;
    swap(&manager, &mut state, "key:c").await;
    let job = queued(&mut state.outbound_rx).await;
    assert!(
        manager
            .handle_outbound(&mut server, job, &mut state)
            .await
            .expect("replace statistic")
    );
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::FullResyncRequired(_)
    ));
    answer(&mut client, "40").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_key_changes_replace_a_pending_statistic_once_under_the_current_keys() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    let mut state = state();
    let (mut server, mut client) = loopback();
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT SUM(amount) FROM notes",
    )
    .await;
    answer(&mut client, "10").await;
    swap(&manager, &mut state, "key:b").await;
    let first = queued(&mut state.outbound_rx).await;
    swap(&manager, &mut state, "key:c").await;
    assert!(
        manager
            .handle_outbound(&mut server, first, &mut state)
            .await
            .expect("replace statistic")
    );
    let ControlMessage::FullResyncRequired(notice) = next_control(&mut client).await else {
        panic!("replacement must invalidate the old answer");
    };
    assert_eq!(notice.sub_id, LABEL);
    assert_eq!(notice.reason, FullResyncReason::AuthorizationChange);
    answer(&mut client, "40").await;
    while let Ok(job) = state.outbound_rx.try_recv() {
        assert_no_job_output(&manager, &mut server, &mut client, &mut state, job).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_rebootstrap_releases_its_label_for_a_new_subscription() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    let mut state = state();
    let (mut server, mut client) = loopback();
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT COUNT(*) FROM notes",
    )
    .await;
    answer(&mut client, 2).await;
    swap(&manager, &mut state, "key:b").await;
    let job = queued(&mut state.outbound_rx).await;
    fixture
        .exec("REVOKE SELECT ON notes FROM rebootstrap_reader")
        .await;
    assert!(
        manager
            .handle_outbound(&mut server, job, &mut state)
            .await
            .expect("refuse failed replacement")
    );
    let ControlMessage::NonFatalError(refusal) = next_control(&mut client).await else {
        panic!("an unavailable replacement must be refused");
    };
    assert_eq!(refusal.related_to.as_deref(), Some(LABEL));
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
    fixture
        .exec("GRANT SELECT ON notes TO rebootstrap_reader")
        .await;
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT SUM(amount) FROM notes",
    )
    .await;
    answer(&mut client, "30").await;
}

async fn row_snapshot(client: &mut LoopbackTransport) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = client
                .recv()
                .await
                .expect("snapshot frame")
                .expect("open connection");
            if let IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) = frame {
                assert_eq!(end.sub_id, LABEL);
                break;
            }
        }
    })
    .await
    .expect("row snapshot completes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reserved_row_resend_cannot_replace_a_new_subscription_using_the_label() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture).await;
    let mut state = state();
    let (mut server, mut client) = loopback();
    subscribe(&manager, &mut server, &mut state, "SELECT * FROM notes").await;
    row_snapshot(&mut client).await;
    let row = &state.subs[LABEL];
    let job = Outbound::ReservedResnapshot {
        sub_id: LABEL.to_owned(),
        owner: (row.reg.consumer_id, row.reg.sub_id),
        permit: crate::reserve::ReaderPermit::none(),
    };
    unsubscribe(&manager, &mut server, &mut state).await;
    subscribe(
        &manager,
        &mut server,
        &mut state,
        "SELECT * FROM notes WHERE id = 1",
    )
    .await;
    row_snapshot(&mut client).await;
    assert_no_job_output(&manager, &mut server, &mut client, &mut state, job).await;
}
