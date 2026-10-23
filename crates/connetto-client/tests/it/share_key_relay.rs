//! Share-key changes made in a relay tab travel to the worker that holds the
//! keys (R95 decision 17).
//!
//! A tab's mirror holds no key of its own. Its call sends a relay request,
//! waits for the answer quoting its id, and maps the worker's outcome onto the
//! errors a native call returns. The worker's side commits the change and
//! reports whether the subjects its replica answers moved.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_client::{
    ClientBuilder, ClientError, ConnettoClient, ConnettoConnection, Grant, SyncSchema,
};
use connetto_core::Cursor;
use connetto_core::auth::CapabilitySubject;
use connetto_core::messages::{
    BulkMessage, ControlMessage, GateState, HandshakeAck, ShareKeyChange, TabIdentity,
    TabShareKeyAnswer, TabShareKeyChange, TabShareKeyOutcome, WriterGrant,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use parking_lot::Mutex;
use thiserror::Error;

/// A scripted relay or server that records every control frame it is sent.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    sent: Arc<Mutex<Vec<ControlMessage>>>,
    closed: Arc<AtomicBool>,
}

#[derive(Debug, Error)]
enum Gone {
    #[error("the scripted socket is gone")]
    Closed,
}

impl Script {
    fn say(&self, message: ControlMessage) {
        self.frames
            .lock()
            .push_back(IncomingFrame::Control(message));
    }

    fn changes(&self) -> Vec<TabShareKeyChange> {
        self.sent
            .lock()
            .iter()
            .filter_map(|message| match message {
                ControlMessage::TabShareKeyChange(change) => Some(change.clone()),
                _ => None,
            })
            .collect()
    }

    fn replacements(&self) -> usize {
        self.sent
            .lock()
            .iter()
            .filter(|message| matches!(message, ControlMessage::ReplaceShareKeys(_)))
            .count()
    }

    /// The change the tab sent, waited for within `bound`.
    async fn change(&self, bound: Duration) -> TabShareKeyChange {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            if let Some(change) = self.changes().pop() {
                return change;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the tab sent no share-key change in time"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn answer(&self, request_id: &str, outcome: TabShareKeyOutcome) {
        self.say(ControlMessage::TabShareKeyAnswer(TabShareKeyAnswer {
            request_id: request_id.to_owned(),
            outcome,
        }));
    }
}

impl Transport for Script {
    type Error = Gone;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.sent.lock().push(message);
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

fn ack() -> ControlMessage {
    ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "relay".to_owned(),
        session_token: "relay".to_owned(),
        resume_token: "relay".to_owned(),
        current_cursor: Cursor::from(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        writer: Some(WriterGrant {
            number: 1,
            frontier: 0,
        }),
    })
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

fn grant(token: &str) -> Grant {
    Grant::new(format!("h.{token}.s"))
}

fn subject(name: &str) -> CapabilitySubject<String> {
    CapabilitySubject::<String>::new(name.to_owned())
}

#[derive(QueryableByName)]
struct Subjects {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    subjects: Option<String>,
}

/// A tab mirror attached to a scripted relay, its pump running.
async fn tab() -> (ConnettoClient<Script>, Script, tokio::task::JoinHandle<()>) {
    let script = Script::default();
    script.say(ack());
    let mut conn = ClientBuilder::new(
        schema().relay_mirror(),
        super::support::NeverDial::<Script>::default(),
    )
    .with_client_id("tab")
    .open_driven()
    .expect("the mirror opens");
    conn.attach(script.clone())
        .await
        .expect("the relay acknowledges the tab");
    let (client, pump) = ConnettoClient::with_pump(conn);
    (client, script, tokio::spawn(pump))
}

async fn mirror_subjects(client: &ConnettoClient<Script>) -> Option<String> {
    client
        .with_conn(|conn| {
            diesel::sql_query("SELECT current_app_subjects() AS subjects")
                .get_result::<Subjects>(conn.conn())
                .expect("the mirror answers its subjects function")
                .subjects
        })
        .await
        .expect("the tab is open")
}

/// The relay states the new identity before it answers, as the hub does.
#[tokio::test]
async fn a_tab_change_travels_to_the_worker_and_returns_after_its_identity() {
    let (client, script, pump) = tab().await;

    let call = {
        let client = client.clone();
        tokio::spawn(async move { client.add_share_key(&grant("b"), &subject("b")).await })
    };
    let change = script.change(Duration::from_secs(5)).await;
    assert_eq!(
        change.change,
        ShareKeyChange::Add {
            grant: grant("b"),
            subject: "b".to_owned(),
        }
    );
    script.say(ControlMessage::TabIdentity(TabIdentity {
        caller: None,
        subjects: Some("b".to_owned()),
    }));
    script.answer(&change.request_id, TabShareKeyOutcome::Changed);
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call returns once answered")
        .expect("the call task completes")
        .expect("the worker committed the change");
    assert_eq!(mirror_subjects(&client).await.as_deref(), Some("b"));
    assert_eq!(
        script.replacements(),
        0,
        "a tab never swaps keys with a server"
    );

    let call = {
        let client = client.clone();
        tokio::spawn(async move { client.remove_share_key(&subject("b")).await })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let removal = loop {
        let changes = script.changes();
        if changes.len() == 2 {
            break changes[1].clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no removal was sent"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(
        removal.change,
        ShareKeyChange::Remove {
            subject: "b".to_owned(),
        }
    );
    assert_ne!(removal.request_id, change.request_id);
    script.say(ControlMessage::TabIdentity(TabIdentity {
        caller: None,
        subjects: None,
    }));
    script.answer(&removal.request_id, TabShareKeyOutcome::Changed);
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call returns once answered")
        .expect("the call task completes")
        .expect("the worker committed the removal");
    assert_eq!(mirror_subjects(&client).await, None);

    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// Each refusal the worker reports surfaces as the error a native call returns.
#[tokio::test]
async fn a_tab_maps_each_worker_refusal_onto_the_native_error() {
    let (client, script, pump) = tab().await;
    for (index, outcome) in [
        TabShareKeyOutcome::Locked,
        TabShareKeyOutcome::StoreRefused("the store is gone".to_owned()),
        TabShareKeyOutcome::ReplicaRefused("the replica is gone".to_owned()),
    ]
    .into_iter()
    .enumerate()
    {
        let call = {
            let client = client.clone();
            tokio::spawn(async move { client.add_share_key(&grant("c"), &subject("c")).await })
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let change = loop {
            let changes = script.changes();
            if changes.len() == index + 1 {
                break changes[index].clone();
            }
            assert!(tokio::time::Instant::now() < deadline, "no change was sent");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        script.answer(&change.request_id, outcome.clone());
        let result = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .expect("the call returns once answered")
            .expect("the call task completes");
        match (outcome, result) {
            (TabShareKeyOutcome::Locked, Err(ClientError::Locked))
            | (TabShareKeyOutcome::StoreRefused(_), Err(ClientError::Auth(_)))
            | (TabShareKeyOutcome::ReplicaRefused(_), Err(ClientError::Session(_))) => {}
            (outcome, result) => panic!("{outcome:?} surfaced as {result:?}"),
        }
    }
    assert_eq!(
        mirror_subjects(&client).await,
        None,
        "no refusal changes the mirror"
    );
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// An answer quoting another id settles nothing, and the call's own answer does.
#[tokio::test]
async fn a_foreign_answer_leaves_the_call_waiting() {
    let (client, script, pump) = tab().await;
    let mut call = {
        let client = client.clone();
        tokio::spawn(async move { client.add_share_key(&grant("d"), &subject("d")).await })
    };
    let change = script.change(Duration::from_secs(5)).await;
    script.answer("someone-else", TabShareKeyOutcome::Locked);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut call)
            .await
            .is_err(),
        "a foreign answer returned the call"
    );
    script.answer(&change.request_id, TabShareKeyOutcome::Changed);
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call's own answer returns it")
        .expect("the call task completes")
        .expect("its own answer reports the change");
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// A tab that already learned the gate is locked refuses before sending.
#[tokio::test]
async fn a_locked_tab_refuses_without_asking_the_worker() {
    let (client, script, pump) = tab().await;
    script.say(ControlMessage::GateState(GateState::Locked));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the tab never applied the lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(matches!(
        client.add_share_key(&grant("e"), &subject("e")).await,
        Err(ClientError::Locked)
    ));
    assert!(matches!(
        client.remove_share_key(&subject("e")).await,
        Err(ClientError::Locked)
    ));
    assert_eq!(script.changes(), Vec::new(), "a locked tab asks nothing");
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// A tab wire that drops fails a pending call instead of leaving it waiting.
#[tokio::test]
async fn a_dropped_tab_wire_fails_the_pending_call() {
    let (client, script, pump) = tab().await;
    let call = {
        let client = client.clone();
        tokio::spawn(async move { client.add_share_key(&grant("f"), &subject("f")).await })
    };
    script.change(Duration::from_secs(5)).await;
    script.closed.store(true, Ordering::Release);
    let result = tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .expect("the call fails when the wire drops")
        .expect("the call task completes");
    assert!(
        matches!(result, Err(ClientError::Transport(_))),
        "a dropped wire surfaces as a transport failure, got {result:?}"
    );
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// An unanswered change ends at its bound with an unknown outcome, and the tab
/// stays connected.
#[tokio::test]
async fn an_unanswered_tab_change_ends_at_its_bound() {
    let (client, script, pump) = tab().await;
    let started = std::time::Instant::now();
    let call = {
        let client = client.clone();
        tokio::spawn(async move { client.add_share_key(&grant("g"), &subject("g")).await })
    };
    script.change(Duration::from_secs(5)).await;
    let result = tokio::time::timeout(Duration::from_secs(45), call)
        .await
        .expect("the bound ends the call")
        .expect("the call task completes");
    assert!(
        matches!(&result, Err(ClientError::Transport(detail)) if detail.contains("unknown")),
        "an unanswered change names its unknown outcome, got {result:?}"
    );
    assert!(started.elapsed() >= Duration::from_secs(25));
    assert!(
        !script.closed.load(Ordering::Acquire),
        "an unanswered relay request keeps the tab connected"
    );
    client
        .ping(1)
        .await
        .expect("the tab still speaks to its relay");
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
}

/// The driver API cannot wait for a relay answer, so a driven mirror refuses
/// rather than committing a set the worker never holds.
#[tokio::test]
async fn a_driven_mirror_refuses_a_local_change() {
    let script = Script::default();
    script.say(ack());
    let mut conn: ConnettoConnection<Script> = ClientBuilder::new(
        schema().relay_mirror(),
        super::support::NeverDial::<Script>::default(),
    )
    .with_client_id("tab")
    .open_driven()
    .expect("the mirror opens");
    conn.attach(script.clone())
        .await
        .expect("the relay acknowledges the tab");
    assert!(
        conn.add_share_key(&grant("h"), &subject("h"))
            .await
            .is_err()
    );
    assert!(conn.remove_share_key(&subject("h")).await.is_err());
    let _ = tokio::time::timeout(Duration::from_millis(100), conn.pump_one()).await;
    assert_eq!(script.changes(), Vec::new());
    assert_eq!(script.replacements(), 0);
}

/// The worker's relay call reports whether the subjects its replica answers
/// moved, so the hub restates them only when they did.
#[tokio::test]
async fn a_worker_reports_whether_a_relay_change_moved_its_subjects() {
    let mut conn: ConnettoConnection<Script> =
        ClientBuilder::new(schema(), super::support::NeverDial::<Script>::default())
            .signed_in(super::support::held("worker"))
            .open_driven()
            .expect("the worker opens");
    let before = conn.share_key_generation();
    let add = ShareKeyChange::Add {
        grant: grant("w"),
        subject: "w".to_owned(),
    };
    assert!(conn.apply_relay_share_key_change(&add).await.expect("add"));
    assert_eq!(
        conn.relay_identity().expect("identity").subjects.as_deref(),
        Some("w")
    );
    let after_add = conn.share_key_generation();
    assert_ne!(after_add, before);
    assert!(
        !conn
            .apply_relay_share_key_change(&add)
            .await
            .expect("again"),
        "an identical pair moves nothing"
    );
    assert_eq!(conn.share_key_generation(), after_add);
    let absent = ShareKeyChange::Remove {
        subject: "nobody".to_owned(),
    };
    assert!(
        !conn
            .apply_relay_share_key_change(&absent)
            .await
            .expect("absent")
    );
    let held = ShareKeyChange::Remove {
        subject: "w".to_owned(),
    };
    assert!(
        conn.apply_relay_share_key_change(&held)
            .await
            .expect("remove")
    );
    assert_eq!(conn.relay_identity().expect("identity").subjects, None);
    assert_ne!(conn.share_key_generation(), after_add);
}
