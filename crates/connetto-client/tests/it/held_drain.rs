//! R31: the writes an older major captured drain to that major's server over
//! a second wire, presenting the major, its bundle hash and the writer each
//! write is queued under, and each way it can end reaches the application as
//! a typed event.
//!
//! Native and offline. A loopback pair stands in for each server, so each
//! test scripts exactly what that server answers and reads what it was sent.

use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoConnection, DataDir, MemoryRefreshStore, SyncSchema,
};
use connetto_core::messages::{
    ControlMessage, FatalError, FatalErrorReason, HandshakeAck, HeldWork, HeldWrite,
    MutationApplied, MutationReject, MutationRejectReason, Provenance, RateLimited, WriterGrant,
    WriterRef, WriterRequest,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, MAJOR_DIRECTIVE, Major, SchemaVersion, loopback};
use diesel::prelude::*;
use tempfile::{TempDir, tempdir};
use tokio::sync::mpsc;

const V1_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const V2_DDL: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT, rank INTEGER NOT NULL DEFAULT 0)";

diesel::table! {
    /// The synced table at either major, its shared columns.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Optional item label.
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// The writers owed a retirement, read by the assertions.
    #[sql_name = "_connetto_retire"]
    retire (writer) {
        /// The writer, as the replica spells it.
        writer -> Text,
    }
}

fn schema(major: u32, ddl: &str) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}\n-- {ddl}"),
            "",
            ddl,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

async fn open(dir: &TempDir, schema: SyncSchema) -> ConnettoConnection<LoopbackTransport> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(
        schema,
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .signed_in(credential)
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        store,
        MemoryRefreshStore::default(),
    )
    .open_driven()
    .await
    .expect("open with no server")
}

fn write(conn: &mut ConnettoConnection<LoopbackTransport>, id: i32, label: &str) {
    diesel::insert_into(items::table)
        .values((items::id.eq(id), items::label.eq(label)))
        .execute(conn.conn())
        .expect("write locally");
}

/// What a scripted server says to one handshake.
#[derive(Clone)]
enum Answer {
    /// Ack under this hash, granting a number writer with this frontier when
    /// one was asked for, then settle each write as told.
    Ack {
        version: SchemaVersion,
        grant: Option<WriterGrant>,
        settle: Settle,
    },
    /// Refuse with this reason.
    Refuse(FatalErrorReason),
}

/// How a scripted server settles each write it receives.
#[derive(Clone, Copy)]
enum Settle {
    Apply,
    Reject,
    Silent,
}

/// What one scripted server was sent.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Handshake {
        major: Option<Major>,
        writer: WriterRequest,
        settled_through: Option<u64>,
    },
    Mutation {
        seq: u64,
        provenance: Option<Provenance>,
    },
}

/// A scripted server on one end of a loopback pair, reporting what it is
/// sent as it arrives.
fn server(answer: Answer) -> (LoopbackTransport, mpsc::UnboundedReceiver<Seen>) {
    let (client_end, mut server_end) = loopback();
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(handshake)))) =
            server_end.recv().await
        else {
            return;
        };
        let _ = seen_tx.send(Seen::Handshake {
            major: handshake.schema_major,
            writer: handshake.writer,
            settled_through: handshake.settled_through,
        });
        let (version, grant, settle) = match answer {
            Answer::Refuse(reason) => {
                let _ = server_end
                    .send_control(ControlMessage::FatalError(FatalError::new(reason)))
                    .await;
                return;
            }
            Answer::Ack {
                version,
                grant,
                settle,
            } => (version, grant, settle),
        };
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "scripted".to_owned(),
                session_token: "scripted".to_owned(),
                resume_token: "scripted".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(version),
                initial_credits: 64,
                writer: grant,
            }))
            .await;
        while let Ok(Some(frame)) = server_end.recv().await {
            let IncomingFrame::Control(ControlMessage::MutationHeader(header)) = frame else {
                continue;
            };
            let seq = header.client_seq;
            let _ = seen_tx.send(Seen::Mutation {
                seq,
                provenance: header.provenance,
            });
            let reply = match settle {
                Settle::Apply => {
                    ControlMessage::MutationApplied(MutationApplied { client_seq: seq })
                }
                Settle::Reject => ControlMessage::MutationReject(MutationReject {
                    client_seq: seq,
                    reason: MutationRejectReason::Constraint {
                        detail: "the old server refused it".to_owned(),
                    },
                }),
                Settle::Silent => continue,
            };
            let _ = server_end.send_control(reply).await;
        }
    });
    (client_end, seen_rx)
}

/// Everything a scripted server has reported so far.
fn seen(rx: &mut mpsc::UnboundedReceiver<Seen>) -> Vec<Seen> {
    let mut all = Vec::new();
    while let Ok(item) = rx.try_recv() {
        all.push(item);
    }
    all
}

/// Pump until `done` matches an event, collecting every event on the way.
async fn pump_until(
    conn: &mut ConnettoConnection<LoopbackTransport>,
    done: impl Fn(&ClientEvent) -> bool,
) -> Vec<ClientEvent> {
    let mut events = Vec::new();
    loop {
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), conn.pump_one())
            .await
            .expect("the drain answers within the bound")
            .expect("a pump step");
        let finished = done(&event);
        events.push(event);
        if finished {
            return events;
        }
    }
}

/// Dial the drain the connection owes over `transport`.
async fn dial(conn: &mut ConnettoConnection<LoopbackTransport>, transport: LoopbackTransport) {
    let timer = conn.drain_timer().expect("the held batch owes a dial");
    conn.attach_drain(timer, transport)
        .await
        .expect("attach the drain");
}

fn drained(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::Held(HeldWork::Drained { .. }))
}

fn lost(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::Held(HeldWork::Lost { .. }))
}

fn one() -> Major {
    Major::new(1).expect("one is a major")
}

fn two() -> Major {
    Major::new(2).expect("two is a major")
}

const NUMBER: u64 = 7;

/// A major 1 replica whose one write sits unsent under number 7, issued by a
/// major 1 server that never answered the write, then opened by the major 2
/// build. Returns the connection and the major 1 bundle hash.
async fn held_under_number(
    dir: &TempDir,
) -> (ConnettoConnection<LoopbackTransport>, SchemaVersion) {
    let first = schema(1, V1_DDL);
    {
        let mut conn = open(dir, first.clone()).await;
        let (transport, _seen) = server(Answer::Ack {
            version: first.version(),
            grant: Some(WriterGrant {
                number: NUMBER,
                frontier: 0,
            }),
            settle: Settle::Silent,
        });
        conn.attach(transport).await.expect("attach to major 1");
        write(&mut conn, 1, "unsent");
        conn.push().await.expect("queue").expect("a seq");
    }
    (open(dir, schema(2, V2_DDL)).await, first.version())
}

#[tokio::test]
async fn an_unissued_write_drains_under_a_number_the_old_major_issues() {
    let dir = tempdir().expect("temp dir");
    let first = schema(1, V1_DDL);
    {
        let mut conn = open(&dir, first.clone()).await;
        write(&mut conn, 1, "offline");
        conn.push().await.expect("queue").expect("a seq");
    }
    let mut conn = open(&dir, schema(2, V2_DDL)).await;
    assert_eq!(conn.draining_major(), Some(one()));

    let (transport, mut rx) = server(Answer::Ack {
        version: first.version(),
        grant: Some(WriterGrant {
            number: 9,
            frontier: 0,
        }),
        settle: Settle::Apply,
    });
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, drained).await;

    assert_eq!(
        seen(&mut rx),
        vec![
            Seen::Handshake {
                major: Some(one()),
                writer: WriterRequest::Issue,
                settled_through: None,
            },
            Seen::Mutation {
                seq: 1,
                provenance: None,
            },
        ],
        "an unissued write asks the old major for a number and goes up as its first"
    );
    assert!(events.contains(&ClientEvent::Held(HeldWork::Applied {
        major: one(),
        write: HeldWrite {
            writer: WriterRef::Number(9),
            seq: 1,
        },
    })));
    assert!(
        conn.unsynced().is_empty(),
        "the applied write leaves the queue"
    );
    assert_eq!(conn.drain_timer(), None, "nothing is left to drain");
}

#[tokio::test]
async fn a_numbered_write_drains_under_its_number_and_settles_by_the_frontier() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;

    // The old major already settled it, so it answers the frontier and refuses anything sent.
    let (transport, mut rx) = server(Answer::Ack {
        version: old_version,
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 1,
        }),
        settle: Settle::Reject,
    });
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, drained).await;

    assert_eq!(
        seen(&mut rx),
        vec![Seen::Handshake {
            major: Some(one()),
            writer: WriterRequest::Number(NUMBER),
            settled_through: Some(0),
        }],
        "the drain presents the write's own number and sends nothing the frontier covers"
    );
    assert!(events.contains(&ClientEvent::Held(HeldWork::Applied {
        major: one(),
        write: HeldWrite {
            writer: WriterRef::Number(NUMBER),
            seq: 1,
        },
    })));
    assert!(conn.unsynced().is_empty(), "the frontier settled the write");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, ClientEvent::Held(HeldWork::WireLost { .. }))),
        "a settled batch closes its wire without reporting the work as lost"
    );
}

#[tokio::test]
async fn a_held_write_the_old_major_rejects_is_reported_and_dropped() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;
    let (transport, _rx) = server(Answer::Ack {
        version: old_version,
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 0,
        }),
        settle: Settle::Reject,
    });
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, drained).await;
    assert!(events.contains(&ClientEvent::Held(HeldWork::Rejected {
        major: one(),
        write: HeldWrite {
            writer: WriterRef::Number(NUMBER),
            seq: 1,
        },
        reason: Some(MutationRejectReason::Constraint {
            detail: "the old server refused it".to_owned()
        }),
    })));
    assert!(
        conn.unsynced().is_empty(),
        "the refused write leaves the queue"
    );
}

#[tokio::test]
async fn a_decommissioned_major_loses_its_writes_and_retires_their_writer() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, _old_version) = held_under_number(&dir).await;
    // A newer write chains after the lost one in the same writer.
    write(&mut conn, 2, "newer");
    conn.push().await.expect("queue").expect("a seq");

    let (transport, _rx) = server(Answer::Refuse(FatalErrorReason::MajorMismatch {
        server: two(),
        client: Some(one()),
    }));
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, lost).await;

    assert_eq!(
        events.last(),
        Some(&ClientEvent::Held(HeldWork::Lost {
            major: one(),
            writes: vec![HeldWrite {
                writer: WriterRef::Number(NUMBER),
                seq: 1,
            }],
            files: 0
        }))
    );
    let owed: Vec<String> = retire::table
        .select(retire::writer)
        .load(conn.conn())
        .expect("read the owed retirements");
    assert_eq!(
        owed,
        vec![format!("number:{NUMBER}")],
        "the writer whose chain now has a gap is owed a retirement"
    );
    let unsynced = conn.unsynced();
    assert_eq!(
        unsynced
            .iter()
            .map(|write| (write.writer, write.seq, write.major))
            .collect::<Vec<_>>(),
        vec![(WriterRef::Number(0), 1, Some(two()))],
        "the newer write re-chains under a number still to be issued"
    );
    assert_eq!(conn.drain_timer(), None);
}

#[tokio::test]
async fn a_writer_the_old_major_refuses_hands_its_writes_to_an_issued_number() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;

    let (transport, _rx) = server(Answer::Refuse(FatalErrorReason::WriterUnknown));
    dial(&mut conn, transport).await;
    let (transport, mut rx) = server(Answer::Ack {
        version: old_version,
        grant: Some(WriterGrant {
            number: 9,
            frontier: 0,
        }),
        settle: Settle::Apply,
    });
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, drained).await;

    assert_eq!(
        seen(&mut rx),
        vec![
            Seen::Handshake {
                major: Some(one()),
                writer: WriterRequest::Issue,
                settled_through: None,
            },
            Seen::Mutation {
                seq: 1,
                provenance: Some(Provenance {
                    writer: WriterRef::Number(NUMBER),
                    seq: 1,
                }),
            },
        ],
        "the refused writer's write goes up under the issued number, naming where it came from"
    );
    assert!(events.contains(&ClientEvent::Held(HeldWork::Applied {
        major: one(),
        write: HeldWrite {
            writer: WriterRef::Number(9),
            seq: 1,
        },
    })));
}

#[tokio::test]
async fn an_old_major_server_built_from_another_schema_loses_the_held_work() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, _old_version) = held_under_number(&dir).await;
    let (transport, _rx) = server(Answer::Ack {
        version: SchemaVersion::from_hash(b"another schema at major 1".to_vec()),
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 0,
        }),
        settle: Settle::Apply,
    });
    dial(&mut conn, transport).await;
    let events = pump_until(&mut conn, lost).await;
    assert!(events.contains(&ClientEvent::Held(HeldWork::Lost {
        major: one(),
        writes: vec![HeldWrite {
            writer: WriterRef::Number(NUMBER),
            seq: 1,
        }],
        files: 0
    })));
}

#[tokio::test]
async fn the_drained_major_releases_the_newer_writes_to_their_own_wire() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;
    let (main, mut main_rx) = server(Answer::Ack {
        version: schema(2, V2_DDL).version(),
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 0,
        }),
        settle: Settle::Silent,
    });
    conn.attach(main).await.expect("attach to major 2");
    write(&mut conn, 2, "newer");
    conn.push().await.expect("queue").expect("a seq");

    let (transport, _rx) = server(Answer::Ack {
        version: old_version,
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 0,
        }),
        settle: Settle::Apply,
    });
    dial(&mut conn, transport).await;
    pump_until(&mut conn, drained).await;

    let released = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match main_rx.recv().await {
                Some(Seen::Mutation { seq, .. }) => break seq,
                Some(Seen::Handshake { .. }) => {}
                None => panic!("the main wire closed before anything went up"),
            }
        }
    })
    .await
    .expect("the release reaches the main wire within the bound");
    assert_eq!(
        released, 2,
        "the newer write went up on its own major's wire once the older one drained"
    );
}

#[tokio::test]
async fn a_failed_dial_backs_off_and_a_dropped_drain_redials() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;
    let timer = conn.drain_timer().expect("a dial is owed");
    conn.drain_dial_failed(timer);
    let backed_off = conn.drain_timer().expect("the drain still owes a dial");
    assert!(backed_off.wait() > std::time::Duration::ZERO);

    // An old server that acks and then hangs up before settling anything.
    let (client_end, mut server_end) = loopback();
    tokio::spawn(async move {
        let _ = server_end.recv().await;
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "old".to_owned(),
                session_token: "old".to_owned(),
                resume_token: "old".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(old_version),
                initial_credits: 64,
                writer: Some(WriterGrant {
                    number: NUMBER,
                    frontier: 0,
                }),
            }))
            .await;
        let _ = server_end.close().await;
    });
    conn.attach_drain(backed_off, client_end)
        .await
        .expect("attach the drain");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.pump_one()).await;
    assert!(
        conn.drain_timer().is_some(),
        "the held write is still owed after the drain wire dropped"
    );
    assert_eq!(conn.unsynced().len(), 1);
}

#[tokio::test]
async fn a_held_write_the_old_major_rate_limits_drains_over_the_redial() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;
    // The first wire names the held write in a rate-limit refusal.
    let (client_end, mut server_end) = loopback();
    let limit_version = old_version.clone();
    tokio::spawn(async move {
        let _ = server_end.recv().await;
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "limiter".to_owned(),
                session_token: "limiter".to_owned(),
                resume_token: "limiter".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(limit_version),
                initial_credits: 64,
                writer: Some(WriterGrant {
                    number: NUMBER,
                    frontier: 0,
                }),
            }))
            .await;
        let Some(IncomingFrame::Control(ControlMessage::MutationHeader(header))) =
            server_end.recv().await.expect("the write")
        else {
            panic!("the write reached the limiter wire");
        };
        let _ = server_end
            .send_control(ControlMessage::RateLimited(RateLimited {
                related_to: Some(header.client_seq.to_string()),
                retry_after_ms: 50,
            }))
            .await;
        // The wire stays up after the refusal, which is what the defect needs.
        while let Ok(Some(_)) = server_end.recv().await {}
    });
    let timer = conn.drain_timer().expect("a dial is owed");
    conn.attach_drain(timer, client_end)
        .await
        .expect("attach the drain");
    for _ in 0..8 {
        if conn.drain_timer().is_some() {
            break;
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn.pump_one()).await;
    }
    let redial = conn
        .drain_timer()
        .expect("the rate-limited held write owes a redial");
    let (transport, mut rx) = server(Answer::Ack {
        version: old_version,
        grant: Some(WriterGrant {
            number: NUMBER,
            frontier: 0,
        }),
        settle: Settle::Apply,
    });
    conn.attach_drain(redial, transport)
        .await
        .expect("attach the redial");
    pump_until(&mut conn, drained).await;
    let resends: Vec<u64> = seen(&mut rx)
        .into_iter()
        .filter_map(|seen| match seen {
            Seen::Mutation { seq, .. } => Some(seq),
            Seen::Handshake { .. } => None,
        })
        .collect();
    assert_eq!(resends, vec![1], "the redial resent the rate-limited write");
    assert!(
        conn.unsynced().is_empty(),
        "the settled write leaves the queue"
    );
}

#[tokio::test]
async fn a_dropped_drain_wire_reports_its_held_work_as_wire_lost() {
    let dir = tempdir().expect("temp dir");
    let (mut conn, old_version) = held_under_number(&dir).await;

    // An old server that acks and then hangs up before settling anything.
    let (client_end, mut server_end) = loopback();
    tokio::spawn(async move {
        let _ = server_end.recv().await;
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "old".to_owned(),
                session_token: "old".to_owned(),
                resume_token: "old".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(old_version),
                initial_credits: 64,
                writer: Some(WriterGrant {
                    number: NUMBER,
                    frontier: 0,
                }),
            }))
            .await;
        let _ = server_end.close().await;
    });
    let timer = conn.drain_timer().expect("a dial is owed");
    conn.attach_drain(timer, client_end)
        .await
        .expect("attach the drain");
    let events = pump_until(
        &mut conn,
        |event| matches!(event, ClientEvent::Held(HeldWork::WireLost { major }) if *major == one()),
    )
    .await;
    assert!(
        matches!(events.last(), Some(ClientEvent::Held(HeldWork::WireLost { major })) if *major == one()),
        "the dropped wire reports the held work it still carried"
    );
    assert!(
        conn.drain_timer().is_some(),
        "the held write is still owed after the drain wire dropped"
    );
    assert_eq!(conn.unsynced().len(), 1);
}
