//! The browser's writer leg of R75, against the live server.
//!
//! A browser profile's writer is a number the server issues and the worker's
//! durable replica keeps. A signed-in profile reboots under the number it was
//! issued, a restore of an already-settled write is answered from the
//! server's settled record, and a different changeset at a settled
//! (writer, sequence) is refused Forked.
//!
//! The browser-stack runner supplies Postgres, the identity provider and the
//! sync server.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use std::collections::HashSet;
use std::time::Duration;

use common::mint_session;
use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoConnection, ExportScope, Gate, HeldCredential, ReplicaKey,
    WriterRef,
};
use connetto_core::messages::{
    BulkMessage, Challenge, ControlMessage, Grant, Handshake, MutationApplied, MutationHeader,
    MutationPatch, MutationReject, MutationRejectReason, WriterGrant, WriterRequest,
};
use connetto_core::{IncomingFrame, PROTOCOL_VERSION, Transport};
use connetto_wasm_smoke::BrowserSocket;
use connetto_wasm_smoke::build;
use connetto_wasm_smoke::workers::{DEMO_WS_URL, demo_schema, sleep};
use connetto_web::auth::request_unsynced;
use connetto_web::workers::request_import;
use diesel::prelude::*;
use harness::{ParityFixture, load_orders, pump_until, unique_base};
use js_sys::{Array, Uint8Array};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DB_NAME: &str = "r75-writer-keep.sqlite";

/// A fixed key for this suite. What is under test is the writer number, not
/// the codec, which `connetto-web/tests/encrypted_replica.rs` covers.
fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
        created_at -> diesel::sql_types::Timestamp,
    }
}

/// A durable signed-in replica, created on the first boot and reopened after.
async fn connect(
    credential: &HeldCredential,
    first_boot: bool,
) -> ConnettoConnection<BrowserSocket> {
    ClientBuilder::new(demo_schema(), build::server())
        .signed_in(credential.clone())
        .durable(
            build::SuitePlace::new(DB_NAME, !first_boot),
            build::keys_for(credential, replica_key()).await,
            build::share_store().await,
        )
        .with_gate(Gate::off())
        .connect_driven()
        .await
        .expect("client connect")
}

/// Write one row under `writer` and upload it at `expected_seq`, leaving the
/// entry queued until its ack arrives. Returns the row id and the writer
/// number the write sits under.
async fn upload_one(
    writer: &mut ConnettoConnection<BrowserSocket>,
    identity: &str,
    expected_seq: u64,
) -> (rosetta_uuid::Uuid, u64) {
    let before: HashSet<rosetta_uuid::Uuid> =
        load_orders(writer).iter().map(|row| row.id).collect();
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq(identity), orders::quantity.eq(5_i64)))
        .execute(writer.conn())
        .expect("insert the row");
    let id = load_orders(writer)
        .iter()
        .map(|row| row.id)
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    writer.push().await.expect("push").expect("mutation sent");
    let unsynced = writer.unsynced();
    let [entry] = unsynced.as_slice() else {
        panic!("the written row must sit unsynced until the ack");
    };
    assert_eq!(
        entry.seq, expected_seq,
        "the write carries its expected sequence"
    );
    let WriterRef::Number(number) = entry.writer else {
        panic!("a keyless browser writes under a server-issued number");
    };
    (id, number)
}

/// Like [`upload_one`], then pump until the entry's ack settles it.
async fn settle_one(
    writer: &mut ConnettoConnection<BrowserSocket>,
    identity: &str,
    expected_seq: u64,
) -> (rosetta_uuid::Uuid, u64) {
    let (id, number) = upload_one(writer, identity, expected_seq).await;
    pump_until(writer, |event| {
        matches!(event, ClientEvent::MutationApplied { .. })
    })
    .await;
    assert!(
        writer.unsynced().is_empty(),
        "the settled write leaves the queue"
    );
    (id, number)
}

/// The worker's durable replica reboots under the writer number it was issued,
/// so a reloaded page keeps writing as the same writer and resumes its
/// sequences from the server's settled frontier.
#[wasm_bindgen_test]
async fn the_number_writer_survives_a_reload() {
    let (token, user_id) = mint_session().await;
    // A fixed file name across runs, so start from nothing.
    connetto_web::storage::ReplicaStorage::install()
        .await
        .delete_db(DB_NAME)
        .expect("clear an earlier replica");
    let credential = build::held(token, &user_id);

    // Boot one: a fresh replica is issued a number, its first write is
    // uploaded and settled server-side, but the ack is never read, so the
    // entry stays queued for the reload.
    let mut worker = connect(&credential, true).await;
    let (id, number) = upload_one(&mut worker, &user_id, 1).await;
    assert!(number > 0, "a fresh writer number starts at one or above");
    drop(worker);
    // Give the server a moment to settle the first write: a replay that
    // arrived before the original's apply would re-apply it and collide on
    // the primary key.
    sleep(Duration::from_secs(2)).await;

    // Boot two: the same replica reopens and replays the queued entry. The
    // server answers it from the stored outcome, so the ack arrives applied
    // rather than rejected: a lost number would have resent the row under a
    // fresh writer and the primary key would have refused it.
    let mut worker = connect(&credential, false).await;
    pump_until(&mut worker, |event| {
        matches!(event, ClientEvent::MutationApplied { .. })
    })
    .await;
    assert!(
        worker.unsynced().is_empty(),
        "the replayed entry settles from the stored outcome"
    );
    assert!(
        load_orders(&mut worker).iter().any(|row| row.id == id),
        "the first boot's row survived the reload"
    );

    // The session keeps the number: the next write is the writer's sequence
    // two, not a fresh writer's sequence one.
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq(&user_id), orders::quantity.eq(9_i64)))
        .execute(worker.conn())
        .expect("insert the row");
    worker.push().await.expect("push").expect("mutation sent");
    let unsynced = worker.unsynced();
    let [entry] = unsynced.as_slice() else {
        panic!("the written row must sit unsynced until the ack");
    };
    assert_eq!(
        entry.writer,
        WriterRef::Number(number),
        "the reloaded replica writes under its issued number"
    );
    assert_eq!(
        entry.seq, 2,
        "the sequences resume from the settled frontier, not from one"
    );
    pump_until(&mut worker, |event| {
        matches!(event, ClientEvent::MutationApplied { .. })
    })
    .await;
    assert!(worker.unsynced().is_empty());
}

/// A restore of a write the server already settled is answered from the
/// settled record. The direct client settles a row, exports its unsynced
/// entry, and the worker imports it: the worker's entry carries the original
/// (writer, sequence) as provenance, the server settles the new sequence from
/// the stored outcome, and neither mirror ends up with a second copy.
#[wasm_bindgen_test]
async fn a_restore_of_a_settled_write_is_answered_from_the_settled_record() {
    let base = unique_base();
    let (token, user_id) = mint_session().await;
    let mut fixture = ParityFixture::setup(base, "writer-restore", token, &user_id).await;

    // The direct client writes one row and uploads it, exporting its unsynced
    // tail before the ack retires it, the archive of a profile that wrote and
    // then caught up.
    let before: HashSet<rosetta_uuid::Uuid> = load_orders(&mut fixture.direct)
        .iter()
        .map(|row| row.id)
        .collect();
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq(&user_id), orders::quantity.eq(5_i64)))
        .execute(fixture.direct.conn())
        .expect("insert the row");
    let id = load_orders(&mut fixture.direct)
        .iter()
        .map(|row| row.id)
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    fixture
        .direct
        .push()
        .await
        .expect("push")
        .expect("mutation sent");
    let unsynced = fixture.direct.unsynced();
    let [entry] = unsynced.as_slice() else {
        panic!("the written row must sit unsynced until the ack");
    };
    assert_eq!(entry.seq, 1, "a fresh writer starts its sequences at one");
    assert!(
        matches!(entry.writer, WriterRef::Number(_)),
        "a keyless browser writes under a server-issued number"
    );

    // The export scopes only the unsynced tail, then the server settles the
    // write on the direct path.
    let archive = fixture
        .direct
        .export_local_data(ExportScope::Unsynced, Vec::new())
        .expect("export the unsynced tail");
    pump_until(&mut fixture.direct, |event| {
        matches!(event, ClientEvent::MutationApplied { .. })
    })
    .await;
    assert!(
        fixture.direct.unsynced().is_empty(),
        "the write settled on the direct path"
    );

    // Both mirrors already hold the row, so the import's local apply omits it
    // and only its unsynced entry is restored.
    fixture.converge_row(id).await;

    let blob = {
        let array = Uint8Array::from(archive.as_slice());
        web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&array)).expect("blob from bytes")
    };
    let (outcome, _) = request_import(blob)
        .await
        .expect("the worker imports the archive");
    assert_eq!(
        outcome.writes_restored, 1,
        "the archive's one unsynced entry is restored"
    );

    // The worker replays the restored entry with its provenance, the server
    // settles the new sequence from the stored outcome, and the queue drains.
    for _ in 0..200 {
        let pending = request_unsynced().await.expect("the worker answers");
        if pending.unsynced.is_empty() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let pending = request_unsynced().await.expect("the worker answers");
    assert!(
        pending.unsynced.is_empty(),
        "the restored entry settled from the stored outcome, not a re-apply"
    );

    // Neither mirror gained a second copy of the row.
    assert_eq!(
        load_orders(&mut fixture.direct)
            .iter()
            .filter(|row| row.id == id)
            .count(),
        1,
        "the direct mirror holds the row once"
    );
    assert_eq!(
        load_orders(&mut fixture.relay)
            .iter()
            .filter(|row| row.id == id)
            .count(),
        1,
        "the worker's mirror holds the row once"
    );
}

/// A different changeset at a settled (writer, sequence) is refused Forked.
/// The forged write goes over a raw socket, because the client refuses to send
/// a changeset the server would fork. The socket presents the direct client's
/// grant, so it takes over that session handle and the direct client is done.
#[wasm_bindgen_test]
async fn a_forged_changeset_at_a_settled_sequence_is_refused_forked() {
    use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};

    let base = unique_base();
    let (token, user_id) = mint_session().await;
    let mut fixture = ParityFixture::setup(base, "writer-fork", token.clone(), &user_id).await;

    // Settle one row under the direct client's number.
    let (_, number) = settle_one(&mut fixture.direct, &user_id, 1).await;

    // A valid insert the server never saw, compressed as the bulk frame carries it.
    let insert_patch = |id: rosetta_uuid::Uuid| {
        let table = SimpleTable::new(
            "orders",
            &["id", "owner_id", "quantity", "created_at"],
            &[0],
        );
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Blob(<[u8; 16]>::from(id).to_vec()))
            .expect("set the id")
            .set(1, Value::Text(user_id.clone()))
            .expect("set the owner")
            .set(2, Value::Integer(5))
            .expect("set the quantity")
            .set(3, Value::Text(common::now_rfc3339()))
            .expect("set the created at");
        let changeset = ChangeSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        zstd::encode_all(changeset.as_slice(), 3).expect("compress the changeset")
    };
    let patchset = insert_patch(rosetta_uuid::Uuid::new_v4());

    let mut socket = BrowserSocket::connect(DEMO_WS_URL)
        .await
        .expect("dial the server");
    socket
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, rosetta_uuid::Uuid::new_v4().to_string())
                .with_grant(Grant::new(token))
                .with_writer(WriterRequest::Number(number)),
        ))
        .await
        .expect("handshake");

    // Every connection opens with the R91 challenge before the ack.
    match socket
        .recv()
        .await
        .expect("recv the challenge")
        .expect("the connection stays open")
    {
        IncomingFrame::Control(ControlMessage::Challenge(Challenge { .. })) => {}
        other => panic!("the challenge opens every connection, got {other:?}"),
    }

    // The server confirms the number at its settled frontier.
    match socket
        .recv()
        .await
        .expect("recv the ack")
        .expect("the connection stays open")
    {
        IncomingFrame::Control(ControlMessage::HandshakeAck(ack)) => {
            assert_eq!(
                ack.writer,
                Some(WriterGrant {
                    number,
                    frontier: 1
                }),
                "the confirmed number carries its settled frontier"
            );
        }
        other => panic!("the handshake answers with its ack, got {other:?}"),
    }

    // The forged write at the settled sequence is refused Forked.
    socket
        .send_control(ControlMessage::MutationHeader(MutationHeader::new(1, 1)))
        .await
        .expect("announce the mutation");
    socket
        .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(1, patchset)))
        .await
        .expect("send the changeset");
    match socket
        .recv()
        .await
        .expect("recv the refusal")
        .expect("the connection stays open")
    {
        IncomingFrame::Control(ControlMessage::MutationReject(MutationReject {
            client_seq,
            reason,
        })) => {
            assert_eq!(client_seq, 1);
            assert!(
                matches!(reason, MutationRejectReason::Forked),
                "a different changeset at a settled sequence forks, got {reason:?}"
            );
        }
        other => panic!("the forged write is refused, got {other:?}"),
    }

    // The refusal settled nothing: a correct write at the next sequence still
    // lands under the same number.
    socket
        .send_control(ControlMessage::MutationHeader(MutationHeader::new(2, 1)))
        .await
        .expect("announce the next mutation");
    socket
        .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(
            2,
            insert_patch(rosetta_uuid::Uuid::new_v4()),
        )))
        .await
        .expect("send the next changeset");
    match socket
        .recv()
        .await
        .expect("recv the answer")
        .expect("the connection stays open")
    {
        IncomingFrame::Control(ControlMessage::MutationApplied(MutationApplied { client_seq })) => {
            assert_eq!(
                client_seq, 2,
                "the number is still live after the fork refusal"
            );
        }
        other => panic!("the write after the refusal lands, got {other:?}"),
    }
}
