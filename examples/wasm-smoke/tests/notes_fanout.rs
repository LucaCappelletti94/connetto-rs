//! Local tier fan-out through the relay hub: `notes` lives only in the DB
//! worker's frontend database, never in the worker replica or on the
//! server, yet every tab of the device sees every note.
//!
//! One test walks the legs: a tab's note write commits into the durable
//! tier and is acknowledged by the hub itself (the terminal authority for
//! the tier, there is no upstream leg), the sibling tab receives it as a
//! fanned out live patch, a tab connecting later receives it through the
//! hub's local snapshot leg, and a single mutation spanning both tiers is
//! rejected by the hub and rolled back on the writing tab.
//!
//! **Needs the stack up.** See `authenticated_boot.rs` for the commands.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test notes_fanout`

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_core::Transport;
use connetto_wasm_smoke::workers::{DEMO_TAB_DDL, announce_tab, await_db_worker_ready};
use connetto_wasm_smoke::{BroadcastTransport, leader, locks, uuidv7_functions};
use diesel::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The local tier subscription every tab registers.
const NOTES_QUERY: &str = "SELECT * FROM notes";

/// Progress marker for diagnosing a harness timeout: the stages appear in
/// the captured console output.
fn stage(message: &str) {
    web_sys::console::log_1(&message.into());
}

/// Relay the worker's breadcrumbs into the page console: a worker's
/// console is not always visible to the harness, so the bootstrap
/// broadcasts its progress and failures on this channel instead.
fn relay_worker_breadcrumbs() {
    let channel = web_sys::BroadcastChannel::new("connetto-debug").expect("broadcast channel");
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
        |event: web_sys::MessageEvent| {
            web_sys::console::log_1(&event.data());
        },
    );
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    // The channel itself must outlive the test to keep delivering.
    core::mem::forget(channel);
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
    }
}

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
}

/// Base for row ids unique across smoke runs, in this test's band.
fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    80_000_000_000 + millis
}

/// The served URL of this test's wasm-bindgen glue module, recovered from
/// the wasm fetch the harness already performed. The DB worker bootstrap
/// receives it as a query parameter.
fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .expect("query resource entries")
    .as_string()
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

/// Connect a tab client to the DB worker over its own wire channel. The
/// tab mirror holds both tiers in its main schema.
async fn connect_tab(client_id: &str) -> ConnettoConnection<BroadcastTransport> {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await;
    let transport = BroadcastTransport::new(&wire).expect("wire channel");
    let config = ClientConfig {
        client_id: client_id.to_owned(),
        auth_token: common::mint_token().await,
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: uuidv7_functions(),
    };
    ConnettoConnection::connect(transport, &Replica::Ephemeral, DEMO_TAB_DDL, &config, None)
        .await
        .expect("tab connect through the wire channel")
}

/// Pump `conn` until an event matches `pred`, applying every frame in
/// between. The harness timeout bounds the wait.
async fn pump_until<T>(
    conn: &mut ConnettoConnection<T>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

/// Pump `conn` until its local mirror holds the note row `id`.
async fn pump_until_note<T>(conn: &mut ConnettoConnection<T>, id: i64)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let rows: Vec<Note> = notes::table
            .filter(notes::id.eq(id))
            .load(conn.conn())
            .expect("local read");
        if !rows.is_empty() {
            return;
        }
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
    }
}

/// Subscribe one tab to the notes query and drain to the snapshot end.
async fn subscribe_notes<T>(conn: &mut ConnettoConnection<T>, sub_id: &str)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    conn.subscribe(sub_id, NOTES_QUERY)
        .await
        .expect("notes subscribe");
    pump_until(conn, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
}

#[wasm_bindgen_test]
async fn local_tier_notes_fan_out_across_tabs() {
    let base = unique_base();
    relay_worker_breadcrumbs();
    let note_id = base;
    let mixed_note_id = base + 1;

    // This page wins the leader election and owns the DB worker.
    let membership = leader::join(&format!("connetto-notes-leader-{base}"), &glue_url());
    await_db_worker_ready().await;
    stage("db worker ready");

    let client_a = format!("notes-tab-a-{base}");
    let lock_a = locks::hold_lock(&locks::tab_lock_name(&client_a)).await;
    let mut tab_a = connect_tab(&client_a).await;
    subscribe_notes(&mut tab_a, "tab-a-notes").await;
    stage("tab a subscribed");

    let client_b = format!("notes-tab-b-{base}");
    let lock_b = locks::hold_lock(&locks::tab_lock_name(&client_b)).await;
    let mut tab_b = connect_tab(&client_b).await;
    subscribe_notes(&mut tab_b, "tab-b-notes").await;
    stage("tab b subscribed");

    // A note written in tab A: the push produces a mutation (the tab
    // mirror captures both tiers, the hub keeps them apart), the hub
    // acknowledges it as the tier's terminal authority, and tab B receives
    // it as a fanned out live patch.
    diesel::insert_into(notes::table)
        .values((notes::id.eq(note_id), notes::body.eq("from tab a")))
        .execute(tab_a.conn())
        .expect("tab a note insert");
    let seq = tab_a
        .push()
        .await
        .expect("tab a push")
        .expect("a tab note write must produce a mutation");
    pump_until(
        &mut tab_a,
        |event| matches!(event, ClientEvent::MutationApplied { client_seq } if *client_seq == seq),
    )
    .await;
    stage("hub acknowledged the note");
    pump_until_note(&mut tab_b, note_id).await;
    stage("fan out verified");

    // A tab connecting later: the note reaches it through the hub's local
    // snapshot leg, served from the durable tier file.
    let client_c = format!("notes-tab-c-{base}");
    let lock_c = locks::hold_lock(&locks::tab_lock_name(&client_c)).await;
    let mut tab_c = connect_tab(&client_c).await;
    subscribe_notes(&mut tab_c, "tab-c-notes").await;
    let snap: Vec<Note> = notes::table
        .filter(notes::id.eq(note_id))
        .load(tab_c.conn())
        .expect("tab c read");
    assert_eq!(
        snap.len(),
        1,
        "the late tab receives the note in its snapshot"
    );
    stage("snapshot leg verified");

    // One transaction spanning both tiers: the hub rejects it (the local
    // half could not ride the rollback of an upstream rejection) and the
    // tab rolls the whole mutation back, both rows included.
    tab_a
        .conn()
        .transaction::<_, diesel::result::Error, _>(|conn| {
            diesel::insert_into(notes::table)
                .values((notes::id.eq(mixed_note_id), notes::body.eq("mixed")))
                .execute(conn)?;
            diesel::insert_into(orders::table)
                .values(orders::quantity.eq(1_i64))
                .execute(conn)?;
            Ok(())
        })
        .expect("mixed tier transaction");
    tab_a
        .push()
        .await
        .expect("mixed push")
        .expect("mutation sent");
    pump_until(&mut tab_a, |event| {
        matches!(event, ClientEvent::MutationRejected { .. })
    })
    .await;
    let leftover_notes: i64 = notes::table
        .filter(notes::id.eq(mixed_note_id))
        .count()
        .get_result(tab_a.conn())
        .expect("count mixed notes");
    let leftover_orders: i64 = orders::table
        .count()
        .get_result(tab_a.conn())
        .expect("count mixed orders");
    assert_eq!(leftover_notes, 0, "the rejected note is rolled back");
    assert_eq!(leftover_orders, 0, "the rejected order is rolled back");
    stage("mixed tier mutation rejected and rolled back");

    tab_a.close().await.expect("close tab a");
    tab_b.close().await.expect("close tab b");
    tab_c.close().await.expect("close tab c");
    lock_a.release();
    lock_b.release();
    lock_c.release();
    drop(membership);
}
