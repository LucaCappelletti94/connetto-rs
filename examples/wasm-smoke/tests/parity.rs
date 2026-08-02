//! Relay parity: the worked example.
//!
//! This is the template every relay-parity phase (1 through 7) copies. It
//! runs one row live-query scenario against both a direct-to-server client and
//! a relay tab client and asserts they observe identical behavior: the same
//! snapshot rows, the same live patches, and byte-identical mirror state. Row
//! live queries already pass through both paths today, so this example is
//! green now and pins the parity contract. A later phase copies it, adds one
//! failing assertion for the leg it fixes (an aggregate value, a full-resync
//! deletion, a conflict distinction), then implements until it passes.
//!
//! Run with the demo stack up. See `authenticated_boot.rs` for the commands.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use common::mint_token;
use harness::{ParityFixture, connect_server, stage, unique_base, write_row};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A row live query is relay-transparent: a pre-existing row reaches both
/// clients through their snapshot, a subsequent write reaches both as a live
/// patch, and the two mirrors stay byte-identical throughout.
#[wasm_bindgen_test]
async fn row_live_query_is_relay_transparent() {
    let base = unique_base();

    // Each concurrent client needs a distinct session token.
    let writer_token = mint_token().await;
    let direct_token = mint_token().await;
    let relay_token = mint_token().await;

    // Seed a row BEFORE the fixture brings up the worker and both clients, so
    // it can only reach either client through the snapshot leg. The DEFAULT
    // mints the id, which the writer reads back for the convergence assertion.
    let mut writer = connect_server("parity-writer", base, writer_token).await;
    let snapshot_id = write_row(&mut writer, 1).await;
    stage("writer seeded the snapshot row");

    let mut fixture = ParityFixture::setup(base, "parity-orders", direct_token, relay_token).await;

    // Snapshot parity: both clients received the pre-existing row, and their
    // mirrors are identical.
    fixture.converge_row(snapshot_id).await;
    fixture.assert_mirrors_match();
    stage("snapshot parity verified");

    // Live-patch parity: a write after both subscribed reaches each client as
    // a live patch, not a re-snapshot, and the mirrors stay identical.
    let live_id = write_row(&mut writer, 2).await;
    fixture.converge_live_patch(live_id).await;
    fixture.assert_mirrors_match();
    stage("live patch parity verified");

    writer.close().await.expect("close writer");
    fixture.teardown().await;
}

/// An aggregate live query is relay-transparent: a `COUNT(*)` subscription
/// resolves to the same value through the relay as on a direct socket, and
/// both track a subsequent insert by exactly one. Before Phase 1 the relay
/// served the aggregate query as a row snapshot and never delivered an
/// `AggregateUpdate`, so the relay leg timed out.
#[wasm_bindgen_test]
async fn aggregate_is_relay_transparent() {
    let base = unique_base();

    let writer_token = mint_token().await;
    let direct_token = mint_token().await;
    let relay_token = mint_token().await;

    let mut writer = connect_server("parity-agg-writer", base, writer_token).await;
    let mut fixture = ParityFixture::setup(base, "parity-agg", direct_token, relay_token).await;

    // Both clients subscribe to the same global aggregate.
    fixture
        .subscribe_aggregate("agg-count", "SELECT COUNT(*) FROM orders")
        .await;
    let before = fixture.converge_aggregate("agg-count").await;
    stage("aggregate bootstrap parity verified");

    // A write after both subscribed bumps the count on both paths by one.
    write_row(&mut writer, 1).await;
    let after = fixture.converge_aggregate("agg-count").await;
    assert_eq!(
        after,
        before + 1,
        "the insert must bump the aggregate by one"
    );
    stage("aggregate update parity verified");

    writer.close().await.expect("close writer");
    fixture.teardown().await;
}
