//! R92's shared proofs on the browser backend, whose SQLite enforces no
//! references unless connetto turns enforcement on.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

#[path = "../../connetto-client/tests/shared/references.rs"]
mod cases;

use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
fn stripping_keeps_the_rest_of_each_table() {
    cases::stripping_keeps_the_rest_of_each_table();
}

#[wasm_bindgen_test]
fn an_unparsable_replica_schema_refuses_the_open() {
    cases::an_unparsable_replica_schema_refuses_the_open();
}

#[wasm_bindgen_test]
fn the_tier_keeps_its_references_and_synced_tables_lose_theirs() {
    cases::the_tier_keeps_its_references_and_synced_tables_lose_theirs();
}

#[wasm_bindgen_test]
fn foreign_keys_are_on_for_every_replica() {
    cases::foreign_keys_are_on_for_every_replica();
}

#[wasm_bindgen_test]
async fn an_orphan_from_the_server_lands_and_a_local_one_queues() {
    cases::an_orphan_from_the_server_lands_and_a_local_one_queues().await;
}

#[wasm_bindgen_test]
fn every_action_applies_on_delete_and_update() {
    cases::every_action_applies_on_delete_and_update();
}

#[wasm_bindgen_test]
fn a_null_reference_is_not_checked() {
    cases::a_null_reference_is_not_checked();
}

#[wasm_bindgen_test]
fn composite_references_and_chains_hold() {
    cases::composite_references_and_chains_hold();
}

#[wasm_bindgen_test]
fn a_hierarchy_twelve_levels_deep_cascades() {
    cases::a_hierarchy_twelve_levels_deep_cascades();
}

#[wasm_bindgen_test]
fn a_deferred_reference_is_checked_at_commit() {
    cases::a_deferred_reference_is_checked_at_commit();
}

#[wasm_bindgen_test]
fn an_import_of_a_child_table_created_first_restores() {
    cases::an_import_of_a_child_table_created_first_restores();
}

#[wasm_bindgen_test]
fn an_import_of_reverse_ordered_self_references_restores() {
    cases::an_import_of_reverse_ordered_self_references_restores();
}

#[wasm_bindgen_test]
fn an_orphan_aborts_the_import_and_checks_resume() {
    cases::an_orphan_aborts_the_import_and_checks_resume();
}
