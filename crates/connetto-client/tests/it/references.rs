//! R92's shared proofs on the native backend.

#[path = "../shared/references.rs"]
mod cases;

#[test]
fn the_tier_keeps_its_references() {
    cases::the_tier_keeps_its_references();
}

#[test]
fn foreign_keys_are_on_for_every_replica() {
    cases::foreign_keys_are_on_for_every_replica();
}

#[tokio::test]
async fn an_orphan_from_the_server_lands_and_a_local_one_queues() {
    cases::an_orphan_from_the_server_lands_and_a_local_one_queues().await;
}

#[test]
fn every_action_applies_on_delete_and_update() {
    cases::every_action_applies_on_delete_and_update();
}

#[test]
fn a_null_reference_is_not_checked() {
    cases::a_null_reference_is_not_checked();
}

#[test]
fn composite_references_and_chains_hold() {
    cases::composite_references_and_chains_hold();
}

#[test]
fn a_hierarchy_twelve_levels_deep_cascades() {
    cases::a_hierarchy_twelve_levels_deep_cascades();
}

#[test]
fn a_deferred_reference_is_checked_at_commit() {
    cases::a_deferred_reference_is_checked_at_commit();
}

#[test]
fn an_import_of_a_child_table_created_first_restores() {
    cases::an_import_of_a_child_table_created_first_restores();
}

#[test]
fn an_import_of_reverse_ordered_self_references_restores() {
    cases::an_import_of_reverse_ordered_self_references_restores();
}

#[test]
fn an_orphan_aborts_the_import_and_checks_resume() {
    cases::an_orphan_aborts_the_import_and_checks_resume();
}
