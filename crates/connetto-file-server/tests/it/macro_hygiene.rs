//! `connetto_file_tables!` expands in a module that imports nothing.

mod bare {
    connetto_file_server::connetto_file_tables!();
}

/// A generated impl builds statements against the deployment's own table names.
#[test]
fn the_expansion_needs_no_imports_at_the_call_site() {
    use connetto_file_server::ConnettoFileSchema;

    let sql = diesel::debug_query::<diesel::pg::Pg, _>(
        &bare::ConnettoFileSchemaImpl::delete_registry_row_stmt(vec![0u8; 32]),
    )
    .to_string();

    assert!(
        sql.contains(bare::ConnettoFileSchemaImpl::CHUNK_REGISTRY_SQL),
        "the statement names the registry table: {sql}"
    );
}
