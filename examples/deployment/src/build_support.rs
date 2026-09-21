//! The build-time translation each demo's build script runs.
//!
//! Every demo translates the same synced tier through pg2sqlite and writes the
//! same three artifacts, so the pipeline lives here once. A demo's own local
//! tier is passed in, because that document is the demo's and differs.
//!
//! This is the pipeline a generated schema crate would run, inlined for the
//! demos. Each tier is translated alone: they are separate reference universes,
//! so pg2sqlite's reference-closure validation makes a foreign key crossing the
//! boundary fail the build.

use std::path::Path;

use diesel::connection::SimpleConnection;
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use pg2sqlite::prelude::{
    Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation, WrapperKind,
};

diesel::table! {
    /// SQLite's own catalogue, read to list the views the translation created.
    /// Deducing them from the table names instead would bake pg2sqlite's
    /// naming into this build, which is the drift the generated map avoids.
    #[sql_name = "sqlite_schema"]
    sqlite_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
    }
}

/// How this deployment's documents translate: its uuid representation, the two
/// caller settings its policies read, and the write exemption connetto holds
/// while applying its own writes.
///
/// The exemption name is `connetto_client::WRITE_EXEMPTION_FUNCTION`, spelled
/// here because a build script cannot cheaply depend on the client crate.
/// connetto registers it on every replica connection and holds it true only
/// while applying its own writes, so the fail-closed guards admit server data.
#[must_use]
pub fn options() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_uuid_representation(UuidRepresentation::Blob)
        .with_uuid_function_name("uuidv4")
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            crate::CALLER_FUNCTION,
        ))
        .with_session_variable(
            SessionVariableMapping::current_setting("app.subjects", crate::SUBJECTS_FUNCTION)
                .holding_set(crate::SUBJECTS_SEPARATOR),
        )
        .with_rls_audit_table_name("rls_audit".to_string())
        .with_write_exemption_function("connetto_write_exempt")
}

/// Translate the shared synced tier and the demo's own local tier, and write
/// the three artifacts a demo includes: `replica-ddl.sql`, `frontend-ddl.sql`
/// and `replica-tables.rs`.
///
/// `frontend` is the path to the demo's local-tier document, relative to its
/// own manifest directory, or `None` for a demo with no local tier. The rerun
/// directives for every document read are emitted here, so a build script
/// naming them again cannot fall out of step with what this reads.
///
/// # Panics
///
/// Every failure here is a broken build rather than a runtime condition: a
/// document that does not parse, a translation SQLite refuses, or an artifact
/// that cannot be written.
pub fn emit(frontend: Option<&str>, out_dir: &Path) {
    let synced = [shared("schema.sql"), shared("policies.sql")];
    for document in &synced {
        println!("cargo::rerun-if-changed={document}");
    }
    let synced: Vec<&str> = synced.iter().map(String::as_str).collect();
    let views = translate(&synced, &out_dir.join("replica-ddl.sql"));
    if let Some(frontend) = frontend {
        println!("cargo::rerun-if-changed={frontend}");
        translate(&[frontend], &out_dir.join("frontend-ddl.sql"));
    }
    // The synced tier only: the local tier is a separate database, attached
    // under its own schema, and the check the map feeds reads `main`.
    write_policy_tables(&synced, &views, &out_dir.join("replica-tables.rs"));
}

/// One shared document, named absolutely so a build script's own working
/// directory does not enter into it.
fn shared(name: &str) -> String {
    format!("{}/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Parse every document in `documents` into one translator.
fn parsed(documents: &[&str]) -> Pg2Sqlite {
    documents
        .iter()
        .fold(Pg2Sqlite::default(), |acc, document| {
            let pg_sql = std::fs::read_to_string(document).expect("read the source document");
            acc.sql(&pg_sql).expect("parse the Postgres schema")
        })
}

/// Translate one tier, write its SQLite DDL to `ddl_path`, and report the
/// views the translation created.
///
/// The DDL is also applied to a throwaway in-memory database, which is the only
/// check that SQLite accepts what pg2sqlite emitted. That same database is what
/// the view list is read from, so the artifact records what the translation
/// actually built rather than what it was expected to.
fn translate(documents: &[&str], ddl_path: &Path) -> Vec<String> {
    let statements = parsed(documents)
        .translate_to_sql(&options())
        .expect("translate the schema to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    std::fs::write(ddl_path, &ddl).expect("write the translated DDL");
    let mut probe = SqliteConnection::establish(":memory:").expect("open the validation database");
    probe
        .batch_execute(&ddl)
        .expect("SQLite accepts the translated DDL");
    sqlite_catalog::table
        .select(sqlite_catalog::name)
        .filter(sqlite_catalog::kind.eq("view"))
        .load::<String>(&mut probe)
        .expect("list the views the translation created")
}

/// Write the logical-to-physical map and the view list the client is
/// configured with, as Rust source the demo includes.
fn write_policy_tables(documents: &[&str], views: &[String], out: &Path) {
    let manifest = parsed(documents)
        .translation_manifest(&options())
        .expect("report the translation manifest");
    let pairs = manifest
        .iter()
        .filter(|entry| entry.wrapper == WrapperKind::RlsView)
        .map(|entry| format!("    ({:?}, {:?}),\n", entry.logical, entry.physical))
        .collect::<String>();
    let views = views
        .iter()
        .map(|name| format!("    {name:?},\n"))
        .collect::<String>();
    let source = format!(
        "/// Tables the row-level-security translation split, as (logical, physical).\n\
         pub const POLICY_TABLES: &[(&str, &str)] = &[\n{pairs}];\n\n\
         /// Every view that translation emitted, which the replica is checked against.\n\
         pub const POLICY_VIEWS: &[&str] = &[\n{views}];\n"
    );
    std::fs::write(out, source).expect("write the policy-table map");
}
