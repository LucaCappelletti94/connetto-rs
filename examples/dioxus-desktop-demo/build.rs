//! Build-time schema pipeline: translate the Postgres dialect schema in
//! `schema.sql` to SQLite DDL through pg2sqlite and write the result as
//! `replica-ddl.sql` for the app to read at compile time.

use diesel::connection::SimpleConnection;
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use pg2sqlite::prelude::{
    Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, TranslationOptions, UuidRepresentation,
    WrapperKind,
};

/// The replica's local name for the caller identity a policy compares against.
/// The app registers a SQLite function under this name on every connection
/// connetto opens, returning the identity the replica was opened for.
const CALLER_FUNCTION: &str = "current_app_user";

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

fn options() -> Pg2SqliteOptions {
    Pg2SqliteOptions::default()
        .with_uuid_representation(UuidRepresentation::Blob)
        .with_uuid_function_name("uuidv4")
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            CALLER_FUNCTION,
        ))
        .with_rls_audit_table_name("rls_audit".to_string())
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

/// Write the logical-to-physical map and the view list the client is
/// configured with, as Rust source the crate includes.
fn write_policy_tables(documents: &[&str], views: &[String], out: &std::path::Path) {
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

fn main() {
    println!("cargo::rerun-if-changed=schema.sql");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    let statements = parsed(&["schema.sql"])
        .translate_to_sql(&options())
        .expect("translate the schema to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    std::fs::write(out_dir.join("replica-ddl.sql"), &ddl).expect("write replica-ddl.sql");
    // Applying the translation to a throwaway database is the only check that
    // SQLite accepts what pg2sqlite emitted. It used to land in a baked template
    // the app imported, and that file is gone: an encrypted replica cannot be
    // seeded from a plaintext byte image.
    let mut probe = SqliteConnection::establish(":memory:").expect("open the validation database");
    probe
        .batch_execute(&ddl)
        .expect("SQLite accepts the translated DDL");
    let synced_views = sqlite_catalog::table
        .select(sqlite_catalog::name)
        .filter(sqlite_catalog::kind.eq("view"))
        .load::<String>(&mut probe)
        .expect("list the views the translation created");
    // The synced tier only: this schema has no local tier.
    write_policy_tables(
        &["schema.sql"],
        &synced_views,
        &out_dir.join("replica-tables.rs"),
    );
}
