//! Build-time schema pipeline: translate each Postgres dialect source
//! document to SQLite DDL through pg2sqlite and apply it to a fresh SQLite
//! database, so the app ships every tier's schema pre-applied and never
//! executes DDL at startup (SQLite's file format is its own deployable
//! artifact). `schema.sql` is the shared tier (the synced replica),
//! `frontend.sql` the local tier (device-private, attached, never synced).
//! Each document is translated alone: the two are separate reference
//! universes, so pg2sqlite's reference-closure validation makes a foreign key
//! crossing the boundary fail this build. This is the pipeline a generated
//! schema crate would run, inlined here for the demo.

use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, TranslationOptions, UuidRepresentation};

/// Translate one source document and bake it into a template database file.
fn bake(document: &str, template: &std::path::Path) {
    let pg_sql = std::fs::read_to_string(document).expect("read the source document");
    let statements = Pg2Sqlite::default()
        .sql(&pg_sql)
        .expect("parse the Postgres schema")
        .translate_to_sql(
            &Pg2SqliteOptions::default().with_uuid_representation(UuidRepresentation::Blob),
        )
        .expect("translate the schema to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');

    // Rebuild the template from scratch so a schema edit never layers onto a
    // stale file.
    let _ = std::fs::remove_file(template);
    let mut conn = SqliteConnection::establish(template.to_str().expect("utf8 OUT_DIR"))
        .expect("create the template database");
    conn.batch_execute(&ddl)
        .expect("apply the translated DDL to the template");
}

fn main() {
    println!("cargo::rerun-if-changed=schema.sql");
    println!("cargo::rerun-if-changed=frontend.sql");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    bake("schema.sql", &out_dir.join("replica-template.sqlite"));
    bake("frontend.sql", &out_dir.join("frontend-template.sqlite"));
}
