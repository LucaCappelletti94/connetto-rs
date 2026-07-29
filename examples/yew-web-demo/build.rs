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

/// Translate one source document, write the SQLite DDL beside the template, and
/// bake the template database file.
///
/// The DDL text is an artifact in its own right because a tier that is encrypted
/// at rest cannot first-boot from a template: a baked byte image is a plaintext
/// database, the per-replica key does not exist at build time, and neither page
/// codec offers a plaintext-to-encrypted transform that works on both backends.
/// The template bake stays because it is where pg2sqlite validates the document,
/// including the reference closure that makes a foreign key across the tier
/// boundary fail this build.
fn bake(document: &str, template: &std::path::Path, ddl_out: &std::path::Path) {
    let pg_sql = std::fs::read_to_string(document).expect("read the source document");
    let statements = Pg2Sqlite::default()
        .sql(&pg_sql)
        .expect("parse the Postgres schema")
        .translate_to_sql(
            &Pg2SqliteOptions::default()
                .with_uuid_representation(UuidRepresentation::Blob)
                .with_uuid_function_name("uuidv7"),
        )
        .expect("translate the schema to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    std::fs::write(ddl_out, &ddl).expect("write the translated DDL");

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
    bake(
        "schema.sql",
        &out_dir.join("replica-template.sqlite"),
        &out_dir.join("replica-ddl.sql"),
    );
    bake(
        "frontend.sql",
        &out_dir.join("frontend-template.sqlite"),
        &out_dir.join("frontend-ddl.sql"),
    );
}
