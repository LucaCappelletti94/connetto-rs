//! Build-time schema pipeline: translate the Postgres dialect schema in
//! `schema.sql` to SQLite DDL through pg2sqlite, apply it to a fresh SQLite
//! database, and hand the resulting file to the app as bytes. SQLite's file
//! format is its own deployable artifact, so the app ships the schema
//! pre-applied and never executes DDL at startup. This is the pipeline a
//! generated schema crate would run, inlined here for the demo.

use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, TranslationOptions, UuidRepresentation};

fn main() {
    println!("cargo::rerun-if-changed=schema.sql");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let pg_sql = std::fs::read_to_string("schema.sql").expect("read schema.sql");

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
    // Also expose the DDL as a text file so the app can seed a fresh encrypted
    // replica through `ConnettoConnection::connect` with DDL (the template
    // approach only seeds a plaintext file; an encrypted first-boot uses DDL).
    std::fs::write(out_dir.join("replica-ddl.sql"), &ddl).expect("write replica-ddl.sql");

    let template = out_dir.join("replica-template.sqlite");
    // Rebuild the template from scratch so a schema edit never layers onto a
    // stale file.
    let _ = std::fs::remove_file(&template);
    let mut conn = SqliteConnection::establish(template.to_str().expect("utf8 OUT_DIR"))
        .expect("create the template database");
    conn.batch_execute(&ddl)
        .expect("apply the translated DDL to the template");
}
