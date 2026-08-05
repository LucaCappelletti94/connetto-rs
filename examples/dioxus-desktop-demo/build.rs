//! Build-time schema pipeline: translate the Postgres dialect schema in
//! `schema.sql` to SQLite DDL through pg2sqlite and write the result as
//! `replica-ddl.sql` for the app to read at compile time.

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
                .with_uuid_function_name("uuidv4"),
        )
        .expect("translate the schema to SQLite");
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    std::fs::write(out_dir.join("replica-ddl.sql"), &ddl).expect("write replica-ddl.sql");
    // Applying the translation to a throwaway database is the only check that
    // SQLite accepts what pg2sqlite emitted. It used to land in a baked template
    // the app imported, and that file is gone: an encrypted replica cannot be
    // seeded from a plaintext byte image.
    SqliteConnection::establish(":memory:")
        .expect("open the validation database")
        .batch_execute(&ddl)
        .expect("SQLite accepts the translated DDL");
}
