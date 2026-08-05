//! Build-time schema pipeline: translate each Postgres dialect source
//! document to SQLite DDL through pg2sqlite and write it out as text, which
//! first boot applies. `schema.sql` is the shared tier (the synced replica),
//! `frontend.sql` the local tier (device-private, attached, never synced).
//! Each document is translated alone: the two are separate reference
//! universes, so pg2sqlite's reference-closure validation makes a foreign key
//! crossing the boundary fail this build. This is the pipeline a generated
//! schema crate would run, inlined here for the demo.

use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, TranslationOptions, UuidRepresentation};

/// Translate one source document and write the SQLite DDL to `ddl_out`.
///
/// The DDL is also applied to a throwaway in-memory database, which is the only
/// check that SQLite accepts what pg2sqlite emitted. It used to be applied to a
/// baked template file, and that file is gone: an encrypted replica cannot be
/// seeded from a plaintext byte image, so nothing imported it any more.
fn translate(document: &str, ddl_out: &std::path::Path) {
    let pg_sql = std::fs::read_to_string(document).expect("read the source document");
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
    std::fs::write(ddl_out, &ddl).expect("write the translated DDL");
    SqliteConnection::establish(":memory:")
        .expect("open the validation database")
        .batch_execute(&ddl)
        .expect("SQLite accepts the translated DDL");
}

fn main() {
    println!("cargo::rerun-if-changed=schema.sql");
    println!("cargo::rerun-if-changed=frontend.sql");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    translate("schema.sql", &out_dir.join("replica-ddl.sql"));
    translate("frontend.sql", &out_dir.join("frontend-ddl.sql"));
}
