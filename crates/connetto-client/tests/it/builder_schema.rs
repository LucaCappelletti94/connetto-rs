//! The schema piece of the builder: `SyncSchema::new` installs the `uuidv4()`
//! function a translated column default may call, so a device without a
//! server still mints the id.

use connetto_client::{ClientBuilder, SyncSchema};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use diesel::prelude::*;

/// The replica DDL the bundle carries, whose BLOB key takes a `uuidv4()`
/// default, the shape the translation emits for a Postgres `uuid` primary key.
const DDL: &str = "CREATE TABLE things (id BLOB PRIMARY KEY DEFAULT (uuidv4()), label TEXT);";

diesel::table! {
    /// Synced test table with a minted key.
    things (id) {
        /// The key the `uuidv4()` default mints.
        id -> Binary,
        /// The row's label.
        label -> Nullable<Text>,
    }
}

/// A replica whose DDL defaults a BLOB key with `uuidv4()` mints a distinct
/// 16-byte v4 key on every insert that leaves the key out.
#[test]
fn builder_schema_installs_uuidv4_for_a_default_key() {
    let schema = SyncSchema::new(SchemaBundle::new(
        "CREATE TABLE things (id UUID PRIMARY KEY, label TEXT);",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ));
    let mut conn = ClientBuilder::new(
        schema,
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .open_driven()
    .expect("open the replica with the bundle's DDL");
    diesel::insert_into(things::table)
        .values(things::label.eq("first"))
        .execute(conn.conn())
        .expect("insert the first row without naming the key");
    diesel::insert_into(things::table)
        .values(things::label.eq("second"))
        .execute(conn.conn())
        .expect("insert the second row without naming the key");

    let keys: Vec<Vec<u8>> = things::table
        .select(things::id)
        .order(things::label)
        .load(conn.conn())
        .expect("read the minted keys");
    assert_eq!(keys.len(), 2, "both rows took a key from the default");
    for (n, key) in keys.iter().enumerate() {
        assert_eq!(key.len(), 16, "a v4 uuid is sixteen bytes, row {n}");
        assert_eq!(
            key[6] & 0xF0,
            0x40,
            "the default mints a version-4 uuid, row {n}"
        );
        assert_eq!(
            key[8] & 0xC0,
            0x80,
            "the default mints a version-4 uuid, row {n}"
        );
    }
    assert_ne!(keys[0], keys[1], "two inserts mint distinct keys");
}
