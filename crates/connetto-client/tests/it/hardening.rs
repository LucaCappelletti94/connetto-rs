//! R18: the hardening a replica connection carries, and what its attach posture
//! refuses.
//!
//! Every value is read back through its own getter rather than assumed, so a
//! changed default upstream fails here instead of being inherited silently. The
//! limits deliberately left at stock are asserted too, because leaving them
//! stock is a decision and a later pass that hardens them would break ordinary
//! application queries (a four-row batch insert, an eleven-key lookup).
//!
//! The attach half is behavioral: at rest nothing may attach at all, a window
//! that does not permit creation refuses a missing file without leaving one
//! behind, and a database attached inside a window stays writable after it
//! closes, which is what keeps the local tier usable.

use std::sync::Arc;

use connetto_client::harden::{AttachPermits, attach_in_window};
use connetto_client::{
    ClientBuilder, ConnettoConnection, DataDir, HeldCredential, SqlFunctions, SyncSchema,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sqlite::{SqliteFunctionBehavior, SqliteLimit};
use tempfile::{TempDir, tempdir};

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";

diesel::table! {
    /// Device-private test table, which lives in the attached tier.
    drafts (id) {
        /// Draft identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Draft body text.
        body -> diesel::sql_types::Text,
    }
}

#[diesel::declare_sql_function]
extern "SQL" {
    /// A stand-in for an application's key generator, called from a column
    /// `DEFAULT`.
    fn next_seq() -> diesel::sql_types::BigInt;
}

diesel::table! {
    /// Table whose key is minted by a registered function.
    minted (id) {
        /// Item identifier, minted by the function.
        id -> diesel::sql_types::BigInt,
        /// Item label.
        label -> diesel::sql_types::Text,
    }
}

diesel::table! {
    /// The plain replica's table, for the LIKE dialect check.
    items (id) {
        /// Item identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Item label, matched with LIKE.
        label -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// The identity this module's builds sign in as.
fn credential() -> HeldCredential {
    super::support::held("tester")
}

/// A replica in its own directory, opened offline, with no tier.
async fn open_plain(dir: &TempDir) -> ConnettoConnection<FakeTransport> {
    let credential = credential();
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("open")
}

/// Create a plaintext database at `path` so an attach has something to find.
fn seed(path: &str) {
    let mut conn = diesel::SqliteConnection::establish(path).expect("seed open");
    conn.batch_execute("CREATE TABLE seeded (id INTEGER PRIMARY KEY)")
        .expect("seed schema");
}

#[tokio::test]
async fn every_configured_knob_holds_on_a_fresh_replica() {
    let dir = tempdir().expect("tempdir");
    let mut conn = open_plain(&dir).await;
    let db = conn.conn();

    assert!(
        db.is_defensive().expect("read defensive"),
        "defensive mode is what stops a patchset authored elsewhere writing shadow tables"
    );
    assert!(
        !db.is_trusted_schema().expect("read trusted schema"),
        "a schema object may only call functions registered INNOCUOUS"
    );
    assert!(
        !db.is_attach_create_enabled().expect("read attach create"),
        "at rest an attach may not create a database file"
    );
    assert!(
        !db.is_attach_write_enabled().expect("read attach write"),
        "at rest an attach may not open a database for writing"
    );
    assert_eq!(
        db.get_limit(SqliteLimit::Attached),
        0,
        "this replica has no tier, so its ceiling is nothing at all"
    );

    assert_eq!(db.get_limit(SqliteLimit::FunctionArg), 8, "function arity");
    assert_eq!(db.get_limit(SqliteLimit::TriggerDepth), 10, "trigger depth");
    assert_eq!(
        db.get_limit(SqliteLimit::VdbeOp),
        25_000,
        "instructions per compiled statement"
    );
    assert_eq!(
        db.get_limit(SqliteLimit::WorkerThreads),
        0,
        "no sorter threads"
    );

    // Left at stock on purpose: each one bounds a shape an application writes.
    assert!(
        db.get_limit(SqliteLimit::VariableNumber) >= 32_766,
        "a batch insert and a key list bind more than a hardened ceiling allows"
    );
    assert!(
        db.get_limit(SqliteLimit::ExprDepth) >= 1_000,
        "diesel nests one AND per chained filter"
    );
    assert!(
        db.get_limit(SqliteLimit::LikePatternLength) >= 50_000,
        "a search box supplies the LIKE pattern"
    );
    assert!(
        db.get_limit(SqliteLimit::Length) >= 1_000_000_000,
        "a stored document exceeds a megabyte"
    );
    assert!(
        db.get_limit(SqliteLimit::CompoundSelect) >= 500,
        "an application may union more than three selects"
    );
    assert!(
        db.get_limit(SqliteLimit::ColumnCount) >= 2_000,
        "an application table may be wide"
    );
    assert!(
        db.get_limit(SqliteLimit::SqlLength) >= 1_000_000_000,
        "a generated statement may be long"
    );
}

#[tokio::test]
async fn a_tier_rests_at_one_attached_database_and_stays_writable() {
    let dir = tempdir().expect("tempdir");
    let credential = credential();
    let store = super::support::key_store(&credential).await;
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        Some(TIER_DDL),
    ));
    let mut conn = ClientBuilder::new(
        schema,
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("open");

    assert_eq!(
        conn.conn().get_limit(SqliteLimit::Attached),
        1,
        "the tier is attached, and it is the only thing that may be"
    );
    assert!(
        !conn
            .conn()
            .is_attach_write_enabled()
            .expect("read attach write"),
        "the window closed behind the tier"
    );

    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1), drafts::body.eq("written at rest")))
        .execute(conn.conn())
        .expect("the tier stays writable once its window has closed");

    let other = dir.path().join("other.sqlite");
    let other = other.to_str().expect("utf-8 path");
    seed(other);
    assert!(
        conn.conn().attach_database(other, "other").is_err(),
        "a second attach does not fit under the ceiling"
    );
}

#[tokio::test]
async fn a_window_without_the_create_permit_refuses_a_missing_file() {
    let dir = tempdir().expect("tempdir");
    let mut conn = open_plain(&dir).await;
    let missing = dir.path().join("absent.sqlite");
    let missing_path = missing.to_str().expect("utf-8 path");

    assert!(
        attach_in_window(conn.conn(), missing_path, "absent", AttachPermits::Write).is_err(),
        "a write window may not create the file it cannot find"
    );
    assert!(
        !missing.exists(),
        "the refusal left no empty database behind"
    );
    assert_eq!(
        conn.conn().get_limit(SqliteLimit::Attached),
        0,
        "the window sealed itself even though the attach failed"
    );
    assert!(
        !conn
            .conn()
            .is_attach_write_enabled()
            .expect("read attach write"),
        "and the write permit closed with it"
    );
}

#[tokio::test]
async fn a_missing_tier_file_fails_the_open_rather_than_appearing() {
    let dir = tempdir().expect("tempdir");
    let credential = credential();
    let name = credential.replica_name().to_owned();
    let tier = dir.path().join(format!("{name}-tier"));
    open_plain(&dir).await;
    let store = super::support::key_store(&credential).await;
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        Some(TIER_DDL),
    ));
    assert!(
        ClientBuilder::new(
            schema,
            super::support::NeverDial::<FakeTransport>::default(),
        )
        .signed_in(credential)
        .durable(DataDir::new(dir.path().to_path_buf()), store)
        .open_driven()
        .await
        .is_err(),
        "an existing tier that does not exist is an error, not an empty database"
    );
    assert!(!tier.exists(), "and no file was created for it");
}

#[tokio::test]
async fn a_create_window_creates_the_file_and_leaves_it_writable() {
    let dir = tempdir().expect("tempdir");
    let mut conn = open_plain(&dir).await;
    let store = dir.path().join("store.sqlite");
    let store_path = store.to_str().expect("utf-8 path");

    attach_in_window(
        conn.conn(),
        store_path,
        "store",
        AttachPermits::CreateAndWrite,
    )
    .expect("a create window attaches a database that does not exist yet");
    assert!(store.exists(), "the window created the file");
    assert_eq!(
        conn.conn().get_limit(SqliteLimit::Attached),
        1,
        "the ceiling followed the attach"
    );

    conn.conn()
        .batch_execute("CREATE TABLE store.rows (id INTEGER PRIMARY KEY)")
        .expect("what a create window attached stays writable after it closes");

    let second = dir.path().join("second.sqlite");
    assert!(
        attach_in_window(
            conn.conn(),
            second.to_str().expect("utf-8 path"),
            "second",
            AttachPermits::Write,
        )
        .is_err(),
        "a window still refuses a file that is not there"
    );
}

#[tokio::test]
async fn a_column_default_may_only_call_an_innocuous_function() {
    const MINTED_DDL: &str = "CREATE TABLE minted \
        (id BIGINT PRIMARY KEY DEFAULT (next_seq()) NOT NULL, label TEXT NOT NULL)";

    // The registrar an application writes without reading the rule: the function
    // exists, and the DEFAULT that calls it is refused when it fires.
    let plain = SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        next_seq_utils::register_nondeterministic_impl(conn, || 1i64)
    }));
    let dir = tempdir().expect("tempdir");
    let first = credential();
    let store = super::support::key_store(&first).await;
    let mut conn = ClientBuilder::new(
        super::support::bundle(MINTED_DDL).with_sql_functions(plain),
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(first)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("registering it and creating the table both succeed");
    let refused = diesel::insert_into(minted::table)
        .values(minted::label.eq("first"))
        .execute(conn.conn())
        .expect_err("trusted schema is off, so the DEFAULT may not call it");
    assert!(
        refused.to_string().contains("unsafe use of next_seq"),
        "the refusal names the function, and it is what an application sees: {refused}"
    );

    // The same registrar with the flag the rule asks for.
    let innocuous = SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        next_seq_utils::register_impl_with_behavior(conn, SqliteFunctionBehavior::INNOCUOUS, || {
            7i64
        })
    }));
    let dir = tempdir().expect("tempdir");
    let second = credential();
    let store = super::support::key_store(&second).await;
    let mut conn = ClientBuilder::new(
        super::support::bundle(MINTED_DDL).with_sql_functions(innocuous),
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(second)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("open");
    diesel::insert_into(minted::table)
        .values(minted::label.eq("first"))
        .execute(conn.conn())
        .expect("an INNOCUOUS function may be called from a column DEFAULT");
    assert_eq!(
        minted::table
            .select(minted::id)
            .load::<i64>(conn.conn())
            .expect("read back"),
        vec![7],
        "and the value came from the function rather than from a fold"
    );
}

/// The translated schema is Postgres's dialect, where `LIKE` is case
/// sensitive, and the pragma that makes SQLite agree is connection state, so
/// a reopen that runs no DDL must set it as much as the first boot does.
#[tokio::test]
async fn like_is_case_sensitive_on_a_first_boot_and_on_a_reopen() {
    let dir = tempdir().expect("tempdir");
    let first = credential();
    let store = super::support::key_store(&first).await;
    let lowercase_matches = |conn: &mut ConnettoConnection<FakeTransport>| {
        items::table
            .filter(items::label.like("a%"))
            .count()
            .get_result::<i64>(conn.conn())
            .expect("count the lowercase matches")
    };

    let mut conn = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(first)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("open");
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("Alpha")))
        .execute(conn.conn())
        .expect("insert");
    assert_eq!(
        lowercase_matches(&mut conn),
        0,
        "a first boot matches like Postgres"
    );
    drop(conn);

    let reopened = credential();
    let store = super::support::key_store(&reopened).await;
    let mut conn = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(reopened)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("reopen with no DDL");
    assert_eq!(
        lowercase_matches(&mut conn),
        0,
        "and so does a reopen that ran no DDL"
    );
}

/// pg2sqlite leads every script it emits with the dialect pragma, and a tier
/// script is one of those, so the pragma passes through and the table still
/// lands in the tier.
#[tokio::test]
async fn a_tier_script_may_lead_with_a_pragma() {
    const PRAGMA_LED_TIER_DDL: &str = "PRAGMA case_sensitive_like = 1;\n\
        CREATE TABLE drafts (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
    let dir = tempdir().expect("tempdir");
    let credential = credential();
    let store = super::support::key_store(&credential).await;
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        Some(PRAGMA_LED_TIER_DDL),
    ));
    let mut conn = ClientBuilder::new(
        schema,
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .open_driven()
    .await
    .expect("a pragma in the tier script is not a refusal");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1), drafts::body.eq("in the tier")))
        .execute(conn.conn())
        .expect("the table the script declared exists in the tier");
    assert_eq!(
        conn.conn().get_limit(SqliteLimit::Attached),
        1,
        "the tier is attached and the pragma created nothing"
    );
}
