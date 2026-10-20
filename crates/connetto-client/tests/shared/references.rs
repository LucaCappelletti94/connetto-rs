//! R92's proofs, one body each, run by the native suite in
//! `tests/it/references.rs` and by the browser suite in
//! `crates/connetto-web/tests/references.rs`, so both backends prove the same
//! thing.
//!
//! Synced tables carry no references, since a replica is a partial copy the
//! server alone judges. The device-local tier keeps its references, and SQLite
//! enforces them on every connection connetto opens.

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ExportScope, ImportChoices, SyncSchema,
    TransportFactory,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, SnapshotBegin, SnapshotEnd, SnapshotPatch, SubscriptionPriority,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{IncomingFrame, MaybeSend};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

type Conn = ConnettoConnection<FakeTransport>;

/// A synced table as its translation reaches the replica, without the
/// reference to a parent the replica may never hold.
const SYNCED_DDL: &str = "CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY); \
    CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, folder INTEGER NOT NULL);";

diesel::table! {
    /// The synced child, whose folder the replica may never hold.
    notes (id) {
        /// Row key.
        id -> BigInt,
        /// The folder the note sits in.
        folder -> BigInt,
    }
}

diesel::table! {
    /// A tier parent. `code` exists only in the tiers that reference it.
    parents (id) {
        /// Row key.
        id -> BigInt,
        /// The key children reference in the action tiers.
        code -> BigInt,
    }
}

diesel::table! {
    /// A tier child.
    children (id) {
        /// Row key.
        id -> BigInt,
        /// The parent it references.
        parent -> Nullable<BigInt>,
    }
}

diesel::table! {
    /// A self-referencing tier hierarchy.
    nodes (id) {
        /// Row key.
        id -> BigInt,
        /// The node above, `NULL` at the root.
        parent -> Nullable<BigInt>,
    }
}

diesel::table! {
    /// The head of a composite-keyed chain.
    regions (country, code) {
        /// First key half.
        country -> Text,
        /// Second key half.
        code -> Text,
    }
}

diesel::table! {
    /// The middle of the chain, referencing a region by both halves.
    cities (id) {
        /// Row key.
        id -> BigInt,
        /// First half of the region reference.
        country -> Text,
        /// Second half of the region reference.
        code -> Text,
    }
}

diesel::table! {
    /// The tail of the chain.
    streets (id) {
        /// Row key.
        id -> BigInt,
        /// The city it lies in.
        city -> BigInt,
    }
}

diesel::table! {
    /// The client's queue of writes waiting for the server.
    _connetto_pending (seq) {
        /// Queue position.
        seq -> BigInt,
    }
}

/// The refusal of a dialer that never reaches a server.
#[derive(Debug)]
pub struct Unreachable;

impl core::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no server is reachable")
    }
}

/// A dialer that never reaches a server, so every replica here opens offline.
struct Offline;

impl TransportFactory for Offline {
    type Transport = FakeTransport;
    type Error = Unreachable;

    fn connect(&mut self) -> impl Future<Output = Result<FakeTransport, Unreachable>> + MaybeSend {
        core::future::ready(Err(Unreachable))
    }
}

/// An in-memory replica over `synced`, with `tier` as its device-local tier.
fn open_with(synced: &str, tier: Option<&str>) -> Conn {
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        synced,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        tier,
    ));
    ClientBuilder::new(schema, Offline)
        .open_driven()
        .expect("the replica opens")
}

/// An in-memory replica over [`SYNCED_DDL`] with `tier` as its tier.
fn open(tier: &str) -> Conn {
    open_with(SYNCED_DDL, Some(tier))
}

/// How many references SQLite records for `table` in `schema`. Raw because a
/// table-valued pragma has no typed form.
fn references(conn: &mut Conn, schema: &str, table: &str) -> i64 {
    #[derive(QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        rows: i64,
    }
    diesel::sql_query("SELECT count(*) AS rows FROM pragma_foreign_key_list(?, ?)")
        .bind::<diesel::sql_types::Text, _>(table)
        .bind::<diesel::sql_types::Text, _>(schema)
        .get_result::<Count>(conn.conn())
        .expect("read the references")
        .rows
}

/// The tier half of decision 1: the tier keeps its reference.
pub fn the_tier_keeps_its_references() {
    let mut conn = open(
        "CREATE TABLE parents (id INTEGER PRIMARY KEY); \
         CREATE TABLE children (id INTEGER PRIMARY KEY, \
         parent INTEGER REFERENCES parents(id) ON DELETE CASCADE)",
    );
    assert_eq!(references(&mut conn, "connetto_local", "children"), 1);
}

/// Proof 3: enforcement is on for a replica with a tier and for one without,
/// which is the shape of a browser tab's mirror.
pub fn foreign_keys_are_on_for_every_replica() {
    let mut with_tier = open("CREATE TABLE drafts (id INTEGER PRIMARY KEY)");
    assert!(
        with_tier
            .conn()
            .are_foreign_keys_enabled()
            .expect("read the setting"),
        "a replica with a tier enforces"
    );
    let mut mirror = open_with(SYNCED_DDL, None);
    assert!(
        mirror
            .conn()
            .are_foreign_keys_enabled()
            .expect("read the setting"),
        "a replica without a tier enforces"
    );
}

/// The row a snapshot for `notes` carries: note 10 in folder 1.
fn orphan_snapshot() -> Vec<u8> {
    let table = SimpleTable::new("notes", &["id", "folder"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(10))
        .expect("set id")
        .set(1, Value::Integer(1))
        .expect("set folder");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build();
    zstd::encode_all(patchset.as_slice(), 3).expect("compress")
}

/// Proof 4 on the client's side: a server snapshot holding a note whose folder
/// the replica does not hold lands, and a note written here into that folder is
/// queued to go up.
pub async fn an_orphan_from_the_server_lands_and_a_local_one_queues() {
    let mut conn = open("CREATE TABLE drafts (id INTEGER PRIMARY KEY)");
    conn.subscribe("notes", "SELECT * FROM notes")
        .await
        .expect("subscribe offline");
    conn.attach(FakeTransport::accepting_then_delivering([
        IncomingFrame::Control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: "notes".to_owned(),
            priority: SubscriptionPriority::default(),
        })),
        IncomingFrame::Bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            "notes",
            orphan_snapshot(),
        ))),
        IncomingFrame::Control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: "notes".to_owned(),
            cursor: Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        })),
    ]))
    .await
    .expect("attach");
    while conn.is_connected() {
        if conn.pump_one().await.is_err() {
            break;
        }
    }
    assert_eq!(
        notes::table
            .select(notes::id)
            .load::<i64>(conn.conn())
            .expect("read notes"),
        vec![10],
        "the server's note landed without its folder"
    );

    diesel::insert_into(notes::table)
        .values((notes::id.eq(11), notes::folder.eq(1)))
        .execute(conn.conn())
        .expect("a local note in a folder the replica does not hold");
    let _ = conn.push().await;
    assert_eq!(
        _connetto_pending::table
            .count()
            .get_result::<i64>(conn.conn())
            .expect("read the queue"),
        1,
        "the write is queued for the server to settle"
    );
}

/// A tier of one parent table and one child table whose reference carries
/// `action` on both events, with parent code 10 holding child 1 and parent code
/// 0 standing by as the default.
fn action_tier(action: &str) -> Conn {
    let mut conn = open(&format!(
        "CREATE TABLE parents (id INTEGER PRIMARY KEY, code INTEGER NOT NULL UNIQUE); \
         CREATE TABLE children (id INTEGER PRIMARY KEY, parent INTEGER DEFAULT 0 \
         REFERENCES parents(code) ON DELETE {action} ON UPDATE {action})"
    ));
    diesel::insert_into(parents::table)
        .values(&vec![
            (parents::id.eq(1), parents::code.eq(10)),
            (parents::id.eq(2), parents::code.eq(0)),
        ])
        .execute(conn.conn())
        .expect("seed the parents");
    diesel::insert_into(children::table)
        .values((children::id.eq(1), children::parent.eq(10)))
        .execute(conn.conn())
        .expect("seed the child");
    conn
}

/// What became of child 1 after its parent changed.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Child {
    /// The row is gone.
    Gone,
    /// The row stands and references this parent code, or none.
    References(Option<i64>),
}

/// What became of child 1.
fn child_state(conn: &mut Conn) -> Child {
    children::table
        .find(1)
        .select(children::parent)
        .first(conn.conn())
        .optional()
        .expect("read the child")
        .map_or(Child::Gone, Child::References)
}

/// How many rows `table` holds.
macro_rules! rows {
    ($conn:expr, $table:ident) => {
        $table::table
            .count()
            .get_result::<i64>($conn.conn())
            .expect(concat!("count ", stringify!($table)))
    };
}

/// Proof 5, the five actions: each applies on a delete and on an update.
pub fn every_action_applies_on_delete_and_update() {
    // (action, child after the delete, child after the update, whether the parent change is refused)
    let expectations = [
        ("CASCADE", Child::Gone, Child::References(Some(11)), false),
        (
            "SET NULL",
            Child::References(None),
            Child::References(None),
            false,
        ),
        (
            "SET DEFAULT",
            Child::References(Some(0)),
            Child::References(Some(0)),
            false,
        ),
        (
            "RESTRICT",
            Child::References(Some(10)),
            Child::References(Some(10)),
            true,
        ),
        (
            "NO ACTION",
            Child::References(Some(10)),
            Child::References(Some(10)),
            true,
        ),
    ];
    for (action, after_delete, after_update, refused) in expectations {
        let mut conn = action_tier(action);
        let deleted =
            diesel::delete(parents::table.filter(parents::code.eq(10))).execute(conn.conn());
        assert_eq!(deleted.is_err(), refused, "{action} on delete");
        assert_eq!(child_state(&mut conn), after_delete, "{action} on delete");

        let mut conn = action_tier(action);
        let updated = diesel::update(parents::table.filter(parents::code.eq(10)))
            .set(parents::code.eq(11))
            .execute(conn.conn());
        assert_eq!(updated.is_err(), refused, "{action} on update");
        assert_eq!(child_state(&mut conn), after_update, "{action} on update");
    }
}

/// Proof 5: a null reference column names no parent and is never checked, and
/// a reference that names a missing parent is refused.
pub fn a_null_reference_is_not_checked() {
    let mut conn = action_tier("NO ACTION");
    diesel::insert_into(children::table)
        .values((children::id.eq(2), children::parent.eq(None::<i64>)))
        .execute(conn.conn())
        .expect("a null reference names nothing");
    assert!(
        diesel::insert_into(children::table)
            .values((children::id.eq(3), children::parent.eq(99)))
            .execute(conn.conn())
            .is_err(),
        "a missing parent is refused"
    );
}

/// Proof 5: a composite reference holds as one, and a chain across three tables
/// cascades through each.
pub fn composite_references_and_chains_hold() {
    let mut conn = open(
        "CREATE TABLE regions (country TEXT, code TEXT, PRIMARY KEY (country, code)); \
         CREATE TABLE cities (id INTEGER PRIMARY KEY, country TEXT, code TEXT, \
         FOREIGN KEY (country, code) REFERENCES regions(country, code) ON DELETE CASCADE); \
         CREATE TABLE streets (id INTEGER PRIMARY KEY, \
         city INTEGER REFERENCES cities(id) ON DELETE CASCADE)",
    );
    diesel::insert_into(regions::table)
        .values(&vec![
            (regions::country.eq("it"), regions::code.eq("to")),
            (regions::country.eq("it"), regions::code.eq("mi")),
        ])
        .execute(conn.conn())
        .expect("seed the regions");
    diesel::insert_into(cities::table)
        .values((
            cities::id.eq(1),
            cities::country.eq("it"),
            cities::code.eq("to"),
        ))
        .execute(conn.conn())
        .expect("seed the city");
    diesel::insert_into(streets::table)
        .values((streets::id.eq(1), streets::city.eq(1)))
        .execute(conn.conn())
        .expect("seed the street");
    assert!(
        diesel::insert_into(cities::table)
            .values((
                cities::id.eq(2),
                cities::country.eq("fr"),
                cities::code.eq("to")
            ))
            .execute(conn.conn())
            .is_err(),
        "half a matching key is no match"
    );
    diesel::delete(regions::table.filter(regions::country.eq("it").and(regions::code.eq("to"))))
        .execute(conn.conn())
        .expect("delete the region");
    assert_eq!(rows!(conn, cities), 0, "the city went with its region");
    assert_eq!(rows!(conn, streets), 0, "the street went with its city");
}

/// The rows of a self-referencing chain `depth` levels below its root, root
/// first.
fn chain(depth: i64) -> Vec<(i64, Option<i64>)> {
    core::iter::once((0, None))
        .chain((1..=depth).map(|level| (level, Some(level - 1))))
        .collect()
}

/// Insert `rows` into `nodes`, in the order given.
fn insert_nodes(conn: &mut SqliteConnection, rows: &[(i64, Option<i64>)]) -> QueryResult<usize> {
    let values: Vec<_> = rows
        .iter()
        .map(|&(id, parent)| (nodes::id.eq(id), nodes::parent.eq(parent)))
        .collect();
    diesel::insert_into(nodes::table)
        .values(&values)
        .execute(conn)
}

const TREE_TIER: &str = "CREATE TABLE nodes (id INTEGER PRIMARY KEY, \
    parent INTEGER REFERENCES nodes(id) ON DELETE CASCADE)";

/// Proof 5 and 7: a self-referencing hierarchy twelve levels deep cascades
/// whole from its root.
pub fn a_hierarchy_twelve_levels_deep_cascades() {
    let mut conn = open(TREE_TIER);
    insert_nodes(conn.conn(), &chain(12)).expect("seed the tree");
    diesel::delete(nodes::table.find(0))
        .execute(conn.conn())
        .expect("delete the root");
    assert_eq!(rows!(conn, nodes), 0, "every level went with the root");
}

const DEFERRED_TIER: &str = "CREATE TABLE parents (id INTEGER PRIMARY KEY); \
    CREATE TABLE children (id INTEGER PRIMARY KEY, \
    parent INTEGER REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)";

/// Proof 5: a deferred reference broken inside a transaction and repaired
/// before its commit holds, and one still broken at the commit refuses it.
pub fn a_deferred_reference_is_checked_at_commit() {
    let mut conn = open(DEFERRED_TIER);
    conn.conn()
        .transaction::<_, diesel::result::Error, _>(|db| {
            diesel::insert_into(children::table)
                .values((children::id.eq(1), children::parent.eq(1)))
                .execute(db)?;
            diesel::insert_into(parents::table)
                .values(parents::id.eq(1))
                .execute(db)
        })
        .expect("repaired before the commit");
    let broken = conn
        .conn()
        .transaction::<_, diesel::result::Error, _>(|db| {
            diesel::insert_into(children::table)
                .values((children::id.eq(2), children::parent.eq(2)))
                .execute(db)
        });
    assert!(broken.is_err(), "still broken at the commit");
    assert_eq!(rows!(conn, children), 1, "the broken write rolled back");
    diesel::insert_into(parents::table)
        .values(parents::id.eq(3))
        .execute(conn.conn())
        .expect("the connection commits again after the refused commit");
}

/// The archive a tier of `tier` holds after `seed`, exported whole.
fn archive_of(tier: &str, seed: impl FnOnce(&mut SqliteConnection)) -> Vec<u8> {
    let mut source = open(tier);
    seed(source.conn());
    source
        .export_local_data(ExportScope::Unsynced, Vec::new())
        .expect("export")
}

/// Import `archive` into `target`.
fn import(target: &mut Conn, archive: &[u8]) -> Result<(), ClientError> {
    let plan = target.import_local_data(std::io::Cursor::new(archive))?;
    target
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .map(|_| ())
}

/// A tier whose child table was created before its parent, so the export,
/// which writes tables in creation order, carries the children first.
const CHILD_FIRST_TIER: &str = "CREATE TABLE children (id INTEGER PRIMARY KEY, \
    parent INTEGER NOT NULL REFERENCES parents(id)); \
    CREATE TABLE parents (id INTEGER PRIMARY KEY)";

/// Proof 6: a child table created before its parent is exported first and
/// imports whole.
pub fn an_import_of_a_child_table_created_first_restores() {
    let archive = archive_of(CHILD_FIRST_TIER, |db| {
        diesel::insert_into(parents::table)
            .values(parents::id.eq(1))
            .execute(db)
            .expect("seed the parent");
        diesel::insert_into(children::table)
            .values((children::id.eq(1), children::parent.eq(1)))
            .execute(db)
            .expect("seed the child");
    });
    let mut target = open(CHILD_FIRST_TIER);
    import(&mut target, &archive).expect("the import applies");
    assert_eq!(rows!(target, children), 1, "the child came back");
    assert_eq!(rows!(target, parents), 1, "the parent came back");
}

/// Proof 6: self-referencing rows the archive carries leaf first import whole.
pub fn an_import_of_reverse_ordered_self_references_restores() {
    let tree = "CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES nodes(id))";
    // Seeded leaf first under deferred checks, so the archive carries each
    // row ahead of the row it references.
    let archive = archive_of(tree, |db| {
        let mut rows = chain(63);
        rows.reverse();
        db.transaction::<_, diesel::result::Error, _>(|db| {
            db.batch_execute("PRAGMA defer_foreign_keys = ON")?;
            insert_nodes(db, &rows)
        })
        .expect("seed the tree leaf first");
    });
    let mut target = open(tree);
    import(&mut target, &archive).expect("the import applies");
    assert_eq!(rows!(target, nodes), 64, "every node came back");
}

/// Proof 6: an archive holding an orphan aborts, leaves the tier as it was, and
/// the next ordinary statement is checked at once again.
pub fn an_orphan_aborts_the_import_and_checks_resume() {
    let archive = archive_of(CHILD_FIRST_TIER, |db| {
        // Enforcement is connection state, so a source that switched it off can
        // hold an orphan, which is the archive a foreign tool could produce.
        db.set_foreign_keys_enabled(false)
            .expect("switch enforcement off");
        diesel::insert_into(children::table)
            .values((children::id.eq(1), children::parent.eq(9)))
            .execute(db)
            .expect("seed an orphan");
    });

    let mut target = open(CHILD_FIRST_TIER);
    diesel::insert_into(parents::table)
        .values(parents::id.eq(5))
        .execute(target.conn())
        .expect("the target's own parent");
    diesel::insert_into(children::table)
        .values((children::id.eq(5), children::parent.eq(5)))
        .execute(target.conn())
        .expect("the target's own child");
    assert!(import(&mut target, &archive).is_err(), "the orphan aborts");
    assert_eq!(
        rows!(target, children),
        1,
        "the tier kept only its own child"
    );
    assert_eq!(
        rows!(target, parents),
        1,
        "the tier kept only its own parent"
    );

    let orphan = diesel::insert_into(children::table)
        .values((children::id.eq(6), children::parent.eq(6)))
        .execute(target.conn());
    assert!(orphan.is_err(), "the next statement is checked at once");
    diesel::insert_into(parents::table)
        .values(parents::id.eq(7))
        .execute(target.conn())
        .expect("the connection commits again after the refused import");
    assert_eq!(rows!(target, parents), 2, "the later write committed");
}
