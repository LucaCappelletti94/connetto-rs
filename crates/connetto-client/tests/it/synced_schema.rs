//! Opening a replica removes its synced tables' references and keeps the rest
//! of every table exactly (R92 decision 1).

use core::fmt::Write as _;

use connetto_client::ClientBuilder;
use connetto_core::test_support::FakeTransport;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use proptest::prelude::*;

/// One column of a generated table.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent column clause the generator toggles"
)]
struct Column {
    quoted: bool,
    ty: &'static str,
    not_null: bool,
    default: Option<&'static str>,
    collate: bool,
    check: bool,
    unique: bool,
    generated: Option<&'static str>,
    reference: Option<&'static str>,
}

/// How the table declares its key.
#[derive(Debug, Clone, Copy)]
enum Key {
    Column,
    Autoincrement,
    Constraint,
}

/// A generated `CREATE TABLE`, rendered with or without its references.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent table clause the generator toggles"
)]
struct Table {
    quoted: bool,
    columns: Vec<Column>,
    key: Key,
    foreign_key: Option<&'static str>,
    check: bool,
    strict: bool,
    without_rowid: bool,
}

const TYPES: [&str; 5] = ["INTEGER", "TEXT", "BLOB", "REAL", "ANY"];
const DEFAULTS: [&str; 3] = ["7", "'x'", "(1 + 2)"];
const COLUMN_REFERENCES: [&str; 4] = [
    "REFERENCES p(id)",
    "REFERENCES p",
    "REFERENCES \"Parent T\"(\"the id\") ON DELETE CASCADE ON UPDATE SET NULL",
    "CONSTRAINT to_p REFERENCES p(id) DEFERRABLE INITIALLY DEFERRED",
];
const TABLE_REFERENCES: [&str; 2] = [
    "FOREIGN KEY (c0) REFERENCES p(id)",
    "CONSTRAINT to_q FOREIGN KEY (c0, c1) REFERENCES q(a, b) ON DELETE SET DEFAULT",
];

fn column_name(index: usize, quoted: bool) -> String {
    if quoted {
        format!("\"c {index}\"")
    } else {
        format!("c{index}")
    }
}

impl Table {
    fn name(&self) -> &'static str {
        if self.quoted { "\"odd table\"" } else { "t" }
    }

    fn render(&self, references: bool) -> String {
        let mut parts = Vec::new();
        for (index, column) in self.columns.iter().enumerate() {
            let name = column_name(index, column.quoted);
            let mut text = format!("{name} {}", column.ty);
            if index == 0 && !matches!(self.key, Key::Constraint) {
                text.push_str(" PRIMARY KEY");
                if matches!(self.key, Key::Autoincrement) {
                    text.push_str(" AUTOINCREMENT");
                }
            }
            if column.not_null {
                text.push_str(" NOT NULL");
            }
            if let Some(default) = column.default {
                let _ = write!(text, " DEFAULT {default}");
            }
            if column.collate {
                text.push_str(" COLLATE NOCASE");
            }
            if column.check {
                let _ = write!(text, " CHECK ({name} IS NOT NULL)");
            }
            if column.unique {
                text.push_str(" UNIQUE");
            }
            if let Some(storage) = column.generated {
                let _ = write!(
                    text,
                    " GENERATED ALWAYS AS (length({})) {storage}",
                    column_name(0, self.columns[0].quoted)
                );
            }
            if references && let Some(reference) = column.reference {
                text.push(' ');
                text.push_str(reference);
            }
            parts.push(text);
        }
        if matches!(self.key, Key::Constraint) {
            parts.push(format!(
                "PRIMARY KEY ({})",
                column_name(0, self.columns[0].quoted)
            ));
        }
        if self.check {
            parts.push(format!(
                "CHECK ({} IS NOT NULL)",
                column_name(0, self.columns[0].quoted)
            ));
        }
        if references && let Some(foreign_key) = self.foreign_key {
            let mut text = foreign_key.replace("c0", &column_name(0, self.columns[0].quoted));
            if let Some(second) = self.columns.get(1) {
                text = text.replace("c1", &column_name(1, second.quoted));
            }
            parts.push(text);
        }
        let mut text = format!("CREATE TABLE {} ({})", self.name(), parts.join(", "));
        if self.without_rowid {
            text.push_str(" WITHOUT ROWID");
        }
        if self.strict {
            text.push_str(if self.without_rowid {
                ", STRICT"
            } else {
                " STRICT"
            });
        }
        text
    }
}

fn column(first: bool) -> impl Strategy<Value = Column> {
    (
        any::<bool>(),
        0..TYPES.len(),
        any::<bool>(),
        proptest::option::of(0..DEFAULTS.len()),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        proptest::option::of(any::<bool>()),
        proptest::option::of(0..COLUMN_REFERENCES.len()),
    )
        .prop_map(
            move |(quoted, ty, not_null, default, collate, check, unique, generated, reference)| {
                // A key column is never generated, and a generated one takes no
                // default and no reference.
                let generated = if first { None } else { generated };
                let generated = generated.map(|stored| if stored { "STORED" } else { "VIRTUAL" });
                Column {
                    quoted,
                    ty: TYPES[ty],
                    not_null,
                    default: default
                        .filter(|_| generated.is_none())
                        .map(|index| DEFAULTS[index]),
                    collate,
                    check,
                    unique,
                    generated,
                    reference: reference
                        .filter(|_| generated.is_none())
                        .map(|index| COLUMN_REFERENCES[index]),
                }
            },
        )
}

fn table() -> impl Strategy<Value = Table> {
    (
        column(true),
        proptest::collection::vec(column(false), 0..5),
        any::<bool>(),
        0..3_u8,
        proptest::option::of(0..TABLE_REFERENCES.len()),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(first, rest, quoted, key, foreign_key, check, strict, without_rowid)| {
                let mut columns = vec![first];
                columns.extend(rest);
                let key = match key {
                    0 => Key::Column,
                    1 if !without_rowid => Key::Autoincrement,
                    _ => Key::Constraint,
                };
                if !matches!(key, Key::Constraint) {
                    columns[0].ty = "INTEGER";
                }
                // The composite reference names a second column, which must not
                // be generated.
                let foreign_key = foreign_key
                    .filter(|index| {
                        *index == 0 || columns.get(1).is_some_and(|c| c.generated.is_none())
                    })
                    .map(|index| TABLE_REFERENCES[index]);
                Table {
                    quoted,
                    columns,
                    key,
                    foreign_key,
                    check,
                    strict,
                    without_rowid,
                }
            },
        )
}

/// What SQLite reports about a table's columns and indexes, which is the
/// table's shape as SQLite will enforce it.
#[derive(Debug, PartialEq, Eq, QueryableByName)]
struct ColumnInfo {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    cid: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    #[diesel(column_name = "type")]
    ty: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    notnull: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    dflt_value: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pk: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    hidden: i32,
}

#[derive(Debug, PartialEq, Eq, QueryableByName)]
struct IndexInfo {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    unique: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    origin: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    partial: i32,
}

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}

#[derive(QueryableByName)]
struct StoredSql {
    #[diesel(sql_type = diesel::sql_types::Text)]
    sql: String,
}

/// Every piece of SQLite's view of `table` in `db`, each pragma read as the
/// table-valued function so the name binds rather than being spliced.
fn shape(db: &mut SqliteConnection, table: &str) -> (Vec<ColumnInfo>, Vec<IndexInfo>) {
    let columns = diesel::sql_query(
        "SELECT cid, name, type, \"notnull\", dflt_value, pk, hidden \
         FROM pragma_table_xinfo(?) ORDER BY cid",
    )
    .bind::<diesel::sql_types::Text, _>(table)
    .load(db)
    .expect("read the columns");
    let indexes = diesel::sql_query(
        "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?) ORDER BY name",
    )
    .bind::<diesel::sql_types::Text, _>(table)
    .load(db)
    .expect("read the indexes");
    (columns, indexes)
}

fn unquoted(name: &str) -> &str {
    name.trim_matches('"')
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The replica's table has SQLite's shape of the same table written without
    /// references, holds no references, and is stored as exactly that text.
    #[test]
    fn stripping_removes_references_and_keeps_the_rest(table in table()) {
        let with = table.render(true);
        let without = table.render(false);
        let name = unquoted(table.name());

        let mut replica = ClientBuilder::new(
            super::support::bundle(&with),
            super::support::NeverDial::<FakeTransport>::default(),
        )
        .open_driven()
        .expect("the replica opens");
        let mut expected = SqliteConnection::establish(":memory:").expect("open a control");
        expected.batch_execute(&without).expect("the table without references is valid");

        prop_assert_eq!(shape(replica.conn(), name), shape(&mut expected, name));
        let references: Vec<Count> =
            diesel::sql_query("SELECT count(*) AS rows FROM pragma_foreign_key_list(?)")
                .bind::<diesel::sql_types::Text, _>(name)
                .load(replica.conn())
                .expect("read the references");
        prop_assert_eq!(references[0].rows, 0);
        let stored: Vec<StoredSql> =
            diesel::sql_query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
                .bind::<diesel::sql_types::Text, _>(name)
                .load(replica.conn())
                .expect("read the stored table");
        prop_assert_eq!(&stored[0].sql, &without);
    }
}
