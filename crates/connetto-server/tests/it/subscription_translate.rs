//! Server-side handling of the client's SQLite-dialect subscription query:
//! reverse translation into the Postgres SQL that subql parses, placeholder
//! syntax included, with bind values riding the registration natively.
//!
//! The client speaks SQLite (the dialect it runs against its local replica)
//! and ships `?` placeholders with typed bind values. The server owns the
//! schema, so translation happens server-side on the AST, and the binds are
//! never rendered into SQL text: pg2sqlite maps the placeholder syntax to
//! `$N` and subql resolves the values at registration. These tests pin that
//! seam: a dialect-divergent query is actually rewritten, placeholders
//! translate as syntax, a missing bind fails registration cleanly, and an
//! unparseable query fails as `Translate` rather than reaching subql.

use connetto_core::messages::BindValue;
use connetto_server::{Materializer, MaterializerError, ReadBudget, Registration, SeedPlan};

const PG_DDL: &str =
    "CREATE TABLE t (id INT PRIMARY KEY, name TEXT, amount INT, price FLOAT, tag BYTEA);";

fn materializer() -> Materializer {
    Materializer::new(PG_DDL).expect("build materializer")
}

#[test]
fn reverse_translates_a_dialect_divergent_function() {
    // SQLite `unicode(x)` reverse-translates to Postgres `ascii(x)`, proving the
    // translation actually fires and is dialect-aware rather than a passthrough.
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE unicode(name) > 65")
        .expect("translate")
        .to_lowercase();
    assert!(
        pg.contains("ascii"),
        "expected ascii in translated SQL, got {pg}"
    );
    assert!(
        !pg.contains("unicode"),
        "unicode should be rewritten, got {pg}"
    );
}

#[test]
fn translates_plain_placeholders_to_numbered_parameters() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ? AND name = ?")
        .expect("translate");
    assert!(
        pg.contains("$1") && pg.contains("$2"),
        "bare placeholders number in textual order, got {pg}"
    );
    assert!(
        !pg.contains('?'),
        "no SQLite placeholder survives translation, got {pg}"
    );
}

#[test]
fn numbered_placeholders_keep_their_index_and_may_repeat() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ?1 AND id < ?1")
        .expect("translate");
    assert_eq!(
        pg.matches("$1").count(),
        2,
        "both `?1` references keep parameter one, got {pg}",
    );
}

#[test]
fn mixed_placeholders_follow_the_sqlite_assignment_rule() {
    // A bare `?` takes one greater than the largest index assigned so far, so
    // `?` after `?2` becomes `$3`.
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE amount > ?2 AND id < ?")
        .expect("translate");
    assert!(
        pg.contains("$2") && pg.contains("$3"),
        "bare placeholder numbers past the explicit one, got {pg}",
    );
}

#[test]
fn placeholder_inside_string_literal_is_not_a_bind() {
    let pg = materializer()
        .translate_subscription_sql("SELECT * FROM t WHERE name = '?'")
        .expect("translate");
    assert!(
        pg.contains("'?'"),
        "a question mark inside a string literal is data, got {pg}",
    );
}

#[test]
fn register_sqlite_rejects_a_missing_bind() {
    // Placeholder pairing is subql's job now: a `$1` with no bind behind it
    // fails registration, not translation.
    let mut mat = materializer();
    match mat.register_sqlite(
        1,
        "SELECT * FROM t WHERE amount > ?",
        &[],
        ReadBudget::new(core::time::Duration::from_secs(5)),
    ) {
        Err(MaterializerError::Register(_)) => {}
        Err(other) => panic!("expected a registration error, got {other:?}"),
        Ok(_) => panic!("a placeholder without a bind must not register"),
    }
}

#[test]
fn register_sqlite_classifies_translated_query() {
    let mut mat = materializer();
    let agg = mat
        .register_sqlite(
            1,
            "SELECT COUNT(*) FROM t",
            &[],
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
        .expect("register aggregate");
    assert!(
        matches!(&agg.registration, Registration::Computed(cap) if matches!(cap.seed, SeedPlan::Fold { .. })),
        "COUNT(*) should classify as a fold subscription after translation",
    );

    let row = mat
        .register_sqlite(
            2,
            "SELECT * FROM t WHERE amount > ?",
            &[BindValue::Integer(0)],
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
        .expect("register row");
    assert!(
        matches!(row.registration, Registration::Row(_)),
        "a bound row filter should classify as a row subscription after translation",
    );
    assert!(
        row.pg_sql.contains("$1"),
        "the registration carries the translated parameterized SQL, got {}",
        row.pg_sql,
    );
}

#[test]
fn register_sqlite_accepts_a_real_bind() {
    // Float binds ride natively as typed values. Under the old literal
    // substitution they were rejected outright.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT * FROM t WHERE price > ?",
            &[BindValue::Real(1.5)],
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
        .expect("a REAL bind registers");
    assert!(matches!(row.registration, Registration::Row(_)));
}

#[test]
fn register_sqlite_accepts_a_blob_bind() {
    // Blob binds resolve through subql's hex literal round trip.
    let mut mat = materializer();
    let row = mat
        .register_sqlite(
            1,
            "SELECT * FROM t WHERE tag = ?",
            &[BindValue::Blob(vec![0xde, 0xad, 0xbe, 0xef])],
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
        .expect("a BLOB bind registers");
    assert!(matches!(row.registration, Registration::Row(_)));
}

#[test]
fn register_sqlite_rejects_unparseable_query() {
    let mut mat = materializer();
    match mat.register_sqlite(
        1,
        "SELECT ((( FROM",
        &[],
        ReadBudget::new(core::time::Duration::from_secs(5)),
    ) {
        Err(MaterializerError::Translate(_)) => {}
        Err(other) => panic!("expected a translation error, got {other:?}"),
        Ok(_) => panic!("unparseable query must not register"),
    }
}

#[test]
fn registers_the_exact_shape_diesel_renders() {
    // diesel's SQLite rendering emits backtick-quoted identifiers, the
    // complete column list as an explicit projection, a parenthesized WHERE
    // with a `?` bind, and any ORDER BY the app added. This is the wire shape
    // every typed live query produces, so it must register end to end, and
    // its translation must be parameterized Postgres SQL with double-quoted
    // identifiers.
    //
    // A bare ORDER BY changes nothing about which rows are in the answer, so
    // since subql `0832db4` (U12) the ordered and unordered statements both
    // register as row subscriptions and the replica applies the ordering at
    // local execution. Only LIMIT or OFFSET moves a query to a read tier.
    let mut mat = materializer();
    let reg = mat
        .register_sqlite(
            1,
            "SELECT `t`.`id`, `t`.`name`, `t`.`amount`, `t`.`price`, `t`.`tag` FROM `t` \
             WHERE (`t`.`amount` > ?) ORDER BY `t`.`id`",
            &[BindValue::Integer(0)],
            ReadBudget::new(core::time::Duration::from_secs(5)),
        )
        .expect("diesel-rendered shape registers");
    assert!(
        matches!(&reg.registration, Registration::Row(_)),
        "the diesel shape with a bare ORDER BY stays a row subscription (U12)",
    );
    assert!(
        reg.pg_sql.contains("$1") && !reg.pg_sql.contains('`') && !reg.pg_sql.contains('?'),
        "the translation is parameterized Postgres SQL, got {}",
        reg.pg_sql,
    );
}

/// Pins the R60 defect closure: a "latest N" query with ORDER BY and LIMIT but
/// no WHERE predicate used to register as a filterless row subscription, which
/// synced the whole table forever and disabled eviction. It must now register as
/// a read-tier computed subscription (`SeedPlan::Snapshot`), never as `Row`.
#[test]
fn latest_n_row_query_registers_as_snapshot_not_row() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    let reg = mat
        .register(1, "SELECT * FROM t ORDER BY id DESC LIMIT 3")
        .expect("register");
    assert!(
        matches!(&reg, Registration::Computed(cap) if matches!(cap.seed, SeedPlan::Snapshot)),
        "ORDER BY + LIMIT without WHERE must register as Computed(Snapshot), not Row",
    );
    assert!(
        !matches!(reg, Registration::Row(_)),
        "ORDER BY + LIMIT must never register as a row subscription",
    );
}

/// **Every aggregate connetto serves has to survive the reverse translation.**
///
/// A client's query reaches `register_sqlite` in the SQLite dialect, so an
/// aggregate whose name the reverse translator does not recognise is refused
/// before subql ever sees it, and the client is told only `subscription
/// refused`. That is not hypothetical: a pg2sqlite revision refused `var_pop`,
/// `var_samp`, `stddev_pop` and `stddev_samp` as names PostgreSQL does not have,
/// which took out the whole variance family and was caught by one Docker-gated
/// aggregate test rather than here.
///
/// The list is the nine the materializer classifies, plus `variance` and
/// `stddev`, PostgreSQL's own aliases for `var_samp` and `stddev_samp`, which a
/// client is equally free to write.
#[test]
fn every_aggregate_survives_the_reverse_translation() {
    let mat = materializer();
    for name in [
        "COUNT",
        "SUM",
        "AVG",
        "MIN",
        "MAX",
        "VAR_POP",
        "VAR_SAMP",
        "STDDEV_POP",
        "STDDEV_SAMP",
        "VARIANCE",
        "STDDEV",
    ] {
        let query = format!("SELECT {name}(amount) FROM t");
        let pg = mat
            .translate_subscription_sql(&query)
            .unwrap_or_else(|err| panic!("{name} has to survive the translation: {err}"));
        assert!(
            pg.to_uppercase().contains(name),
            "{name} should reach Postgres under its own name, got {pg}"
        );
    }
}
