//! Docker-gated test of the bot cap on a synced table that is not read as a
//! membership.
//!
//! The cap is a Postgres rule of four `AS RESTRICTIVE` policies per table reading
//! `app.bot_list`, combined with the deployment's own rules. A person carries the
//! wildcard `*` and is held to nothing, a bot is held to the `table:verb`
//! entries of its list, and a connection carrying no list sees and writes nothing.
//! The rows a caller may read are what Postgres hands the caller directly, and
//! the same list the rls2fga model reads, so the snapshot and the change path
//! hold the caller to one list.
//!
//! Needs Docker, because the fixture starts its own Postgres.

use super::e2e::{NO_POLICIES, PG_DDL, PG_SERIAL, exec, reset_fixture, with_user_url};
use connetto_server::preflight::{self, Artifact, PreflightError};
use connetto_test_harness::{self, Fixture, pool_for, provision_cap_policies};
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::BigInt;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;
#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = BigInt)]
    n: i64,
}

/// Run `sql` as `app_reader`, the role the deployment grants the synced table
/// to, under `app.bot_list` set to `list`. A superuser bypasses the cap, so the
/// role is what makes the policies bite.
async fn as_reader(
    pool: &Pool<AsyncPgConnection>,
    list: &str,
    sql: &str,
) -> diesel::QueryResult<i64> {
    let mut conn = pool.get().await.unwrap();
    let set = format!("SELECT set_config('app.bot_list', '{list}', false)");
    sql_query(&set).execute(&mut *conn).await?;
    let row: Count = sql_query(sql).get_result(&mut *conn).await?;
    Ok(row.n)
}

/// Attempt a write as `app_reader` under `app.bot_list`, reporting the error
/// when the cap refuses it.
async fn write_as_reader(
    pool: &Pool<AsyncPgConnection>,
    list: &str,
    sql: &str,
) -> Result<usize, diesel::result::Error> {
    let mut conn = pool.get().await.unwrap();
    let set = format!("SELECT set_config('app.bot_list', '{list}', false)");
    sql_query(&set).execute(&mut *conn).await?;
    sql_query(sql).execute(&mut *conn).await
}

/// A reader pool over the fixture's `app_reader` role.
async fn reader_pool(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    let url = with_user_url(fixture.admin_url(), "app_reader", "app_reader");
    pool_for(&url).await
}

/// Run `sql` as `app_reader` under both `app.bot_list` (set to `list`) and
/// `app.user_id` (set to `user`), so the cap and the deployment's real policy
/// both apply to the read.
async fn as_person(
    pool: &Pool<AsyncPgConnection>,
    list: &str,
    user: &str,
    sql: &str,
) -> diesel::QueryResult<i64> {
    let mut conn = pool.get().await.unwrap();
    let set = format!(
        "SELECT set_config('app.bot_list', '{list}', false), \
         set_config('app.user_id', '{user}', false)"
    );
    sql_query(&set).execute(&mut *conn).await?;
    let row: Count = sql_query(sql).get_result(&mut *conn).await?;
    Ok(row.n)
}

/// The cap holds a person to nothing and a bot to exactly the verbs it lists.
/// The person (`*`) reads and writes the table, and a bot holding `orders:read`
/// reads the rows but is refused the insert, update and delete.
#[tokio::test]
async fn the_cap_holds_a_person_to_nothing_and_a_bot_to_its_list() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = pool_for(fixture.admin_url()).await;
    reset_fixture(&pool, &fixture).await;
    let reader = reader_pool(&fixture).await;

    // The seed row is what the person and the read-holding bot both see.
    let person = as_reader(&reader, "*", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(person, 1, "the person sees the seeded row");

    let person_insert = write_as_reader(
        &reader,
        "*",
        "INSERT INTO orders VALUES (2, 2.0, 4, 'person')",
    )
    .await
    .expect("the person may insert");
    assert_eq!(person_insert, 1);
    let person_delete = write_as_reader(&reader, "*", "DELETE FROM orders WHERE id = 2").await;
    assert!(person_delete.is_ok(), "the person may delete");

    // A bot holding only the read verb sees the rows but is refused every write.
    let bot_read = as_reader(&reader, "orders:read", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(bot_read, 1, "the read-holding bot sees the row");

    // The insert is refused outright because the new row fails the cap's WITH CHECK.
    let refused_insert = write_as_reader(
        &reader,
        "orders:read",
        "INSERT INTO orders VALUES (3, 3.0, 5, 'bot')",
    )
    .await;
    assert!(
        refused_insert.is_err(),
        "the read-only bot's insert is refused by the cap"
    );
    // The update and delete are silent no-ops. The cap's USING hides the row
    // from them, so each matches nothing and changes nothing.
    for (verb, sql) in [
        ("update", "UPDATE orders SET status = 'x' WHERE id = 1"),
        ("delete", "DELETE FROM orders WHERE id = 1"),
    ] {
        let affected = write_as_reader(&reader, "orders:read", sql)
            .await
            .unwrap_or_else(|err| {
                panic!("the read-only bot's {verb} should be a silent no-op, it errored: {err}")
            });
        assert_eq!(affected, 0, "the read-only bot's {verb} changes nothing");
    }

    // The bot's refused writes left the table as the person left it.
    let still = as_reader(&reader, "orders:read", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(still, 1, "the refused writes changed nothing");
}

/// A bot whose list names no entry for the table sees nothing, and so does a
/// connection carrying no list at all, both being held to the empty set.
#[tokio::test]
async fn the_cap_hides_the_table_from_a_bot_without_the_entry_and_from_an_unset_list() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = pool_for(fixture.admin_url()).await;
    reset_fixture(&pool, &fixture).await;
    let reader = reader_pool(&fixture).await;

    // A bot list that names another table leaves no entry for this one.
    let other = as_reader(&reader, "notes:read", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(other, 0, "a bot without an orders entry sees no row");

    // A list that names the table but no readable verb hides the rows too.
    let no_read = as_reader(&reader, "orders:insert", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(no_read, 0, "a bot holding only a write verb sees no row");

    // No list at all, so the setting is absent and the cap admits nothing.
    let unset = as_reader(&reader, "", "SELECT COUNT(*) AS n FROM orders")
        .await
        .unwrap();
    assert_eq!(unset, 0, "a connection carrying no list sees no row");

    // The write side is refused alike.
    let refused = write_as_reader(
        &reader,
        "notes:read",
        "INSERT INTO orders VALUES (9, 9.0, 9, 'other')",
    )
    .await;
    assert!(refused.is_err(), "a bot without the table cannot write it");
}

/// The startup check is what makes the cap fail closed. A synced table the
/// deployment did not cap refuses the boot, naming the table, and the same
/// probe passes once the generated cap document is applied.
#[tokio::test]
async fn a_synced_table_without_the_cap_refuses_the_boot() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = pool_for(fixture.admin_url()).await;
    // A fresh table the schema names but the deployment leaves uncapped.
    exec(&pool, "DROP TABLE IF EXISTS orders CASCADE").await;
    exec(&pool, PG_DDL).await;
    let required = [Artifact::CappedTable("orders")];

    let err = preflight::require(&pool, &required).await.unwrap_err();
    match err {
        PreflightError::Uncapped { table, missing } => {
            assert_eq!(table, "orders", "the refusal names the synced table");
            assert!(
                missing.contains("row-level security"),
                "the refusal names the missing row-level security: {missing}"
            );
        }
        other => panic!("expected the uncapped refusal, got {other:?}"),
    }

    // The generated cap document is what a deployment migration applies, and
    // same probe passes once it is there.
    provision_cap_policies(&pool, PG_DDL, NO_POLICIES).await;
    preflight::require(&pool, &required)
        .await
        .expect("the capped table holds to the bot cap");
}

/// A table the schema document itself enables row-level security on is secured
/// by its real policy alone, because the cap adds no `FOR ALL USING (true)` open
/// policy that would OR with the real one and let every row through, so a
/// person sees only their own rows.
#[tokio::test]
async fn a_schema_enabled_table_keeps_its_real_policy_under_the_cap() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = pool_for(fixture.admin_url()).await;
    reset_fixture(&pool, &fixture).await;
    let reader = reader_pool(&fixture).await;

    // A schema document that enables row-level security on the table, with a
    // policies document that carries the real policy but no enable statement.
    let schema = "CREATE TABLE owned (id INT PRIMARY KEY, owner TEXT, body TEXT); \
                  ALTER TABLE owned ENABLE ROW LEVEL SECURITY;";
    let policies = "CREATE POLICY owned_p ON owned FOR ALL USING \
                    (owner = current_setting('app.user_id', true));";
    exec(&pool, "DROP TABLE IF EXISTS owned CASCADE").await;
    connetto_test_harness::exec(&pool, schema).await;
    connetto_test_harness::exec(&pool, policies).await;
    provision_cap_policies(&pool, schema, policies).await;
    exec(&pool, "GRANT SELECT ON owned TO app_reader").await;

    // Two people's rows.
    exec(&pool, "INSERT INTO owned VALUES (1, 'alice', 'a')").await;
    exec(&pool, "INSERT INTO owned VALUES (2, 'bob', 'b')").await;

    // Alice carries the wildcard and her caller id, and the real policy admits
    // only her row. An open policy would have let bob's row through too, so
    // the count is the proof it is absent.
    let alice = as_person(&reader, "*", "alice", "SELECT COUNT(*) AS n FROM owned")
        .await
        .unwrap();
    assert_eq!(alice, 1, "alice sees only her own row, not bob's");

    // Bob's own row, not alice's.
    let bob = as_person(&reader, "*", "bob", "SELECT COUNT(*) AS n FROM owned")
        .await
        .unwrap();
    assert_eq!(bob, 1, "bob sees only his own row, not alice's");
}
