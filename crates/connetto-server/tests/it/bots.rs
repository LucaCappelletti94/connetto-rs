//! Needs Docker, because the fixture starts its own Postgres.
//!
//! The bot registry over the tables `connetto_schema!` names (R91): a first
//! registration mints the bot and its list version 1 and spends the code, a
//! code for an existing bot rotates the key and bumps the list version only
//! when the list changed, and an installation sees its required entries plus
//! the optional tables it accepted.

use connetto_server::bots::{ListEntry, PgBotRegistry, RegistryError, Verb, pg_bot_registry};
use connetto_server::defaults::ConnettoDefaults;
use connetto_server::schema::ConnettoSchema;
use connetto_test_harness::Fixture;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;

use super::e2e::exec;

/// The store over the fixture's registry tables, re-created from the shipped
/// DDL so a drift between it and the columns the store reads shows up here,
/// beside the admin pool the test reads back through.
async fn registry(
    fixture: &Fixture,
) -> (
    Pool<AsyncPgConnection>,
    PgBotRegistry<<ConnettoDefaults as ConnettoSchema>::Bots>,
) {
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(fixture.admin_url().to_owned());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    for statement in [
        "DROP TABLE IF EXISTS connetto_installation_optional_tables",
        "DROP TABLE IF EXISTS connetto_installations",
        "DROP TABLE IF EXISTS connetto_bot_lists",
        "DROP TABLE IF EXISTS connetto_registration_codes",
        "DROP TABLE IF EXISTS connetto_bots",
    ] {
        exec(&pool, statement).await;
    }
    for statement in connetto_server::defaults::BOTS_DDL.split(';') {
        if !statement.trim().is_empty() {
            exec(&pool, statement).await;
        }
    }
    let store = pg_bot_registry::<ConnettoDefaults>(pool.clone());
    (pool, store)
}

/// Seed one registration code expiring `expires_in_secs` after the database
/// clock, negative for a code already past, and naming `bot` when it holds one.
async fn code(
    pool: &Pool<AsyncPgConnection>,
    hash: [u8; 32],
    creator: &str,
    bot: Option<uuid::Uuid>,
    expires_in_secs: i64,
) {
    let bot = bot.map_or_else(|| "NULL".to_owned(), |id| format!("'{id}'"));
    exec(
        pool,
        &format!(
            "INSERT INTO connetto_registration_codes (code_hash, creator, bot, expires_at) \
             VALUES (decode('{hex}', 'hex'), '{creator}', {bot}, \
             now() + make_interval(secs => {expires_in_secs}))",
            hex = hex_of(&hash),
        ),
    )
    .await;
}

/// The database clock, the instant a spent code's stamp has to sit between.
async fn db_now(pool: &Pool<AsyncPgConnection>) -> chrono::DateTime<chrono::Utc> {
    let mut conn = pool.get().await.expect("a connection");
    diesel::select(diesel::dsl::sql::<diesel::sql_types::Timestamptz>("now()"))
        .get_result::<chrono::DateTime<chrono::Utc>>(&mut *conn)
        .await
        .expect("the database clock")
}

fn hex_of(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push(DIGITS[usize::from(byte >> 4)] as char);
        hex.push(DIGITS[usize::from(*byte & 0xf)] as char);
    }
    hex
}
fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn list(orders_read: bool, orders_insert: bool, invoices_optional: bool) -> Vec<ListEntry> {
    let mut entries = Vec::new();
    if orders_read {
        entries.push(ListEntry {
            table: "orders".to_owned(),
            verb: Verb::Read,
            optional: false,
        });
    }
    if orders_insert {
        entries.push(ListEntry {
            table: "orders".to_owned(),
            verb: Verb::Insert,
            optional: false,
        });
    }
    if invoices_optional {
        entries.push(ListEntry {
            table: "invoices".to_owned(),
            verb: Verb::Read,
            optional: true,
        });
    }
    entries
}

struct CodeState {
    used: bool,
    used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Whether the code is spent, and when it spent.
async fn code_state(pool: &Pool<AsyncPgConnection>, hash: [u8; 32]) -> CodeState {
    let mut conn = pool.get().await.expect("a connection");
    let used_at: Option<chrono::DateTime<chrono::Utc>> =
        connetto_server::defaults::connetto_registration_codes::table
            .filter(
                connetto_server::defaults::connetto_registration_codes::code_hash.eq(hash.to_vec()),
            )
            .select(connetto_server::defaults::connetto_registration_codes::used_at)
            .first(&mut *conn)
            .await
            .expect("read the code");
    CodeState {
        used: used_at.is_some(),
        used_at,
    }
}

struct BotRow {
    owner: String,
    list_version: i32,
    public_key: Vec<u8>,
}

/// The bot's owner, current list version and key.
async fn bot_row(pool: &Pool<AsyncPgConnection>, bot: uuid::Uuid) -> BotRow {
    let mut conn = pool.get().await.expect("a connection");
    let (owner, list_version, public_key): (String, i32, Vec<u8>) =
        connetto_server::defaults::connetto_bots::table
            .filter(connetto_server::defaults::connetto_bots::id.eq(bot))
            .select((
                connetto_server::defaults::connetto_bots::owner,
                connetto_server::defaults::connetto_bots::list_version,
                connetto_server::defaults::connetto_bots::public_key,
            ))
            .first(&mut *conn)
            .await
            .expect("read the bot");
    BotRow {
        owner,
        list_version,
        public_key,
    }
}

#[derive(Debug, PartialEq)]
struct ListRow {
    table_name: String,
    verb: String,
    optional: bool,
}

/// The stored rows of one list version, by table and verb.
async fn list_rows(pool: &Pool<AsyncPgConnection>, bot: uuid::Uuid, version: i32) -> Vec<ListRow> {
    let mut conn = pool.get().await.expect("a connection");
    let rows: Vec<(String, String, bool)> = connetto_server::defaults::connetto_bot_lists::table
        .filter(connetto_server::defaults::connetto_bot_lists::bot.eq(bot))
        .filter(connetto_server::defaults::connetto_bot_lists::version.eq(version))
        .order_by((
            connetto_server::defaults::connetto_bot_lists::table_name.asc(),
            connetto_server::defaults::connetto_bot_lists::verb.asc(),
        ))
        .select((
            connetto_server::defaults::connetto_bot_lists::table_name,
            connetto_server::defaults::connetto_bot_lists::verb,
            connetto_server::defaults::connetto_bot_lists::optional,
        ))
        .load(&mut *conn)
        .await
        .expect("read the list");
    rows.into_iter()
        .map(|(table_name, verb, optional)| ListRow {
            table_name,
            verb,
            optional,
        })
        .collect()
}

/// An installation row under the deployment's `String` id, with its accepted
/// optional tables.
async fn installation(
    pool: &Pool<AsyncPgConnection>,
    id: &str,
    bot: uuid::Uuid,
    owner: &str,
    accepted_version: i32,
    optional: &[&str],
) {
    exec(
        pool,
        &format!(
            "INSERT INTO connetto_installations (id, bot, owner, accepted_version) \
             VALUES ('{id}', '{bot}', '{owner}', {accepted_version})"
        ),
    )
    .await;
    for table in optional {
        exec(
            pool,
            &format!(
                "INSERT INTO connetto_installation_optional_tables (installation, table_name) \
                 VALUES ('{id}', '{table}')"
            ),
        )
        .await;
    }
}

#[tokio::test]
async fn a_first_registration_mints_the_bot_its_list_and_spends_the_code() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [7; 32];
    code(&pool, hash, "alice", None, 3600).await;
    let entries = list(true, true, true);
    let before = db_now(&pool).await;

    let registered = store
        .register(hash, key(1), "orders bot".to_owned(), &entries)
        .await
        .expect("a fresh code registers");
    let after = db_now(&pool).await;
    assert_eq!(registered.version, 1, "a first registration is version 1");

    let row = bot_row(&pool, registered.bot).await;
    assert_eq!(row.owner, "alice", "the code's creator owns the bot");
    assert_eq!(row.list_version, 1);
    assert_eq!(row.public_key, key(1).to_vec());
    assert_eq!(
        list_rows(&pool, registered.bot, 1).await,
        vec![
            ListRow {
                table_name: "invoices".to_owned(),
                verb: "read".to_owned(),
                optional: true,
            },
            ListRow {
                table_name: "orders".to_owned(),
                verb: "insert".to_owned(),
                optional: false,
            },
            ListRow {
                table_name: "orders".to_owned(),
                verb: "read".to_owned(),
                optional: false,
            },
        ]
    );
    let spent = code_state(&pool, hash).await;
    assert!(spent.used, "the registration spent the code");
    let spent_at = spent.used_at.expect("a spent code names when");
    assert!(
        spent_at >= before && spent_at <= after,
        "spent at the database's registration instant, got {spent_at} outside [{before}, {after}]"
    );
}

#[tokio::test]
async fn an_unknown_code_is_refused_and_changes_nothing() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;

    let refused = store
        .register(
            [0; 32],
            key(1),
            "ghost".to_owned(),
            &list(true, false, false),
        )
        .await
        .expect_err("a code nobody seeded is refused");
    assert!(
        matches!(refused, RegistryError::Refused),
        "the refusal is the undisclosing one"
    );
    assert_eq!(bot_count(&pool).await, 0, "nothing was minted");
}

async fn bot_count(pool: &Pool<AsyncPgConnection>) -> i64 {
    let mut conn = pool.get().await.expect("a connection");
    connetto_server::defaults::connetto_bots::table
        .count()
        .first(&mut *conn)
        .await
        .expect("count the bots")
}

#[tokio::test]
async fn a_used_code_is_refused_and_changes_nothing() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [3; 32];
    code(&pool, hash, "alice", None, 3600).await;
    let before = db_now(&pool).await;
    let entries = list(true, false, true);

    let registered = store
        .register(hash, key(1), "bot".to_owned(), &entries)
        .await
        .expect("the first registration");

    let after = db_now(&pool).await;
    let refused = store
        .register(hash, key(2), "bot".to_owned(), &entries)
        .await
        .expect_err("the spent code is refused");
    assert!(matches!(refused, RegistryError::Refused));

    let row = bot_row(&pool, registered.bot).await;
    assert_eq!(row.list_version, 1, "no second version");
    assert_eq!(row.public_key, key(1).to_vec(), "no key rotation");
    assert_eq!(list_rows(&pool, registered.bot, 2).await, Vec::new());
    let spent = code_state(&pool, hash).await;
    let spent_at = spent.used_at.expect("the first spend");
    assert!(
        spent_at >= before && spent_at <= after,
        "the refusal did not re-spend it, got {spent_at} outside [{before}, {after}]"
    );
}

/// Two concurrent registrations for one code settle exactly one, because the
/// code row is locked while it is read, so a transaction that reaches it
/// after the winner commits sees the spend and is refused.
#[tokio::test]
async fn two_concurrent_registrations_spend_one_code_once() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [9; 32];
    code(&pool, hash, "alice", None, 3600).await;
    let before = db_now(&pool).await;
    let entries = list(true, true, true);

    // Both tasks hold a pool connection across the barrier, so both reach the
    // code row while the other's transaction is open.
    let store = std::sync::Arc::new(store);
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let first = {
        let store = store.clone();
        let pool = pool.clone();
        let barrier = barrier.clone();
        let entries = entries.clone();
        tokio::spawn(async move {
            let _held = pool.get().await.expect("a connection for the first task");
            barrier.wait().await;
            store
                .register(hash, key(1), "orders bot".to_owned(), &entries)
                .await
        })
    };
    let second = {
        let store = store.clone();
        let pool = pool.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            let _held = pool.get().await.expect("a connection for the second task");
            barrier.wait().await;
            store
                .register(hash, key(2), "orders bot".to_owned(), &entries)
                .await
        })
    };
    let outcomes = [
        first.await.expect("the first registration task"),
        second.await.expect("the second registration task"),
    ];
    let after = db_now(&pool).await;
    let registered = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(registered, 1, "exactly one registration settles");
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Err(RegistryError::Refused))),
        "the loser is the undisclosing refusal"
    );
    let winner = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().ok())
        .expect("one registration settles");
    assert_eq!(winner.version, 1, "a first registration is version 1");
    assert_eq!(bot_count(&pool).await, 1, "one bot was minted");
    let spent = code_state(&pool, hash).await;
    assert!(spent.used, "the code spent once");
    let spent_at = spent.used_at.expect("the spend");
    assert!(
        spent_at >= before && spent_at <= after,
        "spent at the database's registration instant, got {spent_at} outside [{before}, {after}]"
    );
}

#[tokio::test]
async fn an_expired_code_is_refused_and_keeps_it_unspent() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [4; 32];
    code(&pool, hash, "alice", None, -3600).await;

    let refused = store
        .register(hash, key(1), "bot".to_owned(), &list(true, false, false))
        .await
        .expect_err("the expired code is refused");
    assert!(matches!(refused, RegistryError::Refused));

    assert_eq!(bot_count(&pool).await, 0, "nothing was minted");
    let spent = code_state(&pool, hash).await;
    assert!(!spent.used, "refusing an expired code does not spend it");
}

/// A code's expiry is written from the minting device's clock, so a code past
/// it by less than `DEVICE_SKEW` still registers (chapter 21).
#[tokio::test]
async fn a_code_expired_within_device_skew_still_registers() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [14; 32];
    code(&pool, hash, "alice", None, -60).await;

    store
        .register(hash, key(1), "bot".to_owned(), &list(true, false, false))
        .await
        .expect("a minute past is inside the device skew");
    assert!(code_state(&pool, hash).await.used, "the code is spent");
}

#[tokio::test]
async fn a_changed_list_registers_version_two_and_leaves_version_one() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let first_hash = [5; 32];
    code(&pool, first_hash, "alice", None, 3600).await;
    let first = list(true, true, true);

    let registered = store
        .register(first_hash, key(1), "bot".to_owned(), &first)
        .await
        .expect("the first registration");

    installation(&pool, "inst-1", registered.bot, "carol", 1, &["invoices"]).await;

    let second_hash = [6; 32];
    code(&pool, second_hash, "alice", Some(registered.bot), 3600).await;
    let second = list(true, false, false);

    let bumped = store
        .register(second_hash, key(1), "bot".to_owned(), &second)
        .await
        .expect("a code naming the bot registers its new list");
    assert_eq!(bumped.bot, registered.bot, "the same bot");
    assert_eq!(bumped.version, 2, "the changed list is the next version");

    let row = bot_row(&pool, registered.bot).await;
    assert_eq!(row.list_version, 2);
    assert_eq!(
        list_rows(&pool, registered.bot, 1).await,
        vec![
            ListRow {
                table_name: "invoices".to_owned(),
                verb: "read".to_owned(),
                optional: true,
            },
            ListRow {
                table_name: "orders".to_owned(),
                verb: "insert".to_owned(),
                optional: false,
            },
            ListRow {
                table_name: "orders".to_owned(),
                verb: "read".to_owned(),
                optional: false,
            },
        ],
        "version one's rows stay as they were"
    );
    assert_eq!(
        list_rows(&pool, registered.bot, 2).await,
        vec![ListRow {
            table_name: "orders".to_owned(),
            verb: "read".to_owned(),
            optional: false,
        }]
    );
    let accepted: i32 = {
        let mut conn = pool.get().await.expect("a connection");
        connetto_server::defaults::connetto_installations::table
            .filter(connetto_server::defaults::connetto_installations::id.eq("inst-1"))
            .select(connetto_server::defaults::connetto_installations::accepted_version)
            .first(&mut *conn)
            .await
            .expect("read the acceptance")
    };
    assert_eq!(accepted, 1, "the installation still accepts version one");
}

#[tokio::test]
async fn a_new_key_with_the_same_list_rotates_without_a_new_version() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let first_hash = [9; 32];
    code(&pool, first_hash, "alice", None, 3600).await;
    let entries = list(true, false, true);

    let registered = store
        .register(first_hash, key(1), "bot".to_owned(), &entries)
        .await
        .expect("the first registration");

    let second_hash = [10; 32];
    code(&pool, second_hash, "alice", Some(registered.bot), 3600).await;
    let rotated = store
        .register(second_hash, key(2), "bot".to_owned(), &entries)
        .await
        .expect("a code naming the bot with its key rotated");
    assert_eq!(rotated.bot, registered.bot);
    assert_eq!(rotated.version, 1, "the same list stays version 1");

    let row = bot_row(&pool, registered.bot).await;
    assert_eq!(row.list_version, 1);
    assert_eq!(row.public_key, key(2).to_vec(), "the new key is stored");
    assert_eq!(list_rows(&pool, registered.bot, 2).await, Vec::new());

    // A code that changes nothing answers the current version and spends.
    let third_hash = [11; 32];
    code(&pool, third_hash, "alice", Some(registered.bot), 3600).await;
    let unchanged = store
        .register(third_hash, key(2), "bot".to_owned(), &entries)
        .await
        .expect("a code that changes nothing still registers");
    assert_eq!(unchanged.version, 1);
    let spent = code_state(&pool, third_hash).await;
    assert!(spent.used);
}

#[tokio::test]
async fn an_installation_sees_its_required_entries_plus_its_accepted_optional_table() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [13; 32];
    code(&pool, hash, "alice", None, 3600).await;
    let entries = list(true, true, true);

    let registered = store
        .register(hash, key(1), "bot".to_owned(), &entries)
        .await
        .expect("the first registration");

    installation(&pool, "inst-1", registered.bot, "carol", 1, &["invoices"]).await;

    let effective = store
        .effective_list(&"inst-1".to_owned())
        .await
        .expect("the installation is known");
    assert_eq!(
        effective,
        vec![
            ("invoices".to_owned(), Verb::Read),
            ("orders".to_owned(), Verb::Insert),
            ("orders".to_owned(), Verb::Read),
        ],
        "the required entries plus the accepted optional table's, by table and verb"
    );

    let refused = store
        .effective_list(&"stranger".to_owned())
        .await
        .expect_err("an installation nobody added is refused");
    assert!(
        matches!(refused, RegistryError::Refused),
        "the refusal is the undisclosing one"
    );
}
