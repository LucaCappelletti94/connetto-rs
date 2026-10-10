//! Needs Docker, because the fixture starts its own Postgres.
//!
//! The bot registry over the tables `connetto_schema!` names (R91): a first
//! registration mints the bot and its list version 1 and spends the code, a
//! code for an existing bot rotates the key and bumps the list version only
//! when the list changed, and an installation sees its required entries plus
//! the optional tables it accepted.

use std::time::{Duration, SystemTime};

use connetto_server::bots::{ListEntry, PgBotRegistry, RegistryError, Verb, pg_bot_registry};
use connetto_server::defaults::ConnettoDefaults;
use connetto_server::schema::ConnettoSchema;
use connetto_test_harness::Fixture;
use diesel::QueryableByName;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;

use super::e2e::exec;

const HOUR: Duration = Duration::from_hours(1);

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

/// Seed one registration code, expiring an hour after or before the database
/// clock as `future` says, and naming `bot` when it holds one.
async fn code(
    pool: &Pool<AsyncPgConnection>,
    hash: [u8; 32],
    creator: &str,
    bot: Option<uuid::Uuid>,
    future: bool,
) {
    let bot = bot.map_or_else(|| "NULL".to_owned(), |id| format!("'{id}'"));
    let sign = if future { "+" } else { "-" };
    exec(
        pool,
        &format!(
            "INSERT INTO connetto_registration_codes (code_hash, creator, bot, expires_at) \
             VALUES (decode('{hex}', 'hex'), '{creator}', {bot}, now() {sign} interval '1 hour')",
            hex = hex_of(&hash),
        ),
    )
    .await;
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

#[derive(QueryableByName)]
struct CodeState {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    used: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Whether the code is spent, and when it spent.
async fn code_state(pool: &Pool<AsyncPgConnection>, hash: [u8; 32]) -> CodeState {
    let mut conn = pool.get().await.expect("a connection");
    diesel::sql_query(format!(
        "SELECT used_at IS NOT NULL AS used, used_at FROM connetto_registration_codes \
         WHERE code_hash = decode('{hex}', 'hex')",
        hex = hex_of(&hash),
    ))
    .get_result::<CodeState>(&mut *conn)
    .await
    .expect("read the code")
}

#[derive(QueryableByName)]
struct BotRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    owner: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    list_version: i32,
    #[diesel(sql_type = diesel::sql_types::Bytea)]
    public_key: Vec<u8>,
}

/// The bot's owner, current list version and key.
async fn bot_row(pool: &Pool<AsyncPgConnection>, bot: uuid::Uuid) -> BotRow {
    let mut conn = pool.get().await.expect("a connection");
    diesel::sql_query(format!(
        "SELECT owner, list_version, public_key FROM connetto_bots WHERE id = '{bot}'"
    ))
    .get_result::<BotRow>(&mut *conn)
    .await
    .expect("read the bot")
}

#[derive(QueryableByName, Debug, PartialEq)]
struct ListRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    table_name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    verb: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    optional: bool,
}

/// The stored rows of one list version, by table and verb.
async fn list_rows(pool: &Pool<AsyncPgConnection>, bot: uuid::Uuid, version: i32) -> Vec<ListRow> {
    let mut conn = pool.get().await.expect("a connection");
    diesel::sql_query(format!(
        "SELECT table_name, verb, optional FROM connetto_bot_lists \
         WHERE bot = '{bot}' AND version = {version} ORDER BY table_name, verb"
    ))
    .load(&mut *conn)
    .await
    .expect("read the list")
}

/// Postgres keeps microseconds, so a time read back is compared at that grain.
fn micros(at: SystemTime) -> u128 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_micros()
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
    code(&pool, hash, "alice", None, true).await;
    let now = SystemTime::now();
    let entries = list(true, true, true);

    let registered = store
        .register(hash, key(1), "orders bot".to_owned(), &entries, now)
        .await
        .expect("a fresh code registers");
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
    assert_eq!(
        micros(spent.used_at.expect("a spent code names when").into()),
        micros(now),
        "spent at the registration's instant"
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
            SystemTime::now(),
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
    #[derive(QueryableByName)]
    struct BotCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = pool.get().await.expect("a connection");
    diesel::sql_query("SELECT count(*) FROM connetto_bots")
        .get_result::<BotCount>(&mut *conn)
        .await
        .expect("count the bots")
        .count
}

#[tokio::test]
async fn a_used_code_is_refused_and_changes_nothing() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [3; 32];
    code(&pool, hash, "alice", None, true).await;
    let first = SystemTime::now();
    let entries = list(true, false, true);

    let registered = store
        .register(hash, key(1), "bot".to_owned(), &entries, first)
        .await
        .expect("the first registration");

    let later = first + HOUR;
    let refused = store
        .register(hash, key(2), "bot".to_owned(), &entries, later)
        .await
        .expect_err("the spent code is refused");
    assert!(matches!(refused, RegistryError::Refused));

    let row = bot_row(&pool, registered.bot).await;
    assert_eq!(row.list_version, 1, "no second version");
    assert_eq!(row.public_key, key(1).to_vec(), "no key rotation");
    assert_eq!(list_rows(&pool, registered.bot, 2).await, Vec::new());
    let spent = code_state(&pool, hash).await;
    assert_eq!(
        micros(spent.used_at.expect("the first spend").into()),
        micros(first),
        "the refusal did not re-spend it"
    );
}

#[tokio::test]
async fn an_expired_code_is_refused_and_keeps_it_unspent() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let hash = [4; 32];
    code(&pool, hash, "alice", None, false).await;

    let refused = store
        .register(
            hash,
            key(1),
            "bot".to_owned(),
            &list(true, false, false),
            SystemTime::now(),
        )
        .await
        .expect_err("the expired code is refused");
    assert!(matches!(refused, RegistryError::Refused));

    assert_eq!(bot_count(&pool).await, 0, "nothing was minted");
    let spent = code_state(&pool, hash).await;
    assert!(!spent.used, "refusing an expired code does not spend it");
}

#[tokio::test]
async fn a_changed_list_registers_version_two_and_leaves_version_one() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let first_hash = [5; 32];
    code(&pool, first_hash, "alice", None, true).await;
    let now = SystemTime::now();
    let first = list(true, true, true);

    let registered = store
        .register(first_hash, key(1), "bot".to_owned(), &first, now)
        .await
        .expect("the first registration");

    installation(&pool, "inst-1", registered.bot, "carol", 1, &["invoices"]).await;

    let second_hash = [6; 32];
    code(&pool, second_hash, "alice", Some(registered.bot), true).await;
    let second = list(true, false, false);

    let bumped = store
        .register(second_hash, key(1), "bot".to_owned(), &second, now + HOUR)
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
        #[derive(QueryableByName)]
        struct Accepted {
            #[diesel(sql_type = diesel::sql_types::Integer)]
            accepted_version: i32,
        }
        let mut conn = pool.get().await.expect("a connection");
        diesel::sql_query("SELECT accepted_version FROM connetto_installations WHERE id = 'inst-1'")
            .get_result::<Accepted>(&mut *conn)
            .await
            .expect("read the acceptance")
            .accepted_version
    };
    assert_eq!(accepted, 1, "the installation still accepts version one");
}

#[tokio::test]
async fn a_new_key_with_the_same_list_rotates_without_a_new_version() {
    let fixture = Fixture::acquire().await;
    let (pool, store) = registry(&fixture).await;
    let first_hash = [9; 32];
    code(&pool, first_hash, "alice", None, true).await;
    let now = SystemTime::now();
    let entries = list(true, false, true);

    let registered = store
        .register(first_hash, key(1), "bot".to_owned(), &entries, now)
        .await
        .expect("the first registration");

    let second_hash = [10; 32];
    code(&pool, second_hash, "alice", Some(registered.bot), true).await;
    let rotated = store
        .register(second_hash, key(2), "bot".to_owned(), &entries, now + HOUR)
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
    code(&pool, third_hash, "alice", Some(registered.bot), true).await;
    let unchanged = store
        .register(third_hash, key(2), "bot".to_owned(), &entries, now + HOUR)
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
    code(&pool, hash, "alice", None, true).await;
    let entries = list(true, true, true);

    let registered = store
        .register(hash, key(1), "bot".to_owned(), &entries, SystemTime::now())
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
