//! The deployment's bot registry tables (R91).
//!
//! connetto owns no schema. A deployment declares five tables and names them
//! through [`ConnettoBotSchema`], by hand or through
//! [`connetto_schema!`](crate::connetto_schema), as the `Bots` member of its
//! [`ConnettoSchema`](crate::schema::ConnettoSchema). The member runs one
//! statement per function, and [`PgBotRegistry`] composes them inside one
//! transaction and takes every decision itself.
//!
//! ```sql
//! CREATE TABLE connetto_bots (
//!     id UUID PRIMARY KEY,                 -- minted by connetto at registration
//!     owner <Id> NOT NULL,                 -- the registration code's creator
//!     name TEXT NOT NULL,
//!     public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
//!     list_version INT NOT NULL,           -- the current list version
//!     wake_url TEXT                        -- R101, unused here
//! );
//! CREATE TABLE connetto_registration_codes (
//!     code_hash BYTEA PRIMARY KEY,         -- SHA-256 of the code
//!     creator <Id> NOT NULL,
//!     bot UUID REFERENCES connetto_bots (id),  -- NULL for a first registration
//!     expires_at TIMESTAMPTZ NOT NULL,
//!     used_at TIMESTAMPTZ
//! );
//! CREATE TABLE connetto_bot_lists (
//!     bot UUID NOT NULL REFERENCES connetto_bots (id),
//!     version INT NOT NULL,
//!     table_name TEXT NOT NULL,
//!     verb TEXT NOT NULL CHECK (verb IN ('read', 'insert', 'update', 'delete')),
//!     optional BOOLEAN NOT NULL,
//!     PRIMARY KEY (bot, version, table_name, verb)
//! );
//! CREATE TABLE connetto_installations (
//!     id <Id> PRIMARY KEY,                 -- the deployment's Id, minted by the admin's app
//!     bot UUID NOT NULL REFERENCES connetto_bots (id),
//!     owner <Id> NOT NULL,                 -- the owner it serves
//!     accepted_version INT NOT NULL
//! );
//! CREATE TABLE connetto_installation_optional_tables (
//!     installation <Id> NOT NULL REFERENCES connetto_installations (id),
//!     table_name TEXT NOT NULL,
//!     PRIMARY KEY (installation, table_name)
//! );
//! ```
//!
//! The accepted optional tables are a child table rather than an array
//! column, because these tables are synced to client replicas and a
//! relational child table needs nothing new from `pg2sqlite` or the change
//! stream.

use std::collections::{BTreeSet, HashSet};
use std::marker::PhantomData;
use std::pin::Pin;

use diesel::QueryResult;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection as _, AsyncPgConnection};

#[doc(hidden)]
pub use uuid::Uuid;

#[doc(hidden)]
pub use connetto_core::bots::BotRegistryIdSql;

/// One statement of a [`ConnettoBotSchema`], run on a borrowed connection.
pub type Statement<'c, T> = Pin<Box<dyn Future<Output = QueryResult<T>> + Send + 'c>>;

/// One of the four verbs a list entry declares, named once in the core so a
/// session's list and the registry's rows name the same verb.
pub use connetto_core::bots::Verb;

/// A `verb` column spelling outside the four the `CHECK` allows.
#[derive(Debug, thiserror::Error)]
#[error("a verb outside the four: {0}")]
struct VerbSpelling(String);

/// A verb read back from its `TEXT` column, which the `CHECK` holds to one of
/// the four.
///
/// # Errors
///
/// A deserialization error when the column spells no verb.
#[doc(hidden)]
pub fn __verb(spelled: &str) -> QueryResult<Verb> {
    match spelled {
        "read" => Ok(Verb::Read),
        "insert" => Ok(Verb::Insert),
        "update" => Ok(Verb::Update),
        "delete" => Ok(Verb::Delete),
        other => Err(diesel::result::Error::DeserializationError(Box::new(
            VerbSpelling(other.to_owned()),
        ))),
    }
}

/// One entry of a bot's list, a table, one of its verbs and whether an
/// installation must accept its table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// The table the entry names.
    pub table: String,
    /// The verb the entry declares on it.
    pub verb: Verb,
    /// Whether an installation takes the table at all, so its entries join
    /// the effective list only when the installation accepts it.
    pub optional: bool,
}

/// A stored row of one list version, as [`ConnettoBotSchema::list_rows`]
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRow {
    /// The table the entry names.
    pub table: String,
    /// The verb the entry declares on it.
    pub verb: Verb,
    /// Whether the entry's table is optional for an installation.
    pub optional: bool,
}

/// The code row a hash names, locked `FOR UPDATE` until the transaction ends.
#[derive(Debug, Clone)]
pub struct CodeFacts<Id> {
    /// The signed-in person who created the code, the bot its registration
    /// will own.
    pub creator: Id,
    /// The bot the code names, absent for a first registration.
    pub bot: Option<Uuid>,
    /// Whether a registration spent the code.
    pub spent: bool,
    /// Whether the database's clock is past the code's expiry plus `DEVICE_SKEW`.
    pub expired: bool,
}

/// A bot row the registration inserts.
#[derive(Debug, Clone)]
pub struct NewBot<Id> {
    /// The id connetto minted at the first registration.
    pub id: Uuid,
    /// The registration code's creator.
    pub owner: Id,
    /// The name the registration gave it.
    pub name: String,
    /// Its Ed25519 public key, 32 bytes.
    pub public_key: [u8; 32],
    /// The current list version, 1 for a first registration.
    pub list_version: i32,
    /// The wake URL R103 registers for it, absent until then.
    pub wake_url: Option<String>,
}

/// A bot's `list_version` and `public_key`, locked `FOR UPDATE` until the
/// transaction ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotFacts {
    /// The current list version.
    pub list_version: i32,
    /// The key a login will verify against.
    pub public_key: [u8; 32],
}

/// A bot public key read back from its `BYTEA` column.
///
/// # Errors
///
/// A deserialization error when the column does not hold 32 bytes.
#[doc(hidden)]
pub fn __public_key(bytes: &[u8]) -> QueryResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|err| diesel::result::Error::DeserializationError(Box::new(err)))
}

/// An installation as stored: the bot it runs, the owner it serves and the
/// list version its admin accepted, with the optional table names it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation<Id> {
    /// The bot the installation runs.
    pub bot: Uuid,
    /// The owner it serves.
    pub owner: Id,
    /// The list version the admin accepted.
    pub accepted_version: i32,
    /// The optional tables it accepted.
    pub optional_tables: Vec<String>,
}

/// What a registration settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    /// The bot id, minted at the first registration and kept by later ones.
    pub bot: Uuid,
    /// The current list version, 1 for a first registration.
    pub version: i32,
}

/// What the registry could not do, the undisclosing refusal apart from the
/// database failing to answer.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A code that is missing, used or expired, or an installation the
    /// registry does not know.
    #[error("refused")]
    Refused,
    /// The owner pool could not hand out a connection.
    #[error("the registry pool is unreachable")]
    Pool(#[source] diesel_async::pooled_connection::bb8::RunError),
    /// A statement the registry runs failed.
    #[error("the registry statement failed")]
    Query(#[from] diesel::result::Error),
}

/// The bot registry tables, one statement per function.
///
/// Every function runs at most one statement on the connection it is handed,
/// inside the transaction the store opened, and decides nothing.
pub trait ConnettoBotSchema: Send + Sync + 'static {
    /// The deployment's typed distributed user id.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The tables this member reads and writes, by name, which startup
    /// requires to exist, since every connection can register a bot (R98
    /// decision 5).
    const TABLES: &'static [&'static str];

    /// The registry `Id` column's SQL type, which names the registry DDL the
    /// deployment's schema document carries and the translated schema uses.
    type IdSql: BotRegistryIdSql;

    /// The code row `code_hash` names, locked `FOR UPDATE`, and its creator,
    /// the bot it names, whether it spent and whether it lapsed by the
    /// database's clock.
    fn code_facts(
        conn: &mut AsyncPgConnection,
        code_hash: [u8; 32],
    ) -> Statement<'_, Option<CodeFacts<Self::Id>>>;

    /// Mark the code used, stamped by the statement's `now()`.
    fn use_code(conn: &mut AsyncPgConnection, code_hash: [u8; 32]) -> Statement<'_, ()>;

    /// Insert a bot row.
    fn insert_bot(conn: &mut AsyncPgConnection, bot: NewBot<Self::Id>) -> Statement<'_, ()>;

    /// The bot's `list_version` and `public_key`, locked `FOR UPDATE`, absent
    /// when the bot row is gone.
    fn bot_facts(conn: &mut AsyncPgConnection, bot: Uuid) -> Statement<'_, Option<BotFacts>>;

    /// Set a new `public_key` and/or `list_version` on the bot, each when
    /// given.
    fn set_bot(
        conn: &mut AsyncPgConnection,
        bot: Uuid,
        public_key: Option<[u8; 32]>,
        list_version: Option<i32>,
    ) -> Statement<'_, ()>;

    /// Insert the list rows of `(bot, version)`, one row per entry.
    fn insert_list<'c>(
        conn: &'c mut AsyncPgConnection,
        bot: Uuid,
        version: i32,
        entries: &'c [ListEntry],
    ) -> Statement<'c, ()>;

    /// The list rows of `(bot, version)`, by table and verb.
    fn list_rows(
        conn: &mut AsyncPgConnection,
        bot: Uuid,
        version: i32,
    ) -> Statement<'_, Vec<ListRow>>;

    /// The installation `installation` names, its bot, owner and accepted
    /// version and the optional table names it accepted, absent when the
    /// id names no installation.
    fn installation<'c>(
        conn: &'c mut AsyncPgConnection,
        installation: &'c Self::Id,
    ) -> Statement<'c, Option<Installation<Self::Id>>>;
}

/// The bot registry over the deployment's registry tables, `D`'s `Bots`
/// member, on the owner pool.
///
/// [`Bots`]: crate::schema::ConnettoSchema::Bots
#[must_use]
pub fn pg_bot_registry<D>(pool: Pool<AsyncPgConnection>) -> PgBotRegistry<D::Bots>
where
    D: crate::schema::ConnettoSchema,
{
    PgBotRegistry::new(pool)
}

/// The Postgres bot registry, generic over the deployment's member.
pub struct PgBotRegistry<S> {
    pool: Pool<AsyncPgConnection>,
    schema: PhantomData<fn() -> S>,
}

impl<S: ConnettoBotSchema> PgBotRegistry<S> {
    /// The registry over the deployment's tables.
    #[must_use]
    pub fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self {
            pool,
            schema: PhantomData,
        }
    }

    /// Register under `code_hash` in one transaction. The code must be
    /// present, unspent and unexpired, else the undisclosing refusal and
    /// nothing moves. A code that names no bot mints one under the creator
    /// with `list_version` 1 and the list. A code that names a bot keeps the
    /// id, stores a differing `public_key`, and inserts the list as
    /// `list_version + 1` and bumps the bot only when the list differs as a
    /// set, leaving older versions' rows and every installation's
    /// `accepted_version` untouched. The code spends either way.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Refused`] for a missing, used or expired code,
    /// [`RegistryError::Pool`] when no connection was available, and
    /// [`RegistryError::Query`] when a statement failed.
    pub async fn register(
        &self,
        code_hash: [u8; 32],
        public_key: [u8; 32],
        name: String,
        list: &[ListEntry],
    ) -> Result<Registered, RegistryError> {
        let mut conn = self.pool.get().await.map_err(RegistryError::Pool)?;
        conn.transaction::<_, RegistryError, _>(async move |c| {
            let facts = S::code_facts(c, code_hash)
                .await?
                .ok_or(RegistryError::Refused)?;
            if facts.spent || facts.expired {
                return Err(RegistryError::Refused);
            }
            let (bot, version) = match facts.bot {
                None => {
                    let id = Uuid::new_v4();
                    let new = NewBot {
                        id,
                        owner: facts.creator,
                        name,
                        public_key,
                        list_version: 1,
                        wake_url: None,
                    };
                    S::insert_bot(c, new).await?;
                    S::insert_list(c, id, 1, list).await?;
                    (id, 1)
                }
                Some(id) => {
                    let facts = S::bot_facts(c, id).await?.ok_or(RegistryError::Refused)?;
                    let key_changed = facts.public_key != public_key;
                    let current = S::list_rows(c, id, facts.list_version).await?;
                    let list_changed = Self::lists_differ(&current, list);
                    let version = if list_changed {
                        facts.list_version + 1
                    } else {
                        facts.list_version
                    };
                    if key_changed || list_changed {
                        S::set_bot(
                            c,
                            id,
                            key_changed.then_some(public_key),
                            list_changed.then_some(version),
                        )
                        .await?;
                        if list_changed {
                            S::insert_list(c, id, version, list).await?;
                        }
                    }
                    (id, version)
                }
            };
            S::use_code(c, code_hash).await?;
            Ok(Registered { bot, version })
        })
        .await
    }

    /// The accepted version's required entries plus the optional entries
    /// whose table the installation accepted, by table and verb.
    ///
    /// # Errors
    ///
    /// [`RegistryError::Refused`] when the id names no installation,
    /// [`RegistryError::Pool`] when no connection was available, and
    /// [`RegistryError::Query`] when a statement failed.
    pub async fn effective_list(
        &self,
        installation: &S::Id,
    ) -> Result<Vec<(String, Verb)>, RegistryError> {
        let mut conn = self.pool.get().await.map_err(RegistryError::Pool)?;
        let installation = S::installation(&mut conn, installation)
            .await?
            .ok_or(RegistryError::Refused)?;
        let accepted: HashSet<&str> = installation
            .optional_tables
            .iter()
            .map(String::as_str)
            .collect();
        Ok(
            S::list_rows(&mut conn, installation.bot, installation.accepted_version)
                .await?
                .into_iter()
                .filter(|row| !row.optional || accepted.contains(row.table.as_str()))
                .map(|row| (row.table, row.verb))
                .collect(),
        )
    }

    /// Whether `list` differs from the stored `rows` as a set of table, verb
    /// and optional triples.
    fn lists_differ(rows: &[ListRow], list: &[ListEntry]) -> bool {
        let stored: BTreeSet<(&str, Verb, bool)> = rows
            .iter()
            .map(|row| (row.table.as_str(), row.verb, row.optional))
            .collect();
        let offered: BTreeSet<(&str, Verb, bool)> = list
            .iter()
            .map(|entry| (entry.table.as_str(), entry.verb, entry.optional))
            .collect();
        stored != offered
    }
}

/// Generate the default bot registry tables and their
/// [`ConnettoBotSchema`] impl, over the deployment's `Id` SQL type, plus the
/// tables' DDL with that type in the id columns, [`BOTS_DDL`], which a
/// deployment includes in its schema document.
///
/// Invoked at module scope with `diesel` in scope, it emits the five
/// `diesel::table!` modules and a unit struct `ConnettoBots`.
#[doc(hidden)]
#[macro_export]
macro_rules! connetto_bots_tables {
    ($id:ty, $id_sql:ty) => {
        connetto_core::connetto_registry_tables!(pg, $id_sql);

        /// The registry tables' DDL over the deployment's `Id` SQL type,
        /// which a deployment includes in its schema document.
        pub const BOTS_DDL: &str = <$id_sql as $crate::bots::BotRegistryIdSql>::DDL;

        /// The default bot registry tables over the deployment's `Id`.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoBots;

        impl $crate::bots::ConnettoBotSchema for ConnettoBots {
            type Id = $id;
            type IdSql = $id_sql;
            const TABLES: &'static [&'static str] = connetto_core::bots::REGISTRY_TABLES;

            fn code_facts(
                conn: &mut diesel_async::AsyncPgConnection,
                code_hash: [u8; 32],
            ) -> $crate::bots::Statement<'_, Option<$crate::bots::CodeFacts<Self::Id>>> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, OptionalExtension as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let found: Option<($id, Option<$crate::bots::Uuid>, bool, bool)> =
                        RunQueryDsl::first(
                            QueryDsl::for_update(QueryDsl::select(
                                QueryDsl::filter(
                                    connetto_registration_codes::table,
                                    connetto_registration_codes::code_hash.eq(code_hash.to_vec()),
                                ),
                                (
                                    connetto_registration_codes::creator,
                                    connetto_registration_codes::bot,
                                    connetto_registration_codes::used_at.is_not_null(),
                                    // The minting device's clock wrote the
                                    // expiry, so it gets `DEVICE_SKEW` (chapter 21).
                                    connetto_registration_codes::expires_at.le(diesel::dsl::sql::<
                                        diesel::sql_types::Timestamptz,
                                    >(
                                        "now() - make_interval(secs => ",
                                    )
                                    .bind::<diesel::sql_types::Double, _>(
                                        $crate::db_clock::DEVICE_SKEW_SECS,
                                    )
                                    .sql(")")),
                                ),
                            )),
                            conn,
                        )
                        .await
                        .optional()?;
                    Ok(
                        found.map(|(creator, bot, spent, expired)| $crate::bots::CodeFacts {
                            creator,
                            bot,
                            spent,
                            expired,
                        }),
                    )
                })
            }

            fn use_code(
                conn: &mut diesel_async::AsyncPgConnection,
                code_hash: [u8; 32],
            ) -> $crate::bots::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl as _;
                    diesel::update(QueryDsl::filter(
                        connetto_registration_codes::table,
                        connetto_registration_codes::code_hash.eq(code_hash.to_vec()),
                    ))
                    .set(connetto_registration_codes::used_at.eq(diesel::dsl::sql::<
                        diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                    >("now()")))
                    .execute(conn)
                    .await?;
                    Ok(())
                })
            }

            fn insert_bot(
                conn: &mut diesel_async::AsyncPgConnection,
                bot: $crate::bots::NewBot<Self::Id>,
            ) -> $crate::bots::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    let $crate::bots::NewBot {
                        id,
                        owner,
                        name,
                        public_key,
                        list_version,
                        wake_url,
                    } = bot;
                    diesel::insert_into(connetto_bots::table)
                        .values((
                            connetto_bots::id.eq(id),
                            connetto_bots::owner.eq(owner),
                            connetto_bots::name.eq(name),
                            connetto_bots::public_key.eq(public_key.to_vec()),
                            connetto_bots::list_version.eq(list_version),
                            connetto_bots::wake_url.eq(wake_url),
                        ))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            }

            fn bot_facts(
                conn: &mut diesel_async::AsyncPgConnection,
                bot: $crate::bots::Uuid,
            ) -> $crate::bots::Statement<'_, Option<$crate::bots::BotFacts>> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, OptionalExtension as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let found: Option<(i32, Vec<u8>)> = RunQueryDsl::first(
                        QueryDsl::for_update(QueryDsl::select(
                            QueryDsl::filter(connetto_bots::table, connetto_bots::id.eq(bot)),
                            (connetto_bots::list_version, connetto_bots::public_key),
                        )),
                        conn,
                    )
                    .await
                    .optional()?;
                    match found {
                        None => Ok(None),
                        Some((list_version, public_key)) => Ok(Some($crate::bots::BotFacts {
                            list_version,
                            public_key: $crate::bots::__public_key(&public_key)?,
                        })),
                    }
                })
            }

            fn set_bot(
                conn: &mut diesel_async::AsyncPgConnection,
                bot: $crate::bots::Uuid,
                public_key: Option<[u8; 32]>,
                list_version: Option<i32>,
            ) -> $crate::bots::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl as _;
                    let table = QueryDsl::filter(connetto_bots::table, connetto_bots::id.eq(bot));
                    match (public_key, list_version) {
                        (Some(key), Some(version)) => {
                            diesel::update(table)
                                .set((
                                    connetto_bots::public_key.eq(key.to_vec()),
                                    connetto_bots::list_version.eq(version),
                                ))
                                .execute(conn)
                                .await?;
                        }
                        (Some(key), None) => {
                            diesel::update(table)
                                .set(connetto_bots::public_key.eq(key.to_vec()))
                                .execute(conn)
                                .await?;
                        }
                        (None, Some(version)) => {
                            diesel::update(table)
                                .set(connetto_bots::list_version.eq(version))
                                .execute(conn)
                                .await?;
                        }
                        (None, None) => {}
                    }
                    Ok(())
                })
            }

            fn insert_list<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                bot: $crate::bots::Uuid,
                version: i32,
                entries: &'c [$crate::bots::ListEntry],
            ) -> $crate::bots::Statement<'c, ()> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    let rows = entries
                        .iter()
                        .map(|entry| {
                            (
                                connetto_bot_lists::bot.eq(bot),
                                connetto_bot_lists::version.eq(version),
                                connetto_bot_lists::table_name.eq(entry.table.clone()),
                                connetto_bot_lists::verb.eq(entry.verb.as_str().to_owned()),
                                connetto_bot_lists::optional.eq(entry.optional),
                            )
                        })
                        .collect::<Vec<_>>();
                    diesel::insert_into(connetto_bot_lists::table)
                        .values(rows)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            }

            fn list_rows(
                conn: &mut diesel_async::AsyncPgConnection,
                bot: $crate::bots::Uuid,
                version: i32,
            ) -> $crate::bots::Statement<'_, Vec<$crate::bots::ListRow>> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let keyed = QueryDsl::filter(
                        QueryDsl::filter(
                            connetto_bot_lists::table,
                            connetto_bot_lists::bot.eq(bot),
                        ),
                        connetto_bot_lists::version.eq(version),
                    );
                    let ordered = QueryDsl::order_by(
                        keyed,
                        (
                            connetto_bot_lists::table_name.asc(),
                            connetto_bot_lists::verb.asc(),
                        ),
                    );
                    let rows: Vec<(String, String, bool)> = RunQueryDsl::load(
                        QueryDsl::select(
                            ordered,
                            (
                                connetto_bot_lists::table_name,
                                connetto_bot_lists::verb,
                                connetto_bot_lists::optional,
                            ),
                        ),
                        conn,
                    )
                    .await?;
                    rows.into_iter()
                        .map(|(table, verb, optional)| {
                            Ok($crate::bots::ListRow {
                                table,
                                verb: $crate::bots::__verb(&verb)?,
                                optional,
                            })
                        })
                        .collect()
                })
            }

            fn installation<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                installation: &'c Self::Id,
            ) -> $crate::bots::Statement<'c, Option<$crate::bots::Installation<Self::Id>>> {
                Box::pin(async move {
                    use diesel::{
                        ExpressionMethods as _, JoinOnDsl as _, NullableExpressionMethods as _,
                        QueryDsl,
                    };
                    use diesel_async::RunQueryDsl;
                    let keyed = QueryDsl::filter(
                        connetto_installations::table,
                        connetto_installations::id.eq(installation.clone()),
                    );
                    let joined = QueryDsl::left_join(
                        keyed,
                        connetto_installation_optional_tables::table
                            .on(connetto_installation_optional_tables::installation
                                .eq(connetto_installations::id)),
                    );
                    let ordered = QueryDsl::order_by(
                        joined,
                        connetto_installation_optional_tables::table_name,
                    );
                    let rows: Vec<($crate::bots::Uuid, $id, i32, Option<String>)> =
                        RunQueryDsl::load(
                            QueryDsl::select(
                                ordered,
                                (
                                    connetto_installations::bot,
                                    connetto_installations::owner,
                                    connetto_installations::accepted_version,
                                    connetto_installation_optional_tables::table_name.nullable(),
                                ),
                            ),
                            conn,
                        )
                        .await?;
                    if rows.is_empty() {
                        return Ok(None);
                    }
                    let (bot, owner, accepted_version, _) = rows[0].clone();
                    let optional_tables = rows.into_iter().map(|row| row.3).flatten().collect();
                    Ok(Some($crate::bots::Installation {
                        bot,
                        owner,
                        accepted_version,
                        optional_tables,
                    }))
                })
            }
        }
    };
}
