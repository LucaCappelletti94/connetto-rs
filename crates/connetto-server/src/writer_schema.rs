//! The structural contract the write target keys its exactly-once frontier
//! against, the server's writer tables (R75).
//!
//! connetto owns no schema. A deployment declares its own writer tables (see
//! `docs/architecture/11-authentication.md`) and implements
//! [`ConnettoWriterSchema`] for them, either by hand or through
//! [`connetto_writers_table!`](crate::connetto_writers_table), and names it as
//! the `Writers` member of its [`ConnettoSchema`](crate::schema::ConnettoSchema).
//!
//! Two tables carry the domain. `_connetto_writers` holds one row per writer
//! with its applied frontier: `writer` (a number the server issues; a number
//! writer's number is its own `writer` value), `user_id` (the account, absent
//! for an anonymous caller), `device_key` (the device key's id, absent for a
//! number writer, unique when present), `frontier` (the highest settled
//! sequence), `head` (that entry's chain hash) and `retired_at`.
//! `_connetto_settled` holds one row per settled `(writer, seq)` with the
//! entry's chain hash, its outcome as JSON text, the path that settled it and
//! the settle time. The frontier counts every final answer, applied, refused
//! or conflicted, and every path takes only the frontier plus one.
//!
//! Every associated statement is laundered as a boxed future because the
//! diesel `future` trait solver cannot name the `INSERT ... ON CONFLICT ...
//! RETURNING` and `UPDATE` statement types generically. The default impl
//! builds them concretely, the same way the audit and enrolment members do.

use std::pin::Pin;
use std::time::SystemTime;

use connetto_core::messages::MutationRejectReason;
use diesel::QueryResult;
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel_async::AsyncPgConnection;
use serde::{Deserialize, Serialize};
use std::io::Write as _;

/// The Postgres enum type backing the settle `path` column.
pub const SETTLE_PATH_TYPE: &str = "connetto_settle_path";

/// The Postgres enum type marker for [`SettlePath`].
#[derive(diesel::SqlType, diesel::query_builder::QueryId)]
#[diesel(postgres_type(name = "connetto_settle_path"))]
pub struct SettlePathSql;

/// The path that settled one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = SettlePathSql)]
pub enum SettlePath {
    /// The client's own upload over the direct connection.
    Direct,
    /// An import restored the entry, or a retired writer's device carried it
    /// forward under a fresh writer.
    Restore,
    /// The courier carried it between devices (R78 adds the transport).
    Courier,
}

impl SettlePath {
    /// The label this value carries in Postgres, and the one the enum type
    /// declares.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Restore => "restore",
            Self::Courier => "courier",
        }
    }
}

impl ToSql<SettlePathSql, Pg> for SettlePath {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.label().as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<SettlePathSql, Pg> for SettlePath {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"direct" => Ok(Self::Direct),
            b"restore" => Ok(Self::Restore),
            b"courier" => Ok(Self::Courier),
            other => Err(format!(
                "unrecognised connetto_settle_path label {:?}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

/// The outcome a settled entry answers with, the one column that re-answers
/// an applied, a rejected (with its full reason) or a conflicted (with its
/// table) write.
///
/// Externally tagged, since the arbitrary-precision `serde_json` this crate
/// builds with cannot re-read a number an internally tagged enum buffers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SettledOutcome {
    /// The entry applied, or a byte-identical re-delivery of one answered the
    /// same way.
    #[serde(rename = "applied")]
    Applied,
    /// The entry was refused, with the reason the client rolls back on.
    #[serde(rename = "rejected")]
    Rejected(MutationRejectReason),
    /// The entry conflicted with the row it replaced; the table, version
    /// column and primary key name the row so a re-answer can read its current
    /// copy fresh.
    #[serde(rename = "conflict")]
    Conflict {
        /// Table carrying the conflicting row.
        table: String,
        /// The column carrying the row version the conflict is checked against.
        version_column: String,
        /// The primary key columns naming the row.
        pk_columns: Vec<String>,
        /// The primary key values naming the row, one per `pk_columns` entry.
        pk_values: Vec<StoredValue>,
    },
}

/// A primary-key value carried by a settled conflict outcome. The five wire
/// value kinds, tagged, so a re-answer can bind them into a fresh row read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum StoredValue {
    /// SQL NULL.
    Null,
    /// A 64-bit integer.
    Integer(i64),
    /// An IEEE 754 double.
    Real(f64),
    /// UTF-8 text.
    Text(String),
    /// Raw bytes.
    Blob(Vec<u8>),
}

impl SettledOutcome {
    /// The column's JSON text for this outcome.
    ///
    /// # Panics
    ///
    /// When the outcome fails to serialize to JSON text.
    pub fn json(&self) -> String {
        serde_json::to_string(self).expect("a settled outcome serializes")
    }

    /// Read the column's JSON text back into the outcome it stored.
    ///
    /// # Errors
    ///
    /// When the text is not valid JSON of a stored outcome.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// One statement of a [`ConnettoWriterSchema`], run on a borrowed
/// connection.
pub type Statement<'c, T> = Pin<Box<dyn Future<Output = QueryResult<T>> + Send + 'c>>;

/// One writer's row, as the schema reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterRow<Id> {
    /// The server-issued writer number; a number writer's number is this.
    pub writer: i64,
    /// The account the writer belongs to, absent for an anonymous caller.
    pub user_id: Option<Id>,
    /// The device key's id, absent for a number writer.
    pub device_key: Option<Vec<u8>>,
    /// The highest settled sequence, 0 when nothing settled.
    pub frontier: i64,
    /// The frontier entry's chain hash, absent when nothing settled.
    pub head: Option<Vec<u8>>,
    /// When the writer retired, if it did.
    pub retired_at: Option<SystemTime>,
}

/// One settled entry's row, as the schema reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledRow {
    /// The entry's chain hash.
    pub entry_hash: Vec<u8>,
    /// The chain head the entry hashed under, its predecessor's evidence,
    /// retained with the row so a redelivery verifies against it rather
    /// than a preceding row the prune may have removed.
    pub previous_hash: Vec<u8>,
    /// The stored outcome, its JSON text.
    pub outcome: Vec<u8>,
    /// The path that settled it.
    pub path: SettlePath,
}

/// The writer tables, laundered one statement per member.
///
/// Every `fn` member builds the statement it names; the impl runs it on the
/// connection the caller holds, inside the caller's transaction.
pub trait ConnettoWriterSchema: Send + Sync + 'static {
    /// The deployment's typed distributed user id, the same one the store
    /// schema carries.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;

    /// The tables this member reads and writes, by name, which startup
    /// requires to exist (R98 decision 5).
    const TABLES: &'static [&'static str];

    /// `INSERT _connetto_writers (user_id, session_id) RETURNING writer,
    /// frontier`, the issue of a fresh number writer at frontier 0. The
    /// `session_id` is the run's durable handle and is set only for a number
    /// writer issued to a caller with no identity.
    fn issue(
        conn: &mut AsyncPgConnection,
        user_id: Option<Self::Id>,
        session_id: Option<uuid::Uuid>,
    ) -> Statement<'_, (i64, i64)>;
    /// `SELECT` the number writer `writer` of the caller, `None` when no such
    /// writer exists. An identified caller meets a writer of its account and
    /// nothing else; an anonymous caller meets the writer its run handle
    /// `session_id` holds and nothing else, so a guessed number of another
    /// run is never admitted.
    fn by_number<'c>(
        conn: &'c mut AsyncPgConnection,
        writer: i64,
        user_id: Option<&'c Self::Id>,
        session_id: Option<&'c uuid::Uuid>,
    ) -> Statement<'c, Option<WriterRow<Self::Id>>>;
    /// `SELECT` the settled row `(writer, seq)`, `None` when pruned or never
    /// settled.
    fn settled(
        conn: &mut AsyncPgConnection,
        writer: i64,
        seq: i64,
    ) -> Statement<'_, Option<SettledRow>>;
    /// `INSERT ... ON CONFLICT (writer, seq) DO NOTHING`, settling one entry
    /// with `entry_hash`, `previous_hash`, `outcome` and `path`, reporting
    /// whether this statement won the sequence.
    fn settle<'c>(
        conn: &'c mut AsyncPgConnection,
        writer: i64,
        seq: i64,
        entry_hash: &'c [u8],
        previous_hash: &'c [u8],
        outcome: &'c str,
        path: SettlePath,
    ) -> Statement<'c, bool>;
    /// `UPDATE ... SET frontier = seq, head = head WHERE writer AND frontier
    /// = seq - 1`, reporting whether the frontier advanced.
    fn advance<'c>(
        conn: &'c mut AsyncPgConnection,
        writer: i64,
        seq: i64,
        head: &'c [u8],
    ) -> Statement<'c, bool>;
    /// `UPDATE ... SET outcome WHERE (writer, seq)`, restating a reserved
    /// entry's outcome in the transaction that refused it, reporting whether
    /// it matched the reservation.
    fn settle_outcome<'c>(
        conn: &'c mut AsyncPgConnection,
        writer: i64,
        seq: i64,
        outcome: &'c str,
    ) -> Statement<'c, bool>;
    /// `DELETE` the settled rows of `writer` at or below `seq`, the
    /// `settled_through` prune of a number writer.
    fn prune(conn: &mut AsyncPgConnection, writer: i64, seq: i64) -> Statement<'_, i64>;
}

/// Generate the default connetto writer tables and their
/// [`ConnettoWriterSchema`] impl, parameterized by the deployment's `Id`
/// type and the SQL type it stores as.
///
/// A convenience default only: the tables are the deployment's to define
/// however it likes, and [`ConnettoWriterSchema`] is the real contract,
/// implementable by hand against any tables. The reference SQL, including the
/// `connetto_settle_path` enum this depends on, is in
/// `docs/architecture/11-authentication.md`.
///
/// Invoked at module scope, it emits the `_connetto_writers` and
/// `_connetto_settled` `diesel::table!` modules and a unit struct
/// `ConnettoWriters` implementing the trait. The caller needs `diesel` and
/// `diesel_async` in scope.
///
/// ```ignore
/// connetto_server::connetto_writers_table!(String, diesel::sql_types::Text);
/// // now `ConnettoWriters` implements `ConnettoWriterSchema`.
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! connetto_writers_table {
    ($id:ty, $id_sql:ty $(,)?) => {
        diesel::table! {
            /// One writer's applied frontier (R75). The `writer` number is
            /// issued by the server and is a number writer's number; a device
            /// writer is looked up by its key's id in `device_key`.
            _connetto_writers (writer) {
                /// The server-issued writer number.
                writer -> diesel::sql_types::BigInt,
                /// The account the writer belongs to, absent for an
                /// anonymous caller.
                user_id -> diesel::sql_types::Nullable<$id_sql>,
                /// The run's durable handle a number writer is bound to, set
                /// only for a number writer issued to a caller with no
                /// identity.
                session_id -> diesel::sql_types::Nullable<diesel::sql_types::Uuid>,
                /// The device key's id, absent for a number writer.
                device_key -> diesel::sql_types::Nullable<diesel::sql_types::Bytea>,
                /// The highest settled sequence, 0 when nothing settled.
                frontier -> diesel::sql_types::BigInt,
                /// The frontier entry's chain hash.
                head -> diesel::sql_types::Nullable<diesel::sql_types::Bytea>,
                /// When the writer retired.
                retired_at -> diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
            }
        }

        diesel::table! {
            /// One settled entry's row (R75): the chain hash, the stored
            /// outcome, the path that settled it.
            _connetto_settled (writer, seq) {
                /// The writer the entry settled under.
                writer -> diesel::sql_types::BigInt,
                /// The entry's sequence for that writer.
                seq -> diesel::sql_types::BigInt,
                /// The entry's chain hash, computed from the chain and the
                /// changeset bytes.
                entry_hash -> diesel::sql_types::Bytea,
                /// The chain head the entry hashed under, its predecessor's
                /// evidence.
                previous_hash -> diesel::sql_types::Bytea,
                /// The stored outcome, [`$crate::writer_schema::SettledOutcome`]
                /// as JSON text.
                outcome -> diesel::sql_types::Text,
                /// The path that settled it.
                path -> $crate::writer_schema::SettlePathSql,
                /// When it settled, defaulted by the column.
                settled_at -> diesel::sql_types::Timestamptz,
            }
        }

        diesel::allow_tables_to_appear_in_same_query!(_connetto_writers, _connetto_settled,);

        /// The default connetto writer schema over the deployment's `Id` type.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoWriters;

        impl $crate::writer_schema::ConnettoWriterSchema for ConnettoWriters {
            type Id = $id;
            const TABLES: &'static [&'static str] = &["_connetto_writers", "_connetto_settled"];

            fn issue(
                conn: &mut diesel_async::AsyncPgConnection,
                user_id: Option<Self::Id>,
                session_id: Option<uuid::Uuid>,
            ) -> $crate::writer_schema::Statement<'_, (i64, i64)> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    diesel::insert_into(_connetto_writers::table)
                        .values((
                            _connetto_writers::user_id.eq(user_id),
                            _connetto_writers::session_id.eq(session_id),
                            _connetto_writers::frontier.eq(0),
                        ))
                        .returning((_connetto_writers::writer, _connetto_writers::frontier))
                        .get_result(&mut *conn)
                        .await
                })
            }

            fn by_number<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                writer: i64,
                user_id: Option<&'c Self::Id>,
                session_id: Option<&'c uuid::Uuid>,
            ) -> $crate::writer_schema::Statement<
                'c,
                Option<$crate::writer_schema::WriterRow<Self::Id>>,
            > {
                Box::pin(async move {
                    use diesel::{
                        ExpressionMethods as _, NullableExpressionMethods as _,
                        OptionalExtension as _, PgExpressionMethods as _, QueryDsl,
                    };
                    use diesel_async::RunQueryDsl;
                    let query = QueryDsl::select(
                        QueryDsl::filter(
                            QueryDsl::filter(
                                QueryDsl::filter(
                                    _connetto_writers::table,
                                    _connetto_writers::writer.eq(writer),
                                ),
                                _connetto_writers::user_id
                                    .nullable()
                                    .is_not_distinct_from(user_id.cloned()),
                            ),
                            _connetto_writers::session_id
                                .nullable()
                                .is_not_distinct_from(session_id.cloned()),
                        ),
                        (
                            _connetto_writers::writer,
                            _connetto_writers::user_id,
                            _connetto_writers::device_key,
                            _connetto_writers::frontier,
                            _connetto_writers::head,
                            _connetto_writers::retired_at,
                        ),
                    );
                    let row: Option<(
                        i64,
                        Option<$id>,
                        Option<Vec<u8>>,
                        i64,
                        Option<Vec<u8>>,
                        Option<$crate::authn::schema::Instant>,
                    )> = RunQueryDsl::first(query, &mut *conn).await.optional()?;
                    Ok(row.map(
                        |(writer, user_id, device_key, frontier, head, retired_at)| {
                            $crate::writer_schema::WriterRow {
                                writer,
                                user_id,
                                device_key,
                                frontier,
                                head,
                                retired_at: retired_at.map(From::from),
                            }
                        },
                    ))
                })
            }

            fn settled(
                conn: &mut diesel_async::AsyncPgConnection,
                writer: i64,
                seq: i64,
            ) -> $crate::writer_schema::Statement<'_, Option<$crate::writer_schema::SettledRow>>
            {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, OptionalExtension as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let query = QueryDsl::select(
                        QueryDsl::filter(
                            QueryDsl::filter(
                                _connetto_settled::table,
                                _connetto_settled::writer.eq(writer),
                            ),
                            _connetto_settled::seq.eq(seq),
                        ),
                        (
                            _connetto_settled::entry_hash,
                            _connetto_settled::previous_hash,
                            _connetto_settled::outcome,
                            _connetto_settled::path,
                        ),
                    );
                    let row: Option<(Vec<u8>, Vec<u8>, String, $crate::writer_schema::SettlePath)> =
                        RunQueryDsl::first(query, &mut *conn).await.optional()?;
                    Ok(row.map(|(entry_hash, previous_hash, outcome, path)| {
                        $crate::writer_schema::SettledRow {
                            entry_hash,
                            previous_hash,
                            outcome: outcome.into_bytes(),
                            path,
                        }
                    }))
                })
            }

            fn settle<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                writer: i64,
                seq: i64,
                entry_hash: &'c [u8],
                previous_hash: &'c [u8],
                outcome: &'c str,
                path: $crate::writer_schema::SettlePath,
            ) -> $crate::writer_schema::Statement<'c, bool> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    let affected = diesel::insert_into(_connetto_settled::table)
                        .values((
                            _connetto_settled::writer.eq(writer),
                            _connetto_settled::seq.eq(seq),
                            _connetto_settled::entry_hash.eq(entry_hash.to_vec()),
                            _connetto_settled::previous_hash.eq(previous_hash.to_vec()),
                            _connetto_settled::outcome.eq(outcome.to_owned()),
                            _connetto_settled::path.eq(path),
                        ))
                        .on_conflict((_connetto_settled::writer, _connetto_settled::seq))
                        .do_nothing()
                        .execute(&mut *conn)
                        .await?;
                    Ok(affected == 1)
                })
            }

            fn advance<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                writer: i64,
                seq: i64,
                head: &'c [u8],
            ) -> $crate::writer_schema::Statement<'c, bool> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let query = diesel::update(QueryDsl::filter(
                        QueryDsl::filter(
                            _connetto_writers::table,
                            _connetto_writers::writer.eq(writer),
                        ),
                        _connetto_writers::frontier.eq(seq - 1),
                    ))
                    .set((
                        _connetto_writers::frontier.eq(seq),
                        _connetto_writers::head.eq(head.to_vec()),
                    ));
                    let affected = RunQueryDsl::execute(query, &mut *conn).await?;
                    Ok(affected == 1)
                })
            }

            fn settle_outcome<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                writer: i64,
                seq: i64,
                outcome: &'c str,
            ) -> $crate::writer_schema::Statement<'c, bool> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let query = diesel::update(QueryDsl::filter(
                        QueryDsl::filter(
                            _connetto_settled::table,
                            _connetto_settled::writer.eq(writer),
                        ),
                        _connetto_settled::seq.eq(seq),
                    ))
                    .set(_connetto_settled::outcome.eq(outcome.to_owned()));
                    let affected = RunQueryDsl::execute(query, &mut *conn).await?;
                    Ok(affected == 1)
                })
            }

            fn prune(
                conn: &mut diesel_async::AsyncPgConnection,
                writer: i64,
                seq: i64,
            ) -> $crate::writer_schema::Statement<'_, i64> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let query = diesel::delete(QueryDsl::filter(
                        QueryDsl::filter(
                            _connetto_settled::table,
                            _connetto_settled::writer.eq(writer),
                        ),
                        _connetto_settled::seq.le(seq),
                    ));
                    let removed = RunQueryDsl::execute(query, &mut *conn).await?;
                    Ok(i64::try_from(removed).unwrap_or(i64::MAX))
                })
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_settled_outcome_round_trips_through_its_json() {
        for outcome in [
            SettledOutcome::Applied,
            SettledOutcome::Rejected(MutationRejectReason::Unauthorized),
            SettledOutcome::Rejected(MutationRejectReason::SchemaMismatch),
            SettledOutcome::Rejected(MutationRejectReason::Indeterminate),
            SettledOutcome::Rejected(MutationRejectReason::Forked),
            SettledOutcome::Rejected(MutationRejectReason::Malformed {
                detail: "bad patchset".into(),
            }),
            SettledOutcome::Rejected(MutationRejectReason::Constraint {
                detail: "unique violation".into(),
            }),
            SettledOutcome::Rejected(MutationRejectReason::Other {
                detail: "something else".into(),
            }),
            SettledOutcome::Conflict {
                table: "notes".into(),
                version_column: "updated_at".into(),
                pk_columns: vec!["id".into()],
                pk_values: vec![StoredValue::Text("1".into())],
            },
            SettledOutcome::Conflict {
                table: "multi".into(),
                version_column: "edited_at".into(),
                pk_columns: vec!["key".into(), "weight".into(), "tag".into()],
                pk_values: vec![
                    StoredValue::Text("a".into()),
                    StoredValue::Real(1.5),
                    StoredValue::Blob(vec![0, 1]),
                    StoredValue::Integer(7),
                    StoredValue::Null,
                ],
            },
        ] {
            let text = outcome.json();
            let parsed = SettledOutcome::from_json(text.as_bytes())
                .unwrap_or_else(|err| panic!("the stored text reads back: {err}, json: {text}"));
            assert_eq!(outcome, parsed);
        }
    }

    #[test]
    fn a_settle_path_keeps_its_label() {
        assert_eq!(SettlePath::Direct.label(), "direct");
        assert_eq!(SettlePath::Restore.label(), "restore");
        assert_eq!(SettlePath::Courier.label(), "courier");
    }
}
