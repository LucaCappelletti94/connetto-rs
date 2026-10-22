//! Needs Docker: the fixture starts its own Postgres.
//!
//! A deployment that names its own writer tables and types its user id as a
//! `uuid::Uuid` serves through the builder (R98 proof 3). The default
//! `_connetto_writers` and `_connetto_settled` tables are absent, so a write
//! that lands proves the server reads and writes through the deployment's member.

use std::sync::Arc;

use connetto_core::messages::{BulkMessage, ControlMessage, MutationHeader, MutationPatch};
use connetto_core::traits::Transport;
use connetto_server::{IdentityResolver, ResolveFuture, VerifiedClaims};
use connetto_test_harness::{Fixture, RowValue, insert_changeset, isolated_session_keyring};
use diesel::QueryDsl;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl as _;
use diesel_async::pooled_connection::bb8::Pool;
use tokio::net::TcpListener;

use super::e2e::{PG_SERIAL, exec, mint_tokens, reset_fixture};
use super::lifecycle::{admin_pool, builder_over, live_session, next_control, wait_ready};

/// The deployment's schema, every default member over a `Uuid` id but the
/// writers, which live in tables of its own.
mod app {
    use connetto_server::schema::ConnettoSchema;
    use connetto_server::writer_schema::{
        ConnettoWriterSchema, SettlePath, SettledRow, Statement, WriterRow,
    };
    use diesel_async::AsyncPgConnection;

    connetto_server::connetto_schema! {
        pub struct UuidDefaults;
        id: uuid::Uuid => diesel::sql_types::Uuid,
        audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
    }

    diesel::table! {
        app_writers (writer) {
            writer -> BigInt,
            user_id -> Nullable<Uuid>,
            session_id -> Nullable<Uuid>,
            device_key -> Nullable<Bytea>,
            frontier -> BigInt,
            head -> Nullable<Bytea>,
            retired_at -> Nullable<Timestamptz>,
        }
    }

    diesel::table! {
        app_settled (writer, seq) {
            writer -> BigInt,
            seq -> BigInt,
            entry_hash -> Bytea,
            previous_hash -> Bytea,
            outcome -> Text,
            path -> connetto_server::writer_schema::SettlePathSql,
            settled_at -> Timestamptz,
        }
    }

    /// The `app_writers` row as the columns the queries select.
    type WriterRowTuple = (
        i64,
        Option<uuid::Uuid>,
        Option<Vec<u8>>,
        i64,
        Option<Vec<u8>>,
        Option<connetto_server::authn::schema::Instant>,
    );

    pub struct AppWriters;

    impl ConnettoWriterSchema for AppWriters {
        type Id = uuid::Uuid;
        const TABLES: &'static [&'static str] = &["app_writers", "app_settled"];

        fn issue(
            conn: &mut AsyncPgConnection,
            user_id: Option<Self::Id>,
            session_id: Option<uuid::Uuid>,
        ) -> Statement<'_, (i64, i64)> {
            Box::pin(async move {
                use diesel::ExpressionMethods as _;
                use diesel_async::RunQueryDsl as _;
                diesel::insert_into(app_writers::table)
                    .values((
                        app_writers::user_id.eq(user_id),
                        app_writers::session_id.eq(session_id),
                        app_writers::frontier.eq(0),
                    ))
                    .returning((app_writers::writer, app_writers::frontier))
                    .get_result(&mut *conn)
                    .await
            })
        }

        fn by_number<'c>(
            conn: &'c mut AsyncPgConnection,
            writer: i64,
            user_id: Option<&'c Self::Id>,
            session_id: Option<&'c uuid::Uuid>,
        ) -> Statement<'c, Option<WriterRow<Self::Id>>> {
            Box::pin(async move {
                use diesel::{
                    ExpressionMethods, NullableExpressionMethods, OptionalExtension,
                    PgExpressionMethods, QueryDsl,
                };
                use diesel_async::RunQueryDsl;
                let query = app_writers::table
                    .filter(app_writers::writer.eq(writer))
                    .filter(
                        app_writers::user_id
                            .nullable()
                            .is_not_distinct_from(user_id.copied()),
                    )
                    .filter(
                        app_writers::session_id
                            .nullable()
                            .is_not_distinct_from(session_id.copied()),
                    )
                    .select((
                        app_writers::writer,
                        app_writers::user_id,
                        app_writers::device_key,
                        app_writers::frontier,
                        app_writers::head,
                        app_writers::retired_at,
                    ));
                let row: Option<WriterRowTuple> =
                    RunQueryDsl::first(query, &mut *conn).await.optional()?;
                Ok(row.map(
                    |(writer, user_id, device_key, frontier, head, retired_at)| WriterRow {
                        writer,
                        user_id,
                        device_key,
                        frontier,
                        head,
                        retired_at: retired_at.map(From::from),
                    },
                ))
            })
        }

        fn by_key<'c>(
            conn: &'c mut AsyncPgConnection,
            device_key: &'c [u8],
        ) -> Statement<'c, Option<WriterRow<Self::Id>>> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = app_writers::table
                    .filter(app_writers::device_key.eq(device_key.to_vec()))
                    .select((
                        app_writers::writer,
                        app_writers::user_id,
                        app_writers::device_key,
                        app_writers::frontier,
                        app_writers::head,
                        app_writers::retired_at,
                    ));
                let row: Option<WriterRowTuple> =
                    RunQueryDsl::first(query, &mut *conn).await.optional()?;
                Ok(row.map(
                    |(writer, user_id, device_key, frontier, head, retired_at)| WriterRow {
                        writer,
                        user_id,
                        device_key,
                        frontier,
                        head,
                        retired_at: retired_at.map(From::from),
                    },
                ))
            })
        }

        fn insert_key<'c>(
            conn: &'c mut AsyncPgConnection,
            user_id: Option<Self::Id>,
            device_key: &'c [u8],
        ) -> Statement<'c, Option<(i64, i64)>> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, OptionalExtension};
                use diesel_async::RunQueryDsl as _;
                let row: Option<(i64, i64)> = diesel::insert_into(app_writers::table)
                    .values((
                        app_writers::user_id.eq(user_id),
                        app_writers::device_key.eq(device_key.to_vec()),
                        app_writers::frontier.eq(0),
                    ))
                    .on_conflict(app_writers::device_key)
                    .do_nothing()
                    .returning((app_writers::writer, app_writers::frontier))
                    .get_result(&mut *conn)
                    .await
                    .optional()?;
                Ok(row)
            })
        }

        fn insert_retired_key<'c>(
            conn: &'c mut AsyncPgConnection,
            user_id: Option<Self::Id>,
            device_key: &'c [u8],
        ) -> Statement<'c, Option<i64>> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, OptionalExtension};
                use diesel_async::RunQueryDsl as _;
                let at =
                    connetto_server::authn::schema::Instant::from(std::time::SystemTime::now());
                let row: Option<i64> = diesel::insert_into(app_writers::table)
                    .values((
                        app_writers::user_id.eq(user_id),
                        app_writers::device_key.eq(device_key.to_vec()),
                        app_writers::frontier.eq(0),
                        app_writers::retired_at.eq(at),
                    ))
                    .on_conflict(app_writers::device_key)
                    .do_nothing()
                    .returning(app_writers::writer)
                    .get_result(&mut *conn)
                    .await
                    .optional()?;
                Ok(row)
            })
        }

        fn mark_retired<'c>(
            conn: &'c mut AsyncPgConnection,
            writer: i64,
            device_key: Option<&'c [u8]>,
        ) -> Statement<'c, bool> {
            Box::pin(async move {
                use diesel::{
                    ExpressionMethods, NullableExpressionMethods, PgExpressionMethods, QueryDsl,
                };
                use diesel_async::RunQueryDsl;
                let at =
                    connetto_server::authn::schema::Instant::from(std::time::SystemTime::now());
                let key: Option<Vec<u8>> = device_key.map(<[u8]>::to_vec);
                let query = diesel::update(
                    app_writers::table
                        .filter(app_writers::writer.eq(writer))
                        .filter(app_writers::retired_at.is_null())
                        .filter(app_writers::device_key.nullable().is_not_distinct_from(key)),
                )
                .set(app_writers::retired_at.eq(at));
                let affected = RunQueryDsl::execute(query, &mut *conn).await?;
                Ok(affected == 1)
            })
        }

        fn settled(
            conn: &mut AsyncPgConnection,
            writer: i64,
            seq: i64,
        ) -> Statement<'_, Option<SettledRow>> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, OptionalExtension, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = app_settled::table
                    .filter(app_settled::writer.eq(writer))
                    .filter(app_settled::seq.eq(seq))
                    .select((
                        app_settled::entry_hash,
                        app_settled::previous_hash,
                        app_settled::outcome,
                        app_settled::path,
                    ));
                let row: Option<(Vec<u8>, Vec<u8>, String, SettlePath)> =
                    RunQueryDsl::first(query, &mut *conn).await.optional()?;
                Ok(
                    row.map(|(entry_hash, previous_hash, outcome, path)| SettledRow {
                        entry_hash,
                        previous_hash,
                        outcome: outcome.into_bytes(),
                        path,
                    }),
                )
            })
        }

        fn settle<'c>(
            conn: &'c mut AsyncPgConnection,
            writer: i64,
            seq: i64,
            entry_hash: &'c [u8],
            previous_hash: &'c [u8],
            outcome: &'c str,
            path: SettlePath,
        ) -> Statement<'c, bool> {
            Box::pin(async move {
                use diesel::ExpressionMethods as _;
                use diesel_async::RunQueryDsl as _;
                let affected = diesel::insert_into(app_settled::table)
                    .values((
                        app_settled::writer.eq(writer),
                        app_settled::seq.eq(seq),
                        app_settled::entry_hash.eq(entry_hash.to_vec()),
                        app_settled::previous_hash.eq(previous_hash.to_vec()),
                        app_settled::outcome.eq(outcome.to_owned()),
                        app_settled::path.eq(path),
                    ))
                    .on_conflict((app_settled::writer, app_settled::seq))
                    .do_nothing()
                    .execute(&mut *conn)
                    .await?;
                Ok(affected == 1)
            })
        }

        fn advance<'c>(
            conn: &'c mut AsyncPgConnection,
            writer: i64,
            seq: i64,
            head: &'c [u8],
        ) -> Statement<'c, bool> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = diesel::update(
                    app_writers::table
                        .filter(app_writers::writer.eq(writer))
                        .filter(app_writers::frontier.eq(seq - 1)),
                )
                .set((
                    app_writers::frontier.eq(seq),
                    app_writers::head.eq(head.to_vec()),
                ));
                let affected = RunQueryDsl::execute(query, &mut *conn).await?;
                Ok(affected == 1)
            })
        }

        fn settle_outcome<'c>(
            conn: &'c mut AsyncPgConnection,
            writer: i64,
            seq: i64,
            outcome: &'c str,
        ) -> Statement<'c, bool> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = diesel::update(
                    app_settled::table
                        .filter(app_settled::writer.eq(writer))
                        .filter(app_settled::seq.eq(seq)),
                )
                .set(app_settled::outcome.eq(outcome.to_owned()));
                let affected = RunQueryDsl::execute(query, &mut *conn).await?;
                Ok(affected == 1)
            })
        }

        fn prune(conn: &mut AsyncPgConnection, writer: i64, seq: i64) -> Statement<'_, i64> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = diesel::delete(
                    app_settled::table
                        .filter(app_settled::writer.eq(writer))
                        .filter(app_settled::seq.le(seq)),
                );
                let removed = RunQueryDsl::execute(query, &mut *conn).await?;
                Ok(i64::try_from(removed).unwrap_or(i64::MAX))
            })
        }

        fn prune_all(conn: &mut AsyncPgConnection, writer: i64) -> Statement<'_, i64> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query =
                    diesel::delete(app_settled::table.filter(app_settled::writer.eq(writer)));
                let removed = RunQueryDsl::execute(query, &mut *conn).await?;
                Ok(i64::try_from(removed).unwrap_or(i64::MAX))
            })
        }

        fn device_writers(
            conn: &mut AsyncPgConnection,
        ) -> Statement<'_, Vec<(i64, Option<Vec<u8>>)>> {
            Box::pin(async move {
                use diesel::{ExpressionMethods, QueryDsl};
                use diesel_async::RunQueryDsl;
                let query = app_writers::table
                    .filter(app_writers::device_key.is_not_null())
                    .select((app_writers::writer, app_writers::device_key));
                RunQueryDsl::load(query, &mut *conn).await
            })
        }
    }

    pub struct AppSchema;

    impl ConnettoSchema for AppSchema {
        type Id = uuid::Uuid;
        type Auth = ConnettoAuthSchema;
        type Writers = AppWriters;
        type Audit = ConnettoAudit;
        type Bans = ConnettoBans;
        type Enrolments = ConnettoEnrolments;
        type Bots = ConnettoBots;
        type Files = connetto_file_server::DefaultFileSchema;
    }
}

/// A fixed namespace for the deployment's `(issuer, subject)` to `Uuid` map.
const NS: uuid::Uuid = uuid::Uuid::from_u128(0x7c1e_0a52_93d4_4b8f_a6e1_5d2c_0f9b_3e47);

/// The deployment's resolver, a deterministic `Uuid` per verified identity.
struct UuidResolver;

impl IdentityResolver for UuidResolver {
    type Id = uuid::Uuid;

    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, uuid::Uuid> {
        let id = uuid::Uuid::new_v5(
            &NS,
            format!("{}|{}", claims.issuer, claims.subject).as_bytes(),
        );
        Box::pin(async move { Ok(id) })
    }
}

/// Recreate the bot registry tables over the deployment's `UUID` ids, with
/// what a deployment's migration gives them, the cap rules, the reader grant
/// and the publication.
async fn recreate_registry_over_uuid(pool: &Pool<AsyncPgConnection>) {
    for statement in app::BOTS_DDL.split(';') {
        if !statement.trim().is_empty() {
            exec(pool, statement).await;
        }
    }
    let registry_cap = connetto_schema::cap_policies::<connetto_core::bots::UuidIds>("", "")
        .expect("the registry's own cap document");
    connetto_test_harness::exec(pool, &registry_cap).await;
    let registry = connetto_core::bots::REGISTRY_TABLES.join(", ");
    exec(pool, &format!("GRANT SELECT ON {registry} TO PUBLIC")).await;
    for table in connetto_core::bots::REGISTRY_TABLES {
        exec(pool, &format!("ALTER TABLE {table} REPLICA IDENTITY FULL")).await;
    }
    exec(
        pool,
        &format!(
            "ALTER PUBLICATION {} ADD TABLE {registry}",
            connetto_test_harness::PUBLICATION
        ),
    )
    .await;
}

#[tokio::test]
async fn a_deployment_schema_of_its_own_serves_through_the_builder() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    for stmt in [
        "DROP TABLE _connetto_settled",
        "DROP TABLE _connetto_writers",
        "CREATE TABLE app_writers (\
         writer BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY, \
         user_id UUID, session_id UUID, device_key BYTEA UNIQUE, \
         frontier BIGINT NOT NULL DEFAULT 0, head BYTEA, retired_at TIMESTAMPTZ)",
        "CREATE TABLE app_settled (\
         writer BIGINT NOT NULL, seq BIGINT NOT NULL, entry_hash BYTEA NOT NULL, \
         previous_hash BYTEA NOT NULL, \
         outcome TEXT NOT NULL, path connetto_settle_path NOT NULL, \
         settled_at TIMESTAMPTZ NOT NULL DEFAULT now(), \
         PRIMARY KEY (writer, seq))",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON app_writers, app_settled TO app_reader",
        "CREATE TABLE connetto_sessions (\
         session_id UUID PRIMARY KEY, user_id UUID NOT NULL, \
         current_refresh_hash BYTEA NOT NULL, idle_deadline TIMESTAMPTZ NOT NULL, \
         absolute_deadline TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
        "CREATE TABLE connetto_provider_tokens (\
         session_id UUID PRIMARY KEY REFERENCES connetto_sessions (session_id) ON DELETE CASCADE, \
         issuer TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT, \
         expires_at TIMESTAMPTZ)",
        "DROP TABLE connetto_installation_optional_tables",
        "DROP TABLE connetto_installations",
        "DROP TABLE connetto_bot_lists",
        "DROP TABLE connetto_registration_codes",
        "DROP TABLE connetto_bots",
    ] {
        exec(&pool, stmt).await;
    }
    recreate_registry_over_uuid(&pool).await;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let parts = builder
        .deployment_schema::<app::AppSchema>(Arc::new(UuidResolver))
        .build()
        .await
        .expect("the deployment's own schema assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (token, user_id, _refresh) = mint_tokens(&base, "uuid-user").await;
    let user_id: uuid::Uuid = user_id.parse().expect("the login answers a uuid user id");
    let stored: uuid::Uuid = app::connetto_sessions::table
        .select(app::connetto_sessions::user_id)
        .first(&mut pool.get().await.expect("a connection"))
        .await
        .expect("the login stored its session");
    assert_eq!(
        stored, user_id,
        "the session row carries the resolver's uuid"
    );

    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;
    let changeset = insert_changeset(
        "orders",
        &["id", "price", "quantity", "status"],
        &[0],
        vec![
            RowValue::Integer(1000),
            RowValue::Real(1.0),
            RowValue::Integer(1),
            RowValue::Text("own".to_owned()),
        ],
    );
    client
        .send_control(ControlMessage::MutationHeader(MutationHeader::new(1, 1)))
        .await
        .expect("send the mutation header");
    client
        .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(
            1,
            zstd::encode_all(changeset.as_slice(), 3).expect("compress"),
        )))
        .await
        .expect("send the mutation patch");
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(_) => {}
        other => panic!("the write answered {other:?}"),
    }
    let frontier: i64 = app::app_writers::table
        .select(app::app_writers::frontier)
        .first(&mut pool.get().await.expect("a connection"))
        .await
        .expect("the write advanced the deployment's own writer frontier");
    assert_eq!(frontier, 1);

    stream.abort();
    http.abort();
}
