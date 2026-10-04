//! Needs Docker: the fixture starts its own Postgres.
//!
//! A deployment that names its own watermark table and types its user id as a
//! `uuid::Uuid` serves through the builder (R98 proof 3). The default
//! `_connetto_mutations` table is absent, so a write that lands proves the
//! server reads and writes through the deployment's member.

use std::sync::Arc;

use connetto_core::messages::{BulkMessage, ControlMessage, MutationHeader, MutationPatch};
use connetto_core::traits::Transport;
use connetto_server::{IdentityResolver, ResolveFuture, VerifiedClaims};
use connetto_test_harness::{Fixture, RowValue, insert_changeset, isolated_session_keyring};
use diesel::QueryDsl;
use diesel_async::RunQueryDsl as _;
use tokio::net::TcpListener;

use super::e2e::{PG_SERIAL, exec, mint_tokens, reset_fixture};
use super::lifecycle::{admin_pool, builder_over, live_session, next_control, wait_ready};

/// The deployment's schema, every default member over a `Uuid` id but the
/// watermark, which lives in a table of its own.
mod app {
    use connetto_server::SessionId;
    use connetto_server::schema::ConnettoSchema;
    use connetto_server::watermark_schema::{ConnettoWatermarkSchema, greatest};
    use diesel::ExpressionMethods as _;

    connetto_server::connetto_schema! {
        pub struct UuidDefaults;
        id: uuid::Uuid => diesel::sql_types::Uuid,
        audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
    }

    diesel::table! {
        app_write_marks (session_id) {
            session_id -> Uuid,
            last_seq -> BigInt,
        }
    }

    #[derive(diesel::Insertable)]
    #[diesel(table_name = app_write_marks)]
    pub struct NewWriteMark {
        session_id: SessionId,
        last_seq: i64,
    }

    pub struct AppWatermark;

    impl ConnettoWatermarkSchema for AppWatermark {
        type Id = uuid::Uuid;
        const TABLES: &'static [&'static str] = &["app_write_marks"];
        type WatermarkQuery = app_write_marks::table;
        type LastSeq = app_write_marks::last_seq;
        type WmPk = diesel::dsl::Eq<app_write_marks::session_id, SessionId>;
        type Upsert = diesel::helper_types::Set<
            diesel::helper_types::DoUpdate<
                diesel::helper_types::OnConflict<
                    diesel::query_builder::InsertStatement<
                        app_write_marks::table,
                        <NewWriteMark as diesel::Insertable<app_write_marks::table>>::Values,
                    >,
                    app_write_marks::session_id,
                >,
            >,
            diesel::dsl::Eq<
                app_write_marks::last_seq,
                greatest<
                    app_write_marks::last_seq,
                    <i64 as diesel::expression::AsExpression<diesel::sql_types::BigInt>>::Expression,
                >,
            >,
        >;

        fn watermark_upsert(session_id: SessionId, last_seq: i64) -> Self::Upsert {
            diesel::insert_into(app_write_marks::table)
                .values(NewWriteMark {
                    session_id,
                    last_seq,
                })
                .on_conflict(app_write_marks::session_id)
                .do_update()
                .set(app_write_marks::last_seq.eq(greatest(app_write_marks::last_seq, last_seq)))
        }

        fn wm_pk(session_id: SessionId) -> Self::WmPk {
            app_write_marks::session_id.eq(session_id)
        }
    }

    pub struct AppSchema;

    impl ConnettoSchema for AppSchema {
        type Id = uuid::Uuid;
        type Auth = ConnettoAuthSchema;
        type Watermark = AppWatermark;
        type Audit = ConnettoAudit;
        type Bans = ConnettoBans;
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

#[tokio::test]
async fn a_deployment_schema_of_its_own_serves_through_the_builder() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    for stmt in [
        "DROP TABLE _connetto_mutations",
        "CREATE TABLE app_write_marks (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)",
        "GRANT SELECT, INSERT, UPDATE ON app_write_marks TO app_reader",
        "CREATE TABLE connetto_sessions (\
         session_id UUID PRIMARY KEY, user_id UUID NOT NULL, \
         current_refresh_hash BYTEA NOT NULL, idle_deadline TIMESTAMPTZ NOT NULL, \
         absolute_deadline TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
        "CREATE TABLE connetto_provider_tokens (\
         session_id UUID PRIMARY KEY REFERENCES connetto_sessions (session_id) ON DELETE CASCADE, \
         issuer TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT, \
         expires_at TIMESTAMPTZ)",
    ] {
        exec(&pool, stmt).await;
    }

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
    let marked: i64 = app::app_write_marks::table
        .select(app::app_write_marks::last_seq)
        .first(&mut pool.get().await.expect("a connection"))
        .await
        .expect("the write advanced the deployment's own watermark");
    assert_eq!(marked, 1);

    stream.abort();
    http.abort();
}
