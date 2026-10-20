//! R91: the bot list through a running server.
//!
//! For an unlisted table and for a listed table with no declared read verb the
//! snapshot is empty, a mutation is refused by `may_write` and never lands, a
//! live change is not delivered, and the deployment's `connetto_visible_files`
//! hides a file referenced only from that table. A person's session on the
//! same tables is unaffected.
//!
//! Login is R99's, so the harness binds the bot's session settings directly
//! through its own grant form.
//!
//! Needs Docker, because the fixture starts its own Postgres and its own
//! `OpenFGA`.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    CONTENT_TICKET_REFUSED, ContentVerb, ControlMessage, MutationRejectReason,
};
use connetto_server::openfga::{Counted, FgaAuth, ModelSubject, StoreUpkeep, Translated};
use connetto_server::{PgSnapshotSource, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, PUBLICATION, RowValue, Server, ServerConfig, drop_slot, insert_changeset,
    pool_for, provision_cap_policies, snapshot_rows, spawn_server, with_user,
};
use diesel::prelude::*;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;
use openfga_client::client::OpenFgaServiceClient;
use rls2fga::translator::Translator;
use subql::backend::Postgres;
use subql::visibility::openfga::OpenFgaPolicy;

use super::ticket_shared::{OkSigner, do_handshake_with, request_ticket};

/// The one synced table a bot's list may name, and the second one only a
/// person's wildcard reaches.
const PG_DDL: &str = "-- connetto:major 1\nCREATE TABLE t (id INT PRIMARY KEY, file_id \
     BYTEA, label TEXT);CREATE TABLE u (id INT PRIMARY KEY, label TEXT);";
/// The deployment carries no policy at all, so the cap is the only rule a
/// person's wildcard is held to, and nothing at all.
const NO_POLICIES: &str = "";
/// The non-superuser role the snapshot, the write, and the visibility check
/// run as, under the cap.
const READER: &str = "bp_reader";
/// The file id row 1 of `t` references, the one the cap must hide.
const FILE_ID: [u8; 32] = [0xAB; 32];
/// How long a frame that must arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);
/// How long to wait before concluding nothing is delivered. Silence is the
/// assertion, so it has to outlast the change stream, not the scheduler.
const QUIET: Duration = Duration::from_secs(5);

diesel::table! {
    t (id) {
        id -> Integer,
        file_id -> Nullable<Bytea>,
        label -> Nullable<Text>,
    }
}

/// One insert into `t` as the wire carries it.
fn insert_t(id: i32) -> Vec<u8> {
    insert_changeset(
        "t",
        &["id", "file_id", "label"],
        &[0],
        vec![
            RowValue::Integer(i64::from(id)),
            RowValue::Null,
            RowValue::Text("from the client".to_owned()),
        ],
    )
}

/// Whether `t` holds `id`, read back through the typed table under a list
/// that names the read, so the cap lets the check itself through.
async fn row_exists(pool: &Pool<AsyncPgConnection>, id: i32) -> bool {
    let mut conn = pool.get().await.expect("a reader connection");
    diesel::sql_query("SELECT set_config('app.bot_list', 't:read', false)")
        .execute(&mut *conn)
        .await
        .expect("bind the read-back list");
    let n: i64 = t::table
        .filter(t::id.eq(id))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("the count runs");
    diesel::sql_query("SELECT set_config('app.bot_list', '', false)")
        .execute(&mut *conn)
        .await
        .expect("clear the read-back list");
    n == 1
}

/// Translate the fixture's empty deployment plus its cap, put the rules on the
/// service, and compose the executor the shipped binary composes.
async fn shipped_executor(
    fixture: &Fixture,
    pool: Pool<AsyncPgConnection>,
) -> (
    connetto_test_harness::HarnessFga,
    Arc<dyn StoreUpkeep>,
    Translator,
) {
    let (channel, store) = fixture.fga_store().await;
    let translated = Translated::of::<String, connetto_core::bots::TextIds>(
        PG_DDL,
        NO_POLICIES,
        connetto_core::auth::DEFAULT_USER_SETTING,
    )
    .expect("the fixture's policies are one rls2fga classifies");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the service accepted the rules");
    let loader = OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        translated.shapes_arc(),
        setup,
        store.clone(),
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    translated
        .load_into(fixture.admin(), &loader)
        .await
        .expect("the generated queries ran and the facts loaded");
    let naming = translated.naming();
    let (shapes, translator, reach) = translated.into_parts();
    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let fga = FgaAuth::new(Arc::clone(&shapes), delegate, naming);
    let upkeep = fga.upkeep(reach, translator.clone(), pool);
    (fga, upkeep, translator)
}

/// The one stack every proof drives: the two tables under the cap, the reader
/// role, the seed rows, the shipped executor, and the server answering through
/// it.
async fn stack(fixture: &Fixture) -> (Server, Pool<AsyncPgConnection>) {
    use std::fmt::Write as _;
    let mut file_id = String::with_capacity(FILE_ID.len() * 2);
    for byte in &FILE_ID {
        write!(file_id, "{byte:02x}").expect("writing to a String cannot fail");
    }
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS t CASCADE",
            "DROP TABLE IF EXISTS u CASCADE",
            "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
            PG_DDL,
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bp_reader') \
             THEN CREATE ROLE bp_reader LOGIN PASSWORD 'bp_reader'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO bp_reader",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bp_reader",
            "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) \
             RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ \
             SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f \
             WHERE EXISTS (SELECT 1 FROM public.t p WHERE p.file_id = f)) $$",
            "GRANT EXECUTE ON FUNCTION connetto_visible_files(BYTEA[]) TO bp_reader",
            &format!(
                "INSERT INTO t (id, file_id, label) VALUES \
             (1, '\\x{file_id}'::bytea, 'one'), (2, NULL, 'two')"
            ),
            "INSERT INTO u (id, label) VALUES (1, 'u-one')",
        ])
        .await;
    provision_cap_policies(fixture.admin(), PG_DDL, NO_POLICIES).await;
    let reader = pool_for(&with_user(fixture.admin_url(), READER, READER)).await;
    let engine_ddl = connetto_schema::with_registry::<connetto_core::bots::TextIds>(PG_DDL);
    let (fga, upkeep, translator) = shipped_executor(fixture, reader.clone()).await;
    let auth = HarnessAuth::fga(fga, upkeep);
    let snapshot = PgSnapshotSource::from_ddl(reader.clone(), &engine_ddl)
        .expect("snapshot source")
        .with_publication(PUBLICATION);
    let config = ServerConfig::new(engine_ddl.clone(), fixture.admin_url())
        .with_writable(RuntimeWritableCatalog::builder().writable("t").build())
        .with_translation(translator, None)
        .with_content_signer(OkSigner)
        .with_replication(["t", "u"]);
    let server = spawn_server(config, snapshot, auth, reader.clone(), reader.clone()).await;
    (server, reader)
}

/// For an unlisted table and for a listed table with no declared read verb the
/// snapshot is empty, a mutation is refused by `may_write` and never lands, a
/// live change is not delivered, and `connetto_visible_files` hides a file
/// referenced only from the unlisted table. A person's session on the same
/// tables is unaffected.
#[tokio::test]
async fn the_bot_is_held_to_its_list_and_the_person_passes() {
    let fixture = Fixture::acquire().await;
    let (server, reader) = stack(&fixture).await;

    let mut bot_unlisted = server.connect();
    bot_unlisted
        .handshake_with("bot-a", "bot:bot-a#u:read")
        .await;
    let mut bot_write_only = server.connect();
    bot_write_only
        .handshake_with("bot-b", "bot:bot-b#t:insert")
        .await;
    let mut person = server.connect();
    person.handshake_with("alice", "user:alice").await;

    // The snapshot: empty for both bots' read of `t`, full for the person,
    // and the table the list does name reaches bot-a.
    bot_unlisted.subscribe("a-t", "SELECT * FROM t").await;
    assert_eq!(
        snapshot_rows(&bot_unlisted.expect_snapshot("a-t").await),
        0,
        "an unlisted table snapshots empty"
    );
    bot_write_only.subscribe("b-t", "SELECT * FROM t").await;
    assert_eq!(
        snapshot_rows(&bot_write_only.expect_snapshot("b-t").await),
        0,
        "a listed table with no read verb snapshots empty"
    );
    person.subscribe("p-t", "SELECT * FROM t").await;
    assert_eq!(
        snapshot_rows(&person.expect_snapshot("p-t").await),
        2,
        "the person's session on the same table is unaffected"
    );
    bot_unlisted.subscribe("a-u", "SELECT * FROM u").await;
    assert_eq!(
        snapshot_rows(&bot_unlisted.expect_snapshot("a-u").await),
        1,
        "the table the list does name snapshots"
    );

    // The mutation: refused by `may_write` for the bot the table is not in,
    // and the declared insert verb applies for the one whose list names it.
    bot_unlisted.upload(1, insert_t(10)).await;
    let ControlMessage::MutationReject(reject) = bot_unlisted.next_control().await else {
        panic!("the unlisted table refuses the write");
    };
    assert_eq!(
        reject.reason,
        MutationRejectReason::Unauthorized,
        "the refusal is the authorization one"
    );
    assert!(
        !row_exists(&reader, 10).await,
        "the refused write never applied"
    );

    bot_write_only.upload(1, insert_t(11)).await;
    let ControlMessage::MutationApplied(ack) = bot_write_only.next_control().await else {
        panic!("the declared insert verb applies");
    };
    assert_eq!(ack.client_seq, 1);
    assert!(row_exists(&reader, 11).await, "the declared verb applied");

    // The live change: delivered to the person, to neither bot.
    {
        let mut conn = reader.get().await.expect("a writer connection");
        diesel::sql_query("SELECT set_config('app.bot_list', 't:insert', false)")
            .execute(&mut *conn)
            .await
            .expect("bind the writer list");
        diesel::sql_query("INSERT INTO t (id, file_id, label) VALUES (20, NULL, 'live')")
            .execute(&mut *conn)
            .await
            .expect("the live row lands");
        diesel::sql_query("SELECT set_config('app.bot_list', '', false)")
            .execute(&mut *conn)
            .await
            .expect("clear the writer list");
    }
    person.wait_for_live(DELIVERY).await;
    assert!(
        bot_write_only.try_live(QUIET).await.is_none(),
        "no read verb, no delivery"
    );
    assert!(
        bot_unlisted.try_live(QUIET).await.is_none(),
        "unlisted, no delivery"
    );

    // The file: hidden from the bot, minted for the person.
    let mut bot_conn = server.attach();
    do_handshake_with(&mut bot_conn, "bot-a", &["bot:bot-a#u:read"]).await;
    let msg = request_ticket(&mut bot_conn, "hidden", FILE_ID, ContentVerb::Read).await;
    let ControlMessage::NonFatalError(err) = msg else {
        panic!("a file referenced only from the unlisted table is hidden, got {msg:?}");
    };
    assert_eq!(err.detail, CONTENT_TICKET_REFUSED);

    let mut person_conn = server.attach();
    do_handshake_with(&mut person_conn, "alice", &["user:alice"]).await;
    let msg = request_ticket(&mut person_conn, "visible", FILE_ID, ContentVerb::Read).await;
    let ControlMessage::ContentTicketGrant(grant) = msg else {
        panic!("the person sees the file, got {msg:?}");
    };
    assert_ne!(grant.url, "", "the person sees the file");

    drop(bot_unlisted);
    drop(bot_write_only);
    drop(person);
    drop(bot_conn);
    drop(person_conn);
    drop(server);
    drop_slot(fixture.admin()).await;
}
