//! R91: the person's app side of the bot registry, end to end over the wire.
//!
//! A registration code the client mints locally and pushes lands on the
//! server through the person's cap rules, and the bot registering with it
//! settles against the registry, the bot row, the list row and the spent
//! code proven against the database. The add's connetto rows and the app's
//! membership row land whole on the server under a rule that admits them,
//! and under a rule that does not the whole change is refused at apply and
//! leaves no installation row on the server or the replica.
//!
//! The refusal test's client bundle carries no membership rule, because a
//! bundle translated the usual way would refuse the row in the replica's own
//! policy trigger before it uploads. The rule lives only in the fixture, so
//! the refusal is the server's, the way the add transaction takes it.
//!
//! Needs Docker, because the fixture starts its own Postgres.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use connetto_client::bots::{Install, create_registration_code, install};
use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoConnection, Grant, HeldCredential, SyncSchema,
};
use connetto_core::messages::{
    BotListEntry, Challenge, ControlMessage, RegisterBot, bot_registration_message,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::bots::pg_bot_registry;
use connetto_server::defaults::ConnettoDefaults;
use connetto_server::{
    LoopbackTransport, ManagerBuilder, Materializer, PgReadConnector, PgSnapshotSource,
    RuntimeWritableCatalog, SessionConfig, SessionManager, loopback, pg_write_target,
};
use connetto_test_harness::{Fixture, RosterAuth, pool_for, with_user};
use diesel::prelude::*;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use uuid::Uuid;

diesel::table! {
    membership (installation) {
        /// The installation the membership belongs to.
        installation -> Text,
        /// The member the installation serves.
        member -> Text,
    }
}

connetto_client::connetto_bot_tables!(String, diesel::sql_types::Text);
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>;

/// The deployment's Postgres tables, beside the registry tables connetto
/// appends.
const DEPLOYMENT_DDL: &str = "-- connetto:major 1\nCREATE TABLE orders (id INT PRIMARY KEY, \
    label TEXT); CREATE TABLE membership (installation TEXT PRIMARY KEY, member TEXT NOT NULL);";

/// The deployment's rule on its membership table: the writer administers the
/// row's owner.
const MEMBERSHIP_POLICY: &str = "\
ALTER TABLE membership ENABLE ROW LEVEL SECURITY; \
CREATE POLICY membership_admin ON membership \
USING (member = current_setting('app.user_id', true)) \
WITH CHECK (member = current_setting('app.user_id', true));";

static SERVER_DDL: LazyLock<String> =
    LazyLock::new(|| format!("{DEPLOYMENT_DDL}{}", connetto_server::defaults::BOTS_DDL));

/// The tables whose rows the write target must be able to touch as the
/// writer role.
const TABLES: [&str; 7] = [
    "orders",
    "membership",
    "connetto_bots",
    "connetto_registration_codes",
    "connetto_bot_lists",
    "connetto_installations",
    "connetto_installation_optional_tables",
];

/// Split one DDL document into its statements, dropping the empties a
/// trailing `;` leaves behind.
fn statements(document: &str) -> Vec<String> {
    document
        .split(';')
        .filter(|statement| !statement.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// The fixture over the deployment's tables and the registry, with the
/// app's `app_writer` role the write target runs under and the rules that
/// gate it.
/// Returns the admin pool and the writer pool.
async fn setup(fixture: &Fixture) -> (Pool<AsyncPgConnection>, Pool<AsyncPgConnection>) {
    let cap = connetto_schema::cap_policies::<connetto_core::bots::TextIds>(
        DEPLOYMENT_DDL,
        MEMBERSHIP_POLICY,
    )
    .expect("the cap rules generate");
    let mut out: Vec<String> = Vec::new();
    out.push(
        "DROP TABLE IF EXISTS connetto_installation_optional_tables, \
         connetto_installations, connetto_bot_lists, connetto_registration_codes, \
         connetto_bots, orders, membership CASCADE"
            .to_owned(),
    );
    out.push(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
         THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$"
            .to_owned(),
    );
    out.extend(statements(DEPLOYMENT_DDL));
    out.extend(statements(connetto_server::defaults::BOTS_DDL));
    out.extend(statements(MEMBERSHIP_POLICY));
    out.extend(statements(&cap));
    out.push("GRANT USAGE ON SCHEMA public TO app_writer".to_owned());
    for table in TABLES {
        out.push(format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_writer"
        ));
    }
    out.push(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON _connetto_writers, _connetto_settled TO app_writer"
            .to_owned(),
    );
    let refs: Vec<&str> = out.iter().map(String::as_str).collect();
    fixture.setup(&refs).await;
    (
        fixture.admin().clone(),
        pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await,
    )
}

/// A manager over the fixture's pools with the bot registry wired over the
/// admin pool, the way the reference server wires it.
fn manager(
    read: Pool<AsyncPgConnection>,
    write: Pool<AsyncPgConnection>,
    registry: Pool<AsyncPgConnection>,
) -> Arc<Manager> {
    ManagerBuilder::new(
        Materializer::builder(&SERVER_DDL)
            .with_write_catalog(
                RuntimeWritableCatalog::builder()
                    .writable("membership")
                    .build(),
            )
            .with_read_connector(PgReadConnector::with_session_setup(read.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(read.clone(), &SERVER_DDL).expect("snapshot source"),
        RosterAuth::granting("alice"),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(read),
        pg_write_target::<ConnettoDefaults>(write, &SERVER_DDL).expect("build write target"),
    )
    .with_session(SessionConfig::new())
    .with_bot_registry(pg_bot_registry::<ConnettoDefaults>(registry))
    .build()
}

/// The translated bundle the client's replica opens from, the deployment's
/// tables and rule with the registry and the cap connetto appends.
fn bundle() -> SyncSchema {
    SyncSchema::new(
        connetto_schema::translate::<String, connetto_core::bots::TextIds>(
            DEPLOYMENT_DDL,
            MEMBERSHIP_POLICY,
        )
        .expect("translate the sources"),
    )
}

/// The bundle the refusal test's client opens, without the membership rule,
/// so the row uploads and the fixture's rule is the one that refuses it.
fn bundle_without_membership_rule() -> SyncSchema {
    SyncSchema::new(
        connetto_schema::translate::<String, connetto_core::bots::TextIds>(DEPLOYMENT_DDL, "")
            .expect("translate the sources"),
    )
}

/// The refusal a one-shot dialer hands back after it has handed out its
/// transport.
#[derive(Debug, thiserror::Error)]
#[error("the dialer handed out its last transport")]
enum DialRefused {
    /// No transport is left.
    Exhausted,
}

/// The in-process client signed in as alice, over one of the manager's
/// loopback ends.
async fn client(
    manager: &Arc<Manager>,
    schema: SyncSchema,
) -> ConnettoConnection<LoopbackTransport> {
    let (server_end, client_end) = loopback();
    let serving = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let mut held = Some(client_end);
    let dial = move || std::future::ready(held.take().ok_or(DialRefused::Exhausted));
    let credential =
        HeldCredential::new(Grant::new("user:alice"), "alice").expect("the credential holds");
    let mut client = ClientBuilder::new(schema, dial)
        .signed_in(credential)
        .connect_driven()
        .await
        .expect("the client connects");
    // Subscribe and apply the initial snapshot, so the session is fully up
    // before the test's first write uploads.
    client
        .subscribe("orders", "SELECT * FROM orders")
        .await
        .expect("subscribe");
    pump_until(&mut client, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    client
}

/// Drive the client until its pump reports an event matching `pred`, applying
/// every frame in between.
async fn pump_until(
    client: &mut ConnettoConnection<LoopbackTransport>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, client.pump_one())
            .await
            .expect("the client pump timed out")
            .expect("the client pump failed");
        assert_ne!(event, ClientEvent::Closed, "the connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

/// One loopback bot with its serving task, the opening challenge read back.
async fn bot(manager: &Arc<Manager>) -> (LoopbackTransport, Challenge) {
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    (client, challenge)
}

/// Read the next control frame. The exchange's frames are all control, so a
/// bulk frame or a closed connection is a test failure.
async fn next_control(client: &mut LoopbackTransport) -> ControlMessage {
    let Some(IncomingFrame::Control(control)) = client.recv().await.expect("recv") else {
        panic!("expected a control frame, the connection closed");
    };
    control
}

/// A fresh Ed25519 key pair, through the PKCS#8 round trip an app would use.
fn mint_key() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
    Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parse the key pair")
}

/// The one registration the tests present over `code`, signed by `key` for
/// the connection's nonce.
fn registration(code: &str, key: &Ed25519KeyPair, nonce: &[u8; 32]) -> RegisterBot {
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(key.public_key().as_ref());
    RegisterBot {
        code: code.to_owned(),
        name: "bot-a".to_owned(),
        public_key,
        list: vec![BotListEntry {
            table: "orders".to_owned(),
            verb: "read".to_owned(),
            optional: false,
        }],
        signature: key.sign(&bot_registration_message(nonce)).as_ref().to_vec(),
    }
}

/// The code row the server holds, read through the registry's typed table.
async fn code_row(pool: &Pool<AsyncPgConnection>, hash: &[u8; 32]) {
    let mut conn = pool.get().await.expect("a connection");
    let (stored, creator, bot): (Vec<u8>, String, Option<uuid::Uuid>) =
        connetto_server::defaults::connetto_registration_codes::table
            .filter(
                connetto_server::defaults::connetto_registration_codes::code_hash.eq(hash.to_vec()),
            )
            .select((
                connetto_server::defaults::connetto_registration_codes::code_hash,
                connetto_server::defaults::connetto_registration_codes::creator,
                connetto_server::defaults::connetto_registration_codes::bot,
            ))
            .first(&mut *conn)
            .await
            .expect("the code row loads");
    assert_eq!(
        stored,
        hash.to_vec(),
        "the row is keyed by the code's SHA-256"
    );
    assert_eq!(creator, "alice", "the creator is the signed-in person");
    assert!(bot.is_none(), "a first registration names no bot");
}

/// Whether the code the server holds is spent.
async fn code_spent(pool: &Pool<AsyncPgConnection>, hash: [u8; 32]) -> bool {
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
    used_at.is_some()
}

/// The bot's owner and key on the server, read through the registry's typed
/// table.
async fn bot_row(pool: &Pool<AsyncPgConnection>, bot: Uuid) -> (String, Vec<u8>) {
    let mut conn = pool.get().await.expect("a connection");
    connetto_server::defaults::connetto_bots::table
        .filter(connetto_server::defaults::connetto_bots::id.eq(bot))
        .select((
            connetto_server::defaults::connetto_bots::owner,
            connetto_server::defaults::connetto_bots::public_key,
        ))
        .first(&mut *conn)
        .await
        .expect("read the bot")
}

/// The table names the server holds for the bot's list version one.
async fn list_tables(pool: &Pool<AsyncPgConnection>, bot: Uuid) -> Vec<String> {
    let mut conn = pool.get().await.expect("a connection");
    connetto_server::defaults::connetto_bot_lists::table
        .filter(connetto_server::defaults::connetto_bot_lists::bot.eq(bot))
        .filter(connetto_server::defaults::connetto_bot_lists::version.eq(1))
        .select(connetto_server::defaults::connetto_bot_lists::table_name)
        .load(&mut *conn)
        .await
        .expect("read the list")
}

/// Seed a registered bot and its list version one on the server, the way a
/// settlement lands, so an installation's foreign key names a real bot.
async fn seed_bot(pool: &Pool<AsyncPgConnection>, bot: Uuid, owner: &str) {
    let mut conn = pool.get().await.expect("a connection");
    diesel::insert_into(connetto_server::defaults::connetto_bots::table)
        .values((
            connetto_server::defaults::connetto_bots::id.eq(bot),
            connetto_server::defaults::connetto_bots::owner.eq(owner),
            connetto_server::defaults::connetto_bots::name.eq("bot-a"),
            connetto_server::defaults::connetto_bots::public_key.eq(vec![0_u8; 32]),
            connetto_server::defaults::connetto_bots::list_version.eq(1),
        ))
        .execute(&mut *conn)
        .await
        .expect("the bot row seeds");
    diesel::insert_into(connetto_server::defaults::connetto_bot_lists::table)
        .values((
            connetto_server::defaults::connetto_bot_lists::bot.eq(bot),
            connetto_server::defaults::connetto_bot_lists::version.eq(1),
            connetto_server::defaults::connetto_bot_lists::table_name.eq("orders"),
            connetto_server::defaults::connetto_bot_lists::verb.eq("read"),
            connetto_server::defaults::connetto_bot_lists::optional.eq(false),
        ))
        .execute(&mut *conn)
        .await
        .expect("the list row seeds");
}

/// The installation ids the server holds.
async fn server_installations(pool: &Pool<AsyncPgConnection>) -> Vec<String> {
    let mut conn = pool.get().await.expect("a connection");
    connetto_server::defaults::connetto_installations::table
        .select(connetto_server::defaults::connetto_installations::id)
        .load(&mut *conn)
        .await
        .expect("read the installations")
}

/// The installation ids the server's membership table holds.
async fn server_membership(pool: &Pool<AsyncPgConnection>) -> Vec<String> {
    let mut conn = pool.get().await.expect("a connection");
    membership::table
        .select(membership::installation)
        .load(&mut *conn)
        .await
        .expect("read the membership rows")
}

/// The optional tables the server holds for one installation.
async fn server_optional_tables(pool: &Pool<AsyncPgConnection>, installation: &str) -> Vec<String> {
    let mut conn = pool.get().await.expect("a connection");
    connetto_server::defaults::connetto_installation_optional_tables::table
        .filter(
            connetto_server::defaults::connetto_installation_optional_tables::installation
                .eq(installation),
        )
        .select(connetto_server::defaults::connetto_installation_optional_tables::table_name)
        .load(&mut *conn)
        .await
        .expect("read the optional tables")
}

/// A code the client mints and pushes registers the bot through the
/// registry, the operator typing it in lowercase without its dashes, and the
/// settlement is proven against the database rows.
#[tokio::test]
async fn a_code_pushed_by_the_client_registers_the_bot() {
    let fixture = Fixture::acquire().await;
    let (admin, writer) = setup(&fixture).await;
    let manager = manager(admin.clone(), writer, admin.clone());
    let mut client = client(&manager, bundle()).await;

    // The code the client mints locally and pushes lands on the server
    // through the person's cap rules.
    let code = create_registration_code::<ConnettoBots, _>(
        client.conn(),
        "alice".to_owned(),
        None,
        Duration::from_secs(3600),
    )
    .expect("the code mints");
    let seq = client
        .push()
        .await
        .expect("the push runs")
        .expect("the code change records");
    let ClientEvent::MutationApplied { client_seq } = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationApplied { .. })
    })
    .await
    else {
        unreachable!("pump_until matched the applied event")
    };
    assert_eq!(client_seq, seq, "the server confirmed the pushed change");
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(&Sha256::digest(
        connetto_core::bots::canonical_code(&code).as_bytes(),
    ));
    code_row(&admin, &raw).await;

    // The bot registers with the code the operator types, lowercase and
    // without its dashes, and it settles against the canonical form.
    let (mut bot_client, challenge) = bot(&manager).await;
    let key = mint_key();
    let typed = code.to_lowercase().replace('-', "");
    bot_client
        .send_control(ControlMessage::RegisterBot(registration(
            &typed,
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    let ControlMessage::BotRegistered(answer) = next_control(&mut bot_client).await else {
        panic!("the registration did not settle");
    };
    let bot_id = Uuid::parse_str(&answer.bot_id).expect("the bot id is a uuid");

    // The settlement is in the database, in the bot row, the list row and
    // the spent code.
    let (owner, public_key) = bot_row(&admin, bot_id).await;
    assert_eq!(owner, "alice", "the code's creator owns the bot");
    assert_eq!(
        public_key,
        key.public_key().as_ref(),
        "the bot registers its key"
    );
    assert_eq!(list_tables(&admin, bot_id).await, vec!["orders".to_owned()]);
    assert!(
        code_spent(&admin, raw).await,
        "the settlement spent the code"
    );
    client.close().await.expect("close the client");
}

/// A code the operator types with a character outside the base32 alphabet
/// reads as a different canonical form, so the settlement is refused like any
/// wrong code and the code stays unspent.
#[tokio::test]
async fn a_code_with_a_character_outside_the_alphabet_is_refused() {
    let fixture = Fixture::acquire().await;
    let (admin, writer) = setup(&fixture).await;
    let manager = manager(admin.clone(), writer, admin.clone());
    let mut client = client(&manager, bundle()).await;
    let code = create_registration_code::<ConnettoBots, _>(
        client.conn(),
        "alice".to_owned(),
        None,
        Duration::from_secs(3600),
    )
    .expect("the code mints");
    let seq = client
        .push()
        .await
        .expect("the push runs")
        .expect("the code change records");
    let ClientEvent::MutationApplied { client_seq } = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationApplied { .. })
    })
    .await
    else {
        unreachable!("pump_until matched the applied event")
    };
    assert_eq!(client_seq, seq, "the server confirmed the pushed change");

    // The operator mistypes a character outside the base32 alphabet, so the
    // canonical form changes and the code lookup misses.
    let (mut bot_client, challenge) = bot(&manager).await;
    let key = mint_key();
    let wrong = format!("0{}", code.replace('-', ""));
    bot_client
        .send_control(ControlMessage::RegisterBot(registration(
            &wrong,
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    let control = next_control(&mut bot_client).await;
    assert!(
        matches!(control, ControlMessage::RegistrationRefused),
        "the mistyped code is refused like a wrong code, got {control:?}"
    );
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(&Sha256::digest(
        connetto_core::bots::canonical_code(&code).as_bytes(),
    ));
    assert!(
        !code_spent(&admin, raw).await,
        "the refusal left the code unspent"
    );
    client.close().await.expect("close the client");
}

/// A person who does not administer the add's owner is refused the whole
/// change at apply, and the refusal leaves no installation row on the server
/// or the replica.
#[tokio::test]
async fn an_install_for_an_unadministered_owner_is_refused_whole() {
    let fixture = Fixture::acquire().await;
    let (admin, writer) = setup(&fixture).await;
    let manager = manager(admin.clone(), writer, admin.clone());
    let mut client = client(&manager, bundle_without_membership_rule()).await;
    let bot = Uuid::new_v4();
    // The bot the installation names is registered on the server, and the
    // replica carries it through the subscription, the way a real add does.
    seed_bot(&admin, bot, "bob").await;
    client
        .subscribe("connetto_bots", "SELECT * FROM connetto_bots")
        .await
        .expect("subscribe to the bots");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::SnapshotEnd { sub_id } if sub_id == "connetto_bots"),
    )
    .await;
    {
        let replica = client.conn();
        replica
            .transaction::<(), ClientError, _>(|tx| {
                install::<ConnettoBots, _>(
                    tx,
                    Install {
                        installation: "inst-1".to_owned(),
                        bot,
                        owner: "bob".to_owned(),
                        accepted_version: 1,
                        optional_tables: vec!["orders".to_owned()],
                    },
                )?;
                let row = diesel::insert_into(membership::table).values((
                    membership::installation.eq("inst-1"),
                    membership::member.eq("bob"),
                ));
                diesel::query_dsl::methods::ExecuteDsl::<SqliteConnection>::execute(row, tx)?;
                Ok(())
            })
            .expect("the local add commits");
    }
    let seq = client
        .push()
        .await
        .expect("the push runs")
        .expect("the add uploads");
    // The fixture's rule on the membership row refuses the whole change.
    let ClientEvent::MutationRejected { client_seq, .. } = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationRejected { .. })
    })
    .await
    else {
        unreachable!("pump_until matched the rejected event")
    };
    assert_eq!(client_seq, seq, "the refusal names the pushed change");
    // The refusal leaves no row on the server, connetto's or the app's.
    assert!(
        server_installations(&admin).await.is_empty(),
        "the server holds no installation"
    );
    assert!(
        server_membership(&admin).await.is_empty(),
        "the server holds no membership row"
    );
    // ... and none survives on the replica, which rolled the add back.
    let replica = client.conn();
    let query = connetto_installations::table.select(connetto_installations::id);
    let installations: Vec<String> =
        diesel::prelude::RunQueryDsl::<SqliteConnection>::load(query, replica)
            .expect("the installations table loads");
    assert!(installations.is_empty(), "the replica rolled the add back");
    let query = membership::table.select(membership::installation);
    let members: Vec<String> =
        diesel::prelude::RunQueryDsl::<SqliteConnection>::load(query, replica)
            .expect("the membership table loads");
    assert!(
        members.is_empty(),
        "the replica rolled the membership row back"
    );
    client.close().await.expect("close the client");
}

/// A person who administers the add's owner lands both rows on the server in
/// the one applied change, and the replica keeps them.
#[tokio::test]
async fn an_install_for_the_administered_owner_lands_whole() {
    let fixture = Fixture::acquire().await;
    let (admin, writer) = setup(&fixture).await;
    let manager = manager(admin.clone(), writer, admin.clone());
    let mut client = client(&manager, bundle()).await;
    let bot = Uuid::new_v4();
    // The bot the installation names is registered on the server, and the
    // replica carries it through the subscription, the way a real add does.
    seed_bot(&admin, bot, "alice").await;
    client
        .subscribe("connetto_bots", "SELECT * FROM connetto_bots")
        .await
        .expect("subscribe to the bots");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::SnapshotEnd { sub_id } if sub_id == "connetto_bots"),
    )
    .await;
    {
        let replica = client.conn();
        replica
            .transaction::<(), ClientError, _>(|tx| {
                install::<ConnettoBots, _>(
                    tx,
                    Install {
                        installation: "inst-1".to_owned(),
                        bot,
                        owner: "alice".to_owned(),
                        accepted_version: 1,
                        optional_tables: vec!["orders".to_owned()],
                    },
                )?;
                let row = diesel::insert_into(membership::table).values((
                    membership::installation.eq("inst-1"),
                    membership::member.eq("alice"),
                ));
                diesel::query_dsl::methods::ExecuteDsl::<SqliteConnection>::execute(row, tx)?;
                Ok(())
            })
            .expect("the add transaction commits");
    }
    let seq = client
        .push()
        .await
        .expect("the push runs")
        .expect("the add uploads");
    let ClientEvent::MutationApplied { client_seq } = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationApplied { .. })
    })
    .await
    else {
        unreachable!("pump_until matched the applied event")
    };
    assert_eq!(client_seq, seq, "the server confirmed the pushed change");
    // Both rows landed on the server, connetto's and the app's.
    let installations = server_installations(&admin).await;
    assert_eq!(
        installations,
        vec!["inst-1".to_owned()],
        "the server holds the installation"
    );
    assert_eq!(
        server_optional_tables(&admin, "inst-1").await,
        vec!["orders".to_owned()],
        "the server holds the accepted optional table"
    );
    assert_eq!(
        server_membership(&admin).await,
        vec!["inst-1".to_owned()],
        "the server holds the app's membership row"
    );
    // The replica keeps the add beside its membership row.
    let replica = client.conn();
    let query = connetto_installations::table.select(connetto_installations::id);
    let kept: Vec<String> = diesel::prelude::RunQueryDsl::<SqliteConnection>::load(query, replica)
        .expect("the installations table loads");
    assert_eq!(kept, vec!["inst-1".to_owned()]);
    client.close().await.expect("close the client");
}
