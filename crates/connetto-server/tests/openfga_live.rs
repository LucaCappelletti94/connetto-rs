//! The change-path executor against a real authorization service.
//!
//! Everything else about R5b is proven structurally: that the schema settles
//! connetto's own policy shape, that a cross-table policy is not settled, that
//! an untranslated policy refuses startup. **This is the one that proves the
//! answers are right**, end to end from policy text to a verdict, through a
//! server that was told nothing except what connetto derived and loaded.
//!
//! Two claims it defends that nothing else can:
//!
//! 1. **The verdict is correct.** A row's owner may see it and a stranger may
//!    not, decided by the composition rather than by Postgres.
//! 2. **It costs no round trip.** `AUTHORIZATION_CALLS` counts calls through the
//!    transport, so a policy the changed row settles locally must leave it
//!    exactly where it started. This is the criterion the counter test asserts
//!    at scale, checked here at the smallest size where it means anything.
//!
//! And it defends the boot rule: a rule description already on the service is
//! adopted rather than rewritten, which is what keeps a restart from reloading
//! every fact in the database.
//!
//! Run with a Postgres and an `OpenFGA` server:
//!
//! ```text
//! docker run -d --rm --name r5b-pg -e POSTGRES_PASSWORD=postgres -p 55480:5432 \
//!     postgres:16 -c wal_level=logical
//! docker run -d --rm --name r5b-fga -p 55481:8081 openfga/openfga:v1.8.13 run
//! DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55480/postgres \
//! CONNETTO_TEST_FGA_URL=http://127.0.0.1:55481 \
//!     cargo +stable test --release -p connetto-server --test openfga_live -- --ignored
//! ```

use std::sync::Arc;

use connetto_core::SessionId;
use connetto_core::auth::{AuthContext, Principal, Subject, VerifiedSession};
use connetto_server::counters;
use connetto_server::openfga::{
    Counted, FgaAuth, ModelState, ModelSubject, SubjectNaming, Translated,
};
use connetto_server::row_view::ValuesRow;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use openfga_client::client::{CreateStoreRequest, OpenFgaServiceClient};
use openfga_client::tonic::transport::Channel;
use pg_walstream::{ChangeEvent, ColumnValue, Lsn, ReplicaIdentity, RowData};
use subql::backend::{Postgres, Value};
use subql::catalog_helpers;
use subql::visibility::openfga::OpenFgaPolicy;
use subql::visibility::{RowWrite, Verdict, VisibilityPolicy};

/// The schema clients sync.
const SCHEMA: &str = "CREATE TABLE r5b_notes (id INT PRIMARY KEY, owner TEXT NOT NULL);";

/// The policy shape every connetto table carries: the caller's identity, or a
/// key the caller holds.
///
/// One statement per entry, because a prepared statement carries one and the
/// translator reads them joined.
const POLICY_STATEMENTS: [&str; 2] = [
    "ALTER TABLE r5b_notes ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY r5b_notes_p ON r5b_notes FOR ALL USING (\
       owner = current_setting('app.user_id', true) \
       OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
];

/// The same, as the one document the translator is handed.
fn policies() -> String {
    POLICY_STATEMENTS.join(";\n") + ";"
}

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

fn service_url() -> String {
    std::env::var("CONNETTO_TEST_FGA_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_owned())
}

async fn pool() -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url());
    Pool::builder()
        .max_size(4)
        .build(manager)
        .await
        .expect("a Postgres pool")
}

/// Provision the table and its rows, dropping whatever a previous run left.
async fn provision(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("a connection");
    let mut statements = vec!["DROP TABLE IF EXISTS r5b_notes CASCADE", SCHEMA];
    statements.extend(POLICY_STATEMENTS);
    statements.push("INSERT INTO r5b_notes (id, owner) VALUES (1, 'alice'), (2, 'bob')");
    for statement in statements {
        diesel::sql_query(statement)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|err| panic!("provisioning `{statement}`: {err}"));
    }
}

/// A caller with one identity and no share keys.
fn caller(user: &str) -> Arc<Principal> {
    let mut principal = Principal::unidentified(SessionId::from_uuid(uuid::Uuid::new_v4()));
    principal
        .accept(Subject::Identity(VerifiedSession {
            context: AuthContext::new(user),
            session_id: SessionId::from_uuid(uuid::Uuid::new_v4()),
        }))
        .expect("one identity");
    Arc::new(principal)
}

async fn connect() -> (Channel, String) {
    let endpoint = service_url();
    let channel = Channel::from_shared(endpoint.clone())
        .expect("a service endpoint")
        .connect()
        .await
        .unwrap_or_else(|err| panic!("connecting to {endpoint}: {err}"));
    let store = OpenFgaServiceClient::new(channel.clone())
        .create_store(CreateStoreRequest {
            name: format!("connetto-r5b-{}", uuid::Uuid::new_v4()),
        })
        .await
        .expect("create a store")
        .into_inner()
        .id;
    (channel, store)
}

/// One row as the change stream carries it, every column present, which is what
/// `REPLICA IDENTITY FULL` gives an update.
fn row_data(columns: &[(&str, &str)]) -> RowData {
    let mut row = RowData::with_capacity(columns.len());
    for (name, value) in columns {
        row.push(Arc::from(*name), ColumnValue::text(value));
    }
    row
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres and OpenFGA (Docker); run after explicit approval"]
async fn the_row_settles_the_verdict_and_it_costs_no_round_trip() {
    let pool = pool().await;
    provision(&pool).await;
    let (channel, store) = connect().await;

    let translated = Translated::of::<String>(SCHEMA, &policies(), "app.user_id")
        .expect("connetto's own policy shape translates");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the service accepted the rules");
    assert!(
        matches!(model, ModelState::Written(_)),
        "a fresh store holds no rules, so they are written rather than adopted"
    );

    let records = translated
        .load_records(&pool)
        .await
        .expect("the generated queries ran and their rows spell facts");
    assert!(
        !records.is_empty(),
        "two owned rows must produce at least the facts naming their owners"
    );

    let shapes = translated.shapes();
    let naming = Arc::new(SubjectNaming::resolve::<String>(&shapes));
    OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        Arc::clone(&shapes),
        setup,
        store.clone(),
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned())
    .write_records(&records)
    .await
    .expect("the facts loaded");

    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);

    let notes = catalog_helpers::table_id(shapes.catalog(), "r5b_notes").expect("in the catalog");
    let row = [Value::Int(1), Value::String("alice".to_owned())];
    let view = ValuesRow::new(notes, &row);
    let watchers = [caller("alice"), caller("bob")];
    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, watchers.len());

    // Bracketing the question, not the setup: the model write and the fact load
    // above go through the uncounted client on purpose, so this reads the
    // change path alone.
    let before = counters::snapshot().authorization_calls;
    auth.may_see(&view, &watchers, &mut verdicts)
        .await
        .expect("the composition answered");
    let after = counters::snapshot().authorization_calls;

    assert_eq!(
        verdicts,
        [Verdict::Allow, Verdict::Deny],
        "alice owns the row and bob does not"
    );
    assert_eq!(
        after, before,
        "connetto's own policy shape is settled by the changed row, so the \
         service must not have been asked at all. This is the criterion the \
         counter test asserts at ten and a hundred watchers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres and OpenFGA (Docker); run after explicit approval"]
async fn unchanged_rules_are_adopted_rather_than_rewritten() {
    let pool = pool().await;
    provision(&pool).await;
    let (channel, store) = connect().await;
    let mut client = OpenFgaServiceClient::new(channel);

    let first = Translated::of::<String>(SCHEMA, &policies(), "app.user_id")
        .expect("translates")
        .install_model(&mut client, &store)
        .await
        .expect("written");
    let second = Translated::of::<String>(SCHEMA, &policies(), "app.user_id")
        .expect("translates")
        .install_model(&mut client, &store)
        .await
        .expect("adopted");

    assert!(matches!(first, ModelState::Written(_)));
    assert_eq!(
        second,
        ModelState::Adopted(first.id().to_owned()),
        "the same policy text produces the same rules, and a restart that \
         rewrote them would reload every fact in the database behind them"
    );
}

/// A table Postgres shows to nobody, which the model has to refuse rather than
/// fail to answer.
///
/// **This assertion used to be vacuous and that hid a real defect.** It
/// discarded the result and then asserted the verdicts were still `Deny`, which
/// is the value [`Verdict::reset`] had just written, so it passed whether the
/// composition refused or could not answer at all. Under a fail-closed caller
/// those are opposite outcomes: a refusal delivers to nobody, and no answer
/// holds the event and retries forever. The call is now required to succeed,
/// and the refusal is required to cost nothing, because nobody is granted and
/// so no watcher is worth asking about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres and OpenFGA (Docker); run after explicit approval"]
async fn a_table_with_row_level_security_and_no_policy_grants_nobody() {
    let pool = pool().await;
    provision(&pool).await;
    let (channel, store) = connect().await;

    let policies = "ALTER TABLE r5b_notes ENABLE ROW LEVEL SECURITY;";
    let translated =
        Translated::of::<String>(SCHEMA, policies, "app.user_id").expect("nothing to translate");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the rules are written");

    let shapes = translated.shapes();
    let naming = Arc::new(SubjectNaming::resolve::<String>(&shapes));
    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);

    let notes = catalog_helpers::table_id(shapes.catalog(), "r5b_notes").expect("in the catalog");
    let row = [Value::Int(1), Value::String("alice".to_owned())];
    let view = ValuesRow::new(notes, &row);
    let watchers = [caller("alice")];
    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, watchers.len());

    // Postgres with row level security on and no policy shows the row to
    // nobody, the model renders that as no access, and an allow would be the
    // two executors disagreeing in the one direction that leaks.
    let before = counters::snapshot().authorization_calls;
    auth.may_see(&view, &watchers, &mut verdicts)
        .await
        .expect("a refusal is an answer, so the composition must reach one");
    assert_eq!(
        verdicts,
        [Verdict::Deny],
        "row level security with no policy grants nobody, and the model must \
         say the same"
    );
    assert_eq!(
        counters::snapshot().authorization_calls,
        before,
        "the model refuses every statement here, so there is nobody to ask about"
    );
}

/// **The store has to follow the change stream, and this is the test that
/// fails when it does not.**
///
/// Everything else here proves the boot is right. A boot that is right and a
/// store that then stands still is the failure the upkeep exists to remove:
/// the row's owner changes, the service still holds the old owner, and the old
/// owner is handed a row whose access has already gone. No later correction
/// takes that row back.
///
/// **This failed when it was written, and the cause was upstream.** `apply`
/// sent a difference's additions and removals in one write, and an owner change
/// moves a conditional tuple whose key is identical on both sides, which the
/// server refuses. Fixed in subql `33ee3f8`, which sends the two in separate
/// calls with the removals first, so between them the row reaches nobody rather
/// than everybody. This is the assertion that fix has to keep satisfying.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres and OpenFGA (Docker); run after explicit approval"]
async fn a_changed_owner_reaches_the_store_before_the_row_is_delivered() {
    let pool = pool().await;
    provision(&pool).await;
    let (channel, store) = connect().await;

    let translated = Translated::of::<String>(SCHEMA, &policies(), "app.user_id")
        .expect("connetto's own policy shape translates");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the rules are written");
    let records = translated
        .load_records(&pool)
        .await
        .expect("the facts load");

    let (shapes, _translator, reach) = translated.into_parts();
    let naming = Arc::new(SubjectNaming::resolve::<String>(&shapes));
    let loader = OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        Arc::clone(&shapes),
        setup,
        store.clone(),
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    loader
        .write_records(&records)
        .await
        .expect("the facts load");

    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);
    let upkeep = auth.upkeep(reach);

    // Row 1 moves from alice to carol. This is the event the change stream
    // would carry, with both images, which is what `REPLICA IDENTITY FULL`
    // gives an update.
    let notes = catalog_helpers::table_id(shapes.catalog(), "r5b_notes").expect("in the catalog");
    let after: [Value<Postgres>; 2] = [Value::Int(1), Value::String("carol".to_owned())];
    let event = ChangeEvent::update(
        "public",
        "r5b_notes",
        0,
        Some(row_data(&[("id", "1"), ("owner", "alice")])),
        row_data(&[("id", "1"), ("owner", "carol")]),
        ReplicaIdentity::Full,
        vec![Arc::from("id")],
        Lsn::new(1),
    );

    upkeep
        .keep_current(&event)
        .await
        .expect("the difference reached the store");

    let view = ValuesRow::new(notes, &after);
    let watchers = [caller("alice"), caller("carol")];
    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, watchers.len());
    auth.may_see(&view, &watchers, &mut verdicts)
        .await
        .expect("the composition answered");

    assert_eq!(
        verdicts,
        [Verdict::Deny, Verdict::Allow],
        "alice no longer owns the row and carol does, and the store must say so \
         before the row is delivered rather than after"
    );
}

/// The schema behind the promise measurement: a grant is a membership row, so
/// withdrawing one produces no event on the guarded table at all.
///
/// One statement per entry, because a prepared statement carries one and the
/// translator reads them joined.
const CROSS_SCHEMA_STATEMENTS: [&str; 3] = [
    "CREATE TABLE r7_teams (id INT PRIMARY KEY)",
    "CREATE TABLE r7_members (team_id INT REFERENCES r7_teams(id), member TEXT NOT NULL, \
       PRIMARY KEY (team_id, member))",
    "CREATE TABLE r7_docs (id INT PRIMARY KEY, team_id INT NOT NULL REFERENCES r7_teams(id))",
];

/// The schema as the one document the translator is handed.
fn cross_schema() -> String {
    CROSS_SCHEMA_STATEMENTS.join(";\n") + ";"
}

/// `FOR ALL`, so one policy gates the read and the write and both questions are
/// about the same grant.
const CROSS_POLICY_STATEMENTS: [&str; 2] = [
    "ALTER TABLE r7_docs ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY r7_docs_p ON r7_docs FOR ALL USING (\
       EXISTS (SELECT 1 FROM r7_members \
               WHERE r7_members.team_id = r7_docs.team_id \
                 AND r7_members.member = current_setting('app.user_id', true)))",
];

/// Provision the cross-table fixture, dropping whatever a previous run left.
async fn provision_cross(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("a connection");
    let mut statements = vec!["DROP TABLE IF EXISTS r7_docs, r7_members, r7_teams CASCADE"];
    statements.extend(CROSS_SCHEMA_STATEMENTS);
    statements.extend(CROSS_POLICY_STATEMENTS);
    statements.push("INSERT INTO r7_teams (id) VALUES (1)");
    statements.push("INSERT INTO r7_members (team_id, member) VALUES (1, 'alice')");
    statements.push("INSERT INTO r7_docs (id, team_id) VALUES (1, 1)");
    for statement in statements {
        diesel::sql_query(statement)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|err| panic!("provisioning `{statement}`: {err}"));
    }
}

/// Translate the cross-table policy, put it and its facts on a fresh store, and
/// compose the executor plus the upkeep that keeps it current.
async fn cross_executor(
    pool: &Pool<AsyncPgConnection>,
) -> (
    FgaAuth<String, String, Counted<Channel>>,
    Arc<dyn connetto_server::openfga::StoreUpkeep>,
    Arc<subql::visibility::shapes::Shapes<subql::ParserDB>>,
) {
    let (channel, store) = connect().await;
    let schema = cross_schema();
    let translated =
        Translated::of::<String>(&schema, &CROSS_POLICY_STATEMENTS.join(";\n"), "app.user_id")
            .expect("a membership policy translates");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the rules are written");
    let records = translated.load_records(pool).await.expect("the facts load");

    let (shapes, _translator, reach) = translated.into_parts();
    let naming = Arc::new(SubjectNaming::resolve::<String>(&shapes));
    OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        Arc::clone(&shapes),
        setup,
        store.clone(),
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned())
    .write_records(&records)
    .await
    .expect("the facts load");

    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);
    let upkeep = auth.upkeep(reach);
    (auth, upkeep, shapes)
}

/// **The promise, measured rather than asserted (R7 decision 3).**
///
/// `08-authorization.md` promises that an authorization change takes effect
/// immediately for writes and within the read cache lifetime for reads. This
/// takes both questions the instant the withdrawal is in the store, with no
/// wait anywhere, and both must refuse.
///
/// **The read clause has slack today and this records why.** Reads take
/// `ConsistencyPreference::MinimizeLatency`, so the promise names a ceiling, but
/// the service ships with all three caches disabled, and the bound below is far
/// under the 10 second lifetime a cache would get if one were enabled. Turning
/// `OPENFGA_CHECK_QUERY_CACHE_ENABLED` on is what would make the clause bite,
/// and is what this measurement would then catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres and OpenFGA (Docker); run after explicit approval"]
async fn a_withdrawn_grant_is_refused_at_once_for_both_questions() {
    let pool = pool().await;
    provision_cross(&pool).await;
    let (auth, upkeep, shapes) = cross_executor(&pool).await;
    let docs = catalog_helpers::table_id(shapes.catalog(), "r7_docs").expect("in the catalog");
    let row: [Value<Postgres>; 2] = [Value::Int(1), Value::Int(1)];
    let view = ValuesRow::new(docs, &row);
    let alice = [caller("alice")];

    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, 1);
    auth.may_see(&view, &alice, &mut verdicts)
        .await
        .expect("the composition answered");
    assert_eq!(
        verdicts,
        [Verdict::Allow],
        "a member of the document's team may see it, which is what makes the \
         refusal below mean anything"
    );
    assert!(
        auth.may_write(
            RowWrite::Update {
                old: &view,
                new: &view
            },
            &alice[0]
        )
        .await
        .expect("the composition answered")
        .allowed(),
        "and may write it"
    );

    // The withdrawal, as the change stream carries it.
    let event = ChangeEvent::delete(
        "public",
        "r7_members",
        0,
        row_data(&[("team_id", "1"), ("member", "alice")]),
        ReplicaIdentity::Full,
        vec![Arc::from("team_id"), Arc::from("member")],
        Lsn::new(2),
    );
    upkeep
        .keep_current(&event)
        .await
        .expect("the withdrawal reached the store");

    // No wait of any kind between the store write and the two questions: that
    // absence is the measurement.
    let taken = std::time::Instant::now();
    Verdict::reset(&mut verdicts, 1);
    auth.may_see(&view, &alice, &mut verdicts)
        .await
        .expect("the composition answered");
    let read_after = taken.elapsed();
    assert_eq!(
        verdicts,
        [Verdict::Deny],
        "the read question must reflect the withdrawal with no wait, which the \
         shipped settings make immediate because no cache is enabled"
    );
    let write_taken = std::time::Instant::now();
    assert!(
        !auth
            .may_write(
                RowWrite::Update {
                    old: &view,
                    new: &view
                },
                &alice[0]
            )
            .await
            .expect("the composition answered")
            .allowed(),
        "the write question uses the strict preference, so it must refuse at once"
    );
    let write_after = write_taken.elapsed();
    println!("read refused after {read_after:?}, write refused after {write_after:?}");
    assert!(
        read_after < std::time::Duration::from_secs(2)
            && write_after < std::time::Duration::from_secs(2),
        "both refusals must land far inside the 10 second lifetime a cache would \
         get, or the promise's read clause is no longer slack: read {read_after:?}, \
         write {write_after:?}"
    );
}
