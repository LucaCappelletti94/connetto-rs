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
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::SessionId;
use connetto_core::auth::{AuthContext, Principal, Subject, VerifiedSession};
use connetto_server::counters;
use connetto_server::openfga::{
    Counted, FgaAuth, ModelState, ModelSubject, SubjectNaming, Translated, UpkeepError,
};
use connetto_server::row_view::ValuesRow;
use connetto_test_harness::Fixture;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use openfga_client::client::OpenFgaServiceClient;
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
async fn the_row_settles_the_verdict_and_it_costs_no_round_trip() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision(&pool).await;
    let (channel, store) = fixture.fga_store().await;

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
async fn unchanged_rules_are_adopted_rather_than_rewritten() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision(&pool).await;
    let (channel, store) = fixture.fga_store().await;
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
async fn a_table_with_row_level_security_and_no_policy_grants_nobody() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision(&pool).await;
    let (channel, store) = fixture.fga_store().await;

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
async fn a_changed_owner_reaches_the_store_before_the_row_is_delivered() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision(&pool).await;
    let (channel, store) = fixture.fga_store().await;

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

    let (shapes, translator, reach) = translated.into_parts();
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
    let upkeep = auth.upkeep(reach, translator, pool.clone());

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
    fixture: &Fixture,
    pool: &Pool<AsyncPgConnection>,
) -> (
    FgaAuth<String, String, Counted<Channel>>,
    Arc<dyn connetto_server::openfga::StoreUpkeep>,
    Arc<subql::visibility::shapes::Shapes<subql::ParserDB>>,
) {
    let (channel, store) = fixture.fga_store().await;
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

    let (shapes, translator, reach) = translated.into_parts();
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
    let upkeep = auth.upkeep(reach, translator, pool.clone());
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
async fn a_withdrawn_grant_is_refused_at_once_for_both_questions() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision_cross(&pool).await;
    let (auth, upkeep, shapes) = cross_executor(&fixture, &pool).await;
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

/// A UUID-keyed table shaped like the demo's `orders`, so a client uploads its
/// primary key as a sixteen-byte blob rather than a typed value.
const ORDERS_SCHEMA: &str = "CREATE TABLE r40_orders (id UUID PRIMARY KEY, owner TEXT NOT NULL);";

/// The same owner policy `r5b_notes` carries, on the UUID-keyed table.
const ORDERS_POLICY_STATEMENTS: [&str; 2] = [
    "ALTER TABLE r40_orders ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY r40_orders_p ON r40_orders FOR ALL USING (\
       owner = current_setting('app.user_id', true) \
       OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
];

fn orders_policies() -> String {
    ORDERS_POLICY_STATEMENTS.join(";\n") + ";"
}

/// Provision the UUID-keyed table with one owned row, dropping a prior run's.
async fn provision_orders(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("a connection");
    let mut statements = vec!["DROP TABLE IF EXISTS r40_orders CASCADE", ORDERS_SCHEMA];
    statements.extend(ORDERS_POLICY_STATEMENTS);
    statements.push(
        "INSERT INTO r40_orders (id, owner) VALUES \
         ('11111111-1111-1111-1111-111111111111', 'alice')",
    );
    for statement in statements {
        diesel::sql_query(statement)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|err| panic!("provisioning `{statement}`: {err}"));
    }
}

/// R40 regression: a `UUID` primary key an upload carries as a sixteen-byte
/// blob must name the row the same way the catalog-typed read path does, or the
/// owner grant is never found and an owned write is refused.
///
/// The demo's `orders` has exactly this shape, and this drives the same
/// `FgaAuth::may_write` path a mutation upload takes. It asks the identical
/// owned insert twice, differing only in the key's spelling: once as the
/// `Value::Uuid` the type-directed codec now produces, once as the
/// `Value::Bytes` it produced before. The authorization seam cannot spell
/// bytes (`render_text` returns `None`), so the row could not be named and the
/// write was refused. An allow for the typed key and a refusal for the bytes is
/// the divergence the fix removes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_uuid_primary_key_is_named_so_an_owned_write_is_authorized() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision_orders(&pool).await;
    let (channel, store) = fixture.fga_store().await;

    let translated = Translated::of::<String>(ORDERS_SCHEMA, &orders_policies(), "app.user_id")
        .expect("connetto's own policy shape translates");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the rules are written");
    let records = translated
        .load_records(&pool)
        .await
        .expect("the generated queries ran and their rows spell facts");

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
    .expect("the facts load");

    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);

    let orders = catalog_helpers::table_id(shapes.catalog(), "r40_orders").expect("in the catalog");
    let id = uuid::Uuid::from_u128(0xab4a_f609_f3d2_5ebd_b482_fbe8_b7db_00c6);
    let alice = caller("alice");

    // The key as the type-directed codec produces it: the row names itself
    // `r40_orders:ab4af609-...` and alice owns it, so the write is allowed.
    let typed: [Value<Postgres>; 2] = [Value::Uuid(id), Value::String("alice".to_owned())];
    let typed_view = ValuesRow::new(orders, &typed);
    assert!(
        auth.may_write(RowWrite::Insert { new: &typed_view }, &alice)
            .await
            .expect("the composition answered")
            .allowed(),
        "alice inserting a row she owns, keyed by a UUID, must be allowed"
    );

    // The same UUID as the untyped codec produced it: raw bytes, which cannot
    // be spelled, so the row cannot be named and the owned write is refused. An
    // allow here would be the regression this test guards.
    let untyped: [Value<Postgres>; 2] = [
        Value::Bytes(id.as_bytes().to_vec()),
        Value::String("alice".to_owned()),
    ];
    let untyped_view = ValuesRow::new(orders, &untyped);
    let refused = auth
        .may_write(RowWrite::Insert { new: &untyped_view }, &alice)
        .await;
    assert!(
        !matches!(&refused, Ok(verdict) if verdict.allowed()),
        "a blob-shaped UUID key cannot be named, so the same owned write must \
         not be allowed: {refused:?}"
    );
}

// ---------------------------------------------------------------------------
// R86: a share whose facts travel as a query to re-run
// ---------------------------------------------------------------------------

/// A share that no single row settles, so its facts travel as a query the
/// change path re-runs.
///
/// The residual is what makes it so: whether a share grants depends on a value
/// only the database can compute, so rls2fga hands over a query keyed on the
/// paper rather than records read off the row.
const REPLAY_SCHEMA_STATEMENTS: [&str; 3] = [
    "CREATE TABLE r86_papers (id INT PRIMARY KEY, owner TEXT NOT NULL)",
    "CREATE TABLE r86_shares (paper_id INT NOT NULL, viewer TEXT NOT NULL, \
       weight INT NOT NULL, PRIMARY KEY (paper_id, viewer))",
    "ALTER TABLE r86_papers ENABLE ROW LEVEL SECURITY",
];

const REPLAY_POLICY: &str = "CREATE POLICY r86_papers_p ON r86_papers FOR ALL USING (\
    EXISTS (SELECT 1 FROM r86_shares s WHERE s.paper_id = r86_papers.id \
      AND s.viewer = current_setting('app.user_id', true) \
      AND s.weight > (SELECT avg(weight) FROM r86_shares)))";

/// Provision the replay fixture, dropping whatever a previous run left.
async fn provision_replay(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("a connection");
    let mut statements = vec!["DROP TABLE IF EXISTS r86_papers, r86_shares CASCADE"];
    statements.extend(REPLAY_SCHEMA_STATEMENTS);
    statements.push(REPLAY_POLICY);
    statements.push("INSERT INTO r86_papers (id, owner) VALUES (1, 'zoe')");
    // alice is above the average and carol is below it, so one share grants and
    // the other does not, which is what the residual decides.
    statements.push(
        "INSERT INTO r86_shares (paper_id, viewer, weight) VALUES \
         (1, 'alice', 10), (1, 'carol', 1)",
    );
    for statement in statements {
        diesel::sql_query(statement)
            .execute(&mut conn)
            .await
            .unwrap_or_else(|err| panic!("{statement}: {err}"));
    }
}

/// Build the executor over the replay fixture, exactly as `cross_executor`
/// does over the membership one.
async fn replay_executor(
    fixture: &Fixture,
    pool: &Pool<AsyncPgConnection>,
) -> (
    FgaAuth<String, String, Counted<Channel>>,
    Arc<dyn connetto_server::openfga::StoreUpkeep>,
    Arc<subql::visibility::shapes::Shapes<subql::ParserDB>>,
) {
    let (channel, store) = fixture.fga_store().await;
    let schema = REPLAY_SCHEMA_STATEMENTS.join(";\n") + ";";
    let translated = Translated::of::<String>(&schema, REPLAY_POLICY, "app.user_id")
        .expect("a share whose replay declares its slice boots since R86");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the rules are written");
    let records = translated.load_records(pool).await.expect("the facts load");

    let (shapes, translator, reach) = translated.into_parts();
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
    let auth: FgaAuth<String, String, _> = FgaAuth::new(Arc::clone(&shapes), delegate, naming);
    let upkeep = auth.upkeep(reach, translator, pool.clone());
    (auth, upkeep, shapes)
}

/// **`R86`: deleting the share withdraws the grant, through the re-run.**
///
/// This shape refused to start until `R86`, because `R49` refused everything
/// whose facts travel as a query, on the grounds that the replay only ever
/// wrote. It writes and deletes now: the replay's rows are handed to the
/// reconcile, which reads back the slice the query declares it determines and
/// removes what the replay no longer states.
///
/// **What it would look like if the reconcile were skipped**, which is exactly
/// `R49`'s measurement: the caller stays allowed after the row is gone, because
/// the store still holds the fact nobody deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_share_is_withdrawn_when_its_row_goes() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision_replay(&pool).await;
    let (auth, upkeep, shapes) = replay_executor(&fixture, &pool).await;

    let papers = catalog_helpers::table_id(shapes.catalog(), "r86_papers").expect("in the catalog");
    let row: [Value<Postgres>; 2] = [Value::Int(1), Value::String("zoe".to_owned())];
    let view = ValuesRow::new(papers, &row);
    let alice = [caller("alice")];
    let carol = [caller("carol")];

    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, 1);
    auth.may_see(&view, &alice, &mut verdicts)
        .await
        .expect("the composition answered");
    assert_eq!(
        verdicts,
        [Verdict::Allow],
        "alice's share is above the average, so she may see the paper, which is          what makes the refusal below mean anything"
    );
    Verdict::reset(&mut verdicts, 1);
    auth.may_see(&view, &carol, &mut verdicts)
        .await
        .expect("the composition answered");
    assert_eq!(
        verdicts,
        [Verdict::Deny],
        "carol's share is below the average, so the residual is what decides and          not the mere existence of a share row"
    );

    // The withdrawal. The database is changed first, because the replay asks it
    // what is true now rather than what the event says.
    {
        let mut conn = pool.get().await.expect("a connection");
        diesel::sql_query("DELETE FROM r86_shares WHERE paper_id = 1 AND viewer = 'alice'")
            .execute(&mut conn)
            .await
            .expect("the share row goes");
    }
    let event = ChangeEvent::delete(
        "public",
        "r86_shares",
        0,
        row_data(&[("paper_id", "1"), ("viewer", "alice"), ("weight", "10")]),
        ReplicaIdentity::Full,
        vec![Arc::from("paper_id"), Arc::from("viewer")],
        Lsn::new(2),
    );
    let moves = upkeep
        .keep_current(&event)
        .await
        .expect("the withdrawal reached the store");

    Verdict::reset(&mut verdicts, 1);
    auth.may_see(&view, &alice, &mut verdicts)
        .await
        .expect("the composition answered");
    assert_eq!(
        verdicts,
        [Verdict::Deny],
        "the share row is gone, so the grant has to be gone from the store too,          which is the whole of R49's finding"
    );
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
        "and the write question refuses on the same fact"
    );
    assert!(
        moves
            .iter()
            .any(|moved| moved.tables.iter().any(|table| table == "r86_papers")),
        "a replayed withdrawal has to tell the subscriptions that read the paper          to replace their rows, since no row event on r86_papers will: {moves:?}"
    );
}

/// **`R86` D2: what an affected change costs, measured rather than assumed.**
///
/// A change to a table under a re-run shape pays a Postgres query and a store
/// read before the event is delivered, where a row-settled shape pays neither.
/// The number belongs in the plan rather than in an expectation, so this prints
/// it and asserts only the shape of the answer: that the re-run costs more than
/// a change to a table no shape replays, and that it stays inside the tenth of
/// a second a delivery can absorb.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_change_costs_more_than_a_settled_one_and_is_measured() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision_replay(&pool).await;
    let (_auth, upkeep, _shapes) = replay_executor(&fixture, &pool).await;

    // A change to the guarded table itself settles from its own row, so it pays
    // no replay. This is the baseline the re-run is measured against.
    let settled = ChangeEvent::update(
        "public",
        "r86_papers",
        0,
        Some(row_data(&[("id", "1"), ("owner", "zoe")])),
        row_data(&[("id", "1"), ("owner", "yolanda")]),
        ReplicaIdentity::Full,
        vec![Arc::from("id")],
        Lsn::new(2),
    );
    let mut settled_total = Duration::ZERO;
    for _ in 0..ROUNDS {
        let taken = std::time::Instant::now();
        upkeep
            .keep_current(&settled)
            .await
            .expect("the store keeps up");
        settled_total += taken.elapsed();
    }

    // A change to the share table replays the query and reconciles the slice.
    let replayed = ChangeEvent::update(
        "public",
        "r86_shares",
        0,
        Some(row_data(&[
            ("paper_id", "1"),
            ("viewer", "carol"),
            ("weight", "1"),
        ])),
        row_data(&[("paper_id", "1"), ("viewer", "carol"), ("weight", "2")]),
        ReplicaIdentity::Full,
        vec![Arc::from("paper_id"), Arc::from("viewer")],
        Lsn::new(3),
    );
    let mut replayed_total = Duration::ZERO;
    for _ in 0..ROUNDS {
        let taken = std::time::Instant::now();
        upkeep
            .keep_current(&replayed)
            .await
            .expect("the store keeps up");
        replayed_total += taken.elapsed();
    }

    let settled_each = settled_total / ROUNDS;
    let replayed_each = replayed_total / ROUNDS;
    println!(
        "R86 D2 measurement: settled change {settled_each:?} each, replayed change \
         {replayed_each:?} each, over {ROUNDS} rounds"
    );
    assert!(
        replayed_each > settled_each,
        "the replay reads the database and the store, so it cannot be free: \
         settled {settled_each:?}, replayed {replayed_each:?}"
    );
    // Generously bounded on purpose, the way the refusal measurement above is.
    // The number is the deliverable and it lives in the plan. An assertion
    // tight enough to be interesting here would fail on a loaded CI runner and
    // teach nobody anything.
    assert!(
        replayed_each < Duration::from_secs(1),
        "a change under a re-run shape holds up its own delivery, so a whole \
         second means the path is broken rather than merely slow: {replayed_each:?}"
    );
}

/// Rounds each arm of the measurement above runs, enough to average out one
/// slow container response without making the suite wait.
const ROUNDS: u32 = 20;

/// **A replay that cannot run holds the event rather than delivering it.**
///
/// `R86` gave the change path a second way to fail: besides the store being
/// unreachable, the replay itself runs a query against the database, which can
/// fail or time out. The rest of the chain is already proven in `auth_retry`,
/// where an `Err` from this seam becomes `SessionError::AuthUnavailable`, holds
/// the cursor, and broadcasts `DeliveryPaused`. What is proven here is the
/// entry to that chain: a replay that cannot run reports it instead of quietly
/// leaving the store stale and letting the row through.
///
/// The failure is staged by taking the share table away, which is what a
/// dropped table or a revoked grant looks like from the replay's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_that_cannot_run_refuses_rather_than_letting_the_row_through() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    provision_replay(&pool).await;
    let (_auth, upkeep, _shapes) = replay_executor(&fixture, &pool).await;

    {
        let mut conn = pool.get().await.expect("a connection");
        diesel::sql_query("DROP TABLE r86_shares CASCADE")
            .execute(&mut conn)
            .await
            .expect("the share table goes");
    }

    let event = ChangeEvent::delete(
        "public",
        "r86_shares",
        0,
        row_data(&[("paper_id", "1"), ("viewer", "alice"), ("weight", "10")]),
        ReplicaIdentity::Full,
        vec![Arc::from("paper_id"), Arc::from("viewer")],
        Lsn::new(2),
    );
    let refused = upkeep
        .keep_current(&event)
        .await
        .expect_err("a replay that cannot run must not report success");
    assert!(
        matches!(refused, UpkeepError::Replay(_)),
        "the cause has to name the replay, or an operator reads it as the store \
         being down and waits for a service that is fine: {refused:?}"
    );
}
