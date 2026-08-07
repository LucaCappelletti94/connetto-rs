//! Docker-gated proof that a share key grants exactly its relations (R4).
//!
//! A capability is a signed token naming a subject and nothing else. What that
//! subject may do is an ordinary row in the application's own table, gated by
//! an ordinary policy, so the whole phase reduces to one question: does the
//! subject reach Postgres, on both paths, and does the policy then decide?
//!
//! The fixture is deliberately shaped so a policy that accidentally matches
//! everything cannot pass. `papers` holds three rows, `alice` owns one and
//! `bob` owns two, and exactly one of bob's is shared. The negative half is
//! bob's other paper, which no caller in these tests may ever see.
//!
//! Both executors are covered, because they can disagree and the divergence is
//! silent: a snapshot runs one policy-filtered `SELECT`, while the change path
//! asks the visibility policy per row in its own transaction. Binding the
//! subject in one and forgetting the other would show a shared row once and
//! then never update it.
//!
//! `#[ignore]` on everything needing Postgres. Point `DATABASE_URL` at one and
//! run with `--ignored`. A superuser bypasses RLS entirely, so the checks run
//! as `app_reader` and privileged setup runs as the admin role.

#![allow(clippy::too_many_lines)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use connetto_core::SessionId;
use connetto_core::auth::{AuthContext, CapabilitySubject, Principal, Subject, VerifiedSession};
use connetto_server::audit::{AuthEvent, AuthOp};
use connetto_server::{
    AuthConfig, CapabilityIssuer, CapabilityKey, Materializer, PgSnapshotSource, RlsAuth,
    RowSource, ShareError, SnapshotSource, SourceRow, TokenAuthority,
};
use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as AsyncRunQueryDsl};
use sqlparser::dialect::PostgreSqlDialect;
use subql::backend::{Postgres as PgValues, Value};
use subql::testing::TestEvent;
use subql::visibility::{EventRow, Verdict, VisibilityPolicy};
use subql::{ParserDB, catalog_helpers};

/// The catalog both the read filter and the snapshot encoder parse. Table DDL
/// only, so it parses cleanly. The policies are installed separately.
const CATALOG_DDL: &str = "\
CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT, body TEXT);\
CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer));";

const REPLICA_DDL: &str = "CREATE TABLE papers (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);";

diesel::table! {
    /// Row from the papers test fixture.
    papers (id) {
        /// Paper identifier, the primary key.
        id -> Integer,
        /// Person who owns the paper.
        owner -> Text,
        /// Paper content.
        body -> Text,
    }
}

/// The share key the fixture grants over paper 2. Fixed rather than minted so
/// the read assertions do not depend on the minting path.
const SHARED_KEY: &str = "key:shared-with-me";
/// A key the fixture grants nothing to.
const IDLE_KEY: &str = "key:grants-nothing";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

/// Rewrite a Postgres URL's user info, keeping host, port, and database.
fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

/// Create the tables, the rows, the policies and the reader role, then hand
/// back a pool connected as a role that RLS actually applies to.
///
/// The union is one policy: your own rows, plus whatever a share key you hold
/// is granted. `paper_shares` needs its own read policy or the `EXISTS` above
/// finds nothing, and its insert policy is what closes the gap between the
/// resource connetto checked and the row the application writes.
async fn setup() -> Pool<AsyncPgConnection> {
    let admin = pool_for(&admin_url()).await;
    let mut conn = admin.get().await.expect("admin connection");
    let statements = [
        "DROP TABLE IF EXISTS papers, paper_shares CASCADE",
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
        "CREATE TABLE papers (id INT PRIMARY KEY, owner TEXT, body TEXT)",
        "CREATE TABLE paper_shares (paper_id INT, viewer TEXT, PRIMARY KEY (paper_id, viewer))",
        "INSERT INTO papers VALUES (1, 'alice', 'a'), (2, 'bob', 'b'), (3, 'bob', 'c')",
        "ALTER TABLE papers ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE paper_shares ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY papers_p ON papers USING ( \
           owner = current_setting('app.user_id', true) \
           OR EXISTS (SELECT 1 FROM paper_shares s WHERE s.paper_id = papers.id \
                      AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))))",
        "CREATE POLICY shares_read ON paper_shares FOR SELECT USING ( \
           viewer = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
        // You may only grant over a paper you can see. The subquery runs under
        // `papers_p` as the sharer, so a grant naming somebody else's paper
        // finds no row and the insert is refused.
        "CREATE POLICY shares_insert ON paper_shares FOR INSERT WITH CHECK ( \
           EXISTS (SELECT 1 FROM papers p WHERE p.id = paper_id))",
        "CREATE POLICY shares_delete ON paper_shares FOR DELETE USING (true)",
        "GRANT USAGE ON SCHEMA public TO app_reader",
        "GRANT SELECT ON papers TO app_reader",
        "GRANT SELECT, INSERT, DELETE ON paper_shares TO app_reader",
    ];
    for statement in statements {
        AsyncRunQueryDsl::execute(sql_query(statement), &mut *conn)
            .await
            .expect("setup statement");
    }
    grant(&mut conn, 2, SHARED_KEY).await;
    drop(conn);
    pool_for(&with_user(&admin_url(), "app_reader", "app_reader")).await
}

/// Write one permission row as the admin, which is how the application would,
/// on a connection RLS does not apply to.
async fn grant(conn: &mut AsyncPgConnection, paper: i32, viewer: &str) {
    AsyncRunQueryDsl::execute(
        sql_query(format!(
            "INSERT INTO paper_shares VALUES ({paper}, '{viewer}') ON CONFLICT DO NOTHING"
        )),
        conn,
    )
    .await
    .expect("grant");
}

/// A caller with an identity, capabilities, or both, in the shape a handshake
/// would have produced.
fn caller(user: Option<&str>, keys: &[&str]) -> Principal {
    let handle = SessionId::from_token_hash(user.unwrap_or("anonymous"));
    let mut principal = Principal::unidentified(handle);
    if let Some(user) = user {
        principal
            .accept(Subject::Identity(VerifiedSession {
                context: AuthContext::new(user),
                session_id: handle,
            }))
            .expect("one identity");
    }
    for key in keys {
        principal
            .accept(Subject::Capability(CapabilitySubject::new(*key)))
            .expect("a capability always folds in");
    }
    principal
}

/// The fixture's three rows, complete, so the view handed to the policy is the
/// row rather than only its key.
const PAPERS: [(i32, &str, &str); 3] = [(1, "alice", "a"), (2, "bob", "b"), (3, "bob", "c")];

/// Which papers the change path would deliver, asked one row at a time exactly
/// as the fan-out does, through the same row view a replication event carries.
async fn visible_on_change_path(auth: &RlsAuth, caller: &Principal) -> Vec<i32> {
    let catalog = ParserDB::parse::<PostgreSqlDialect>(CATALOG_DDL).expect("the catalog parses");
    let table = catalog_helpers::table_id(&catalog, "papers").expect("papers is in the catalog");
    let watchers = [Arc::new(caller.clone())];
    let mut verdicts = Vec::new();
    let mut seen = Vec::new();
    for (id, owner, body) in PAPERS {
        let event = TestEvent::<PgValues>::insert(
            table,
            vec![
                Value::Int(i64::from(id)),
                Value::String(owner.to_owned()),
                Value::String(body.to_owned()),
            ],
        )
        .with_pk_columns([0u16]);
        let row = EventRow::current(&event, &catalog).expect("an insert carries a post-image");
        Verdict::reset(&mut verdicts, watchers.len());
        auth.may_see(&row, &watchers, &mut verdicts)
            .await
            .expect("the visibility question");
        if matches!(verdicts.as_slice(), [Verdict::Allow, ..]) {
            seen.push(id);
        }
    }
    seen
}

/// Which papers a fresh snapshot delivers, read back off a replica the
/// patchset was applied to, so the assertion is on rows a client would hold.
async fn visible_in_snapshot(source: &PgSnapshotSource, caller: &Principal) -> Vec<i32> {
    let snapshot = source
        .snapshot("SELECT * FROM papers", &[], caller)
        .await
        .expect("snapshot");
    let mut replica = SqliteConnection::establish(":memory:").expect("open replica");
    diesel::RunQueryDsl::execute(sql_query(REPLICA_DDL), &mut replica).expect("replica ddl");
    let compressed = zstd::encode_all(snapshot.patchset.as_slice(), 3).expect("compress");
    Materializer::new(CATALOG_DDL)
        .expect("applier")
        .apply_diffset(&compressed, &mut replica)
        .expect("apply snapshot");
    diesel::RunQueryDsl::load(
        papers::table.order(papers::id).select(papers::id),
        &mut replica,
    )
    .expect("read replica")
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_capability_grants_exactly_its_relations_and_nothing_else() {
    let reader = setup().await;
    let auth = RlsAuth::from_ddl(reader.clone(), CATALOG_DDL).expect("build RlsAuth");
    let source = PgSnapshotSource::from_ddl(reader, CATALOG_DDL).expect("build snapshot source");

    // No identity and no key: the deployment's policy shows a stranger nothing.
    let stranger = caller(None, &[]);
    assert_eq!(
        visible_on_change_path(&auth, &stranger).await,
        Vec::<i32>::new()
    );
    assert_eq!(
        visible_in_snapshot(&source, &stranger).await,
        Vec::<i32>::new()
    );

    // No identity, holding the key: exactly the shared paper. Not paper 1,
    // which belongs to somebody else, and not paper 3, which is the same
    // owner's unshared paper and is what catches a policy matching everything.
    let bearer = caller(None, &[SHARED_KEY]);
    assert_eq!(visible_on_change_path(&auth, &bearer).await, vec![2]);
    assert_eq!(visible_in_snapshot(&source, &bearer).await, vec![2]);

    // A key nothing was granted to buys nothing, so holding a key is not
    // itself the permission.
    let idle = caller(None, &[IDLE_KEY]);
    assert_eq!(
        visible_on_change_path(&auth, &idle).await,
        Vec::<i32>::new()
    );
    assert_eq!(visible_in_snapshot(&source, &idle).await, Vec::<i32>::new());
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_signed_in_caller_holding_a_key_sees_exactly_the_union() {
    let reader = setup().await;
    let auth = RlsAuth::from_ddl(reader.clone(), CATALOG_DDL).expect("build RlsAuth");
    let source = PgSnapshotSource::from_ddl(reader, CATALOG_DDL).expect("build snapshot source");

    // Alice alone sees her own paper.
    let alone = caller(Some("alice"), &[]);
    assert_eq!(visible_on_change_path(&auth, &alone).await, vec![1]);
    assert_eq!(visible_in_snapshot(&source, &alone).await, vec![1]);

    // Alice holding a key over bob's paper 2 sees the union and not one row
    // more. Paper 3 is bob's too and is the whole point of the assertion.
    let both = caller(Some("alice"), &[SHARED_KEY]);
    assert_eq!(visible_on_change_path(&auth, &both).await, vec![1, 2]);
    assert_eq!(visible_in_snapshot(&source, &both).await, vec![1, 2]);

    // Several keys at once, only one of them granted anything.
    let many = caller(Some("alice"), &[IDLE_KEY, SHARED_KEY]);
    assert_eq!(visible_on_change_path(&auth, &many).await, vec![1, 2]);
    assert_eq!(visible_in_snapshot(&source, &many).await, vec![1, 2]);
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn deleting_the_relation_removes_the_access() {
    let reader = setup().await;
    let auth = RlsAuth::from_ddl(reader.clone(), CATALOG_DDL).expect("build RlsAuth");
    let source = PgSnapshotSource::from_ddl(reader.clone(), CATALOG_DDL).expect("build source");
    let bearer = caller(None, &[SHARED_KEY]);
    assert_eq!(visible_on_change_path(&auth, &bearer).await, vec![2]);

    let admin = pool_for(&admin_url()).await;
    let mut conn = admin.get().await.expect("admin connection");
    AsyncRunQueryDsl::execute(
        sql_query(format!(
            "DELETE FROM paper_shares WHERE viewer = '{SHARED_KEY}'"
        )),
        &mut *conn,
    )
    .await
    .expect("withdraw");
    drop(conn);

    // The token is still cryptographically fine and still names the subject.
    // The subject simply has no relations left, on either executor.
    assert_eq!(
        visible_on_change_path(&auth, &bearer).await,
        Vec::<i32>::new()
    );
    assert_eq!(
        visible_in_snapshot(&source, &bearer).await,
        Vec::<i32>::new()
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_caller_cannot_mint_a_capability_over_a_resource_it_cannot_read() {
    let reader = setup().await;
    let auth = Arc::new(RlsAuth::from_ddl(reader.clone(), CATALOG_DDL).expect("build RlsAuth"));
    let rows =
        Arc::new(PgSnapshotSource::from_ddl(reader, CATALOG_DDL).expect("build snapshot source"));
    let authority = Arc::new(TokenAuthority::generate(&AuthConfig::default()).expect("keypair"));
    // Every successful mint is recorded, every refusal is not. The refusals
    // below are authorization denials, which go to the log by the split in
    // `08-authorization.md`, so this asserts the half of that split a future
    // change is most likely to break.
    let recorded: Arc<Mutex<Vec<AuthEvent<String>>>> = Arc::default();
    let sink = Arc::clone(&recorded);
    let issuer = CapabilityIssuer::new(authority, auth, rows, &AuthConfig::default()).with_audit(
        Arc::new(move |event| sink.lock().expect("sink").push(event)),
    );

    let alice_paper = [Value::<PgValues>::Int(1)];
    let bob_paper = [Value::<PgValues>::Int(3)];

    // Alice may share her own paper.
    issuer
        .issue(&caller(Some("alice"), &[]), "papers", &alice_paper, None)
        .await
        .expect("alice may share what she owns");

    // She may not share bob's, and neither may a caller with nothing at all.
    let refused = issuer
        .issue(&caller(Some("alice"), &[]), "papers", &bob_paper, None)
        .await
        .expect_err("alice cannot share a paper she cannot read");
    assert!(
        matches!(refused, ShareError::Unauthorized { .. }),
        "expected Unauthorized, got {refused:?}"
    );
    let refused = issuer
        .issue(&caller(None, &[]), "papers", &alice_paper, None)
        .await
        .expect_err("a stranger cannot share anything");
    assert!(
        matches!(refused, ShareError::Unauthorized { .. }),
        "expected Unauthorized, got {refused:?}"
    );

    // Holding the key over paper 2 is enough to pass on paper 2 alone, so the
    // check is the same read question every other caller asks.
    let bearer = caller(None, &[SHARED_KEY]);
    let shared_paper = [Value::<PgValues>::Int(2)];
    issuer
        .issue(&bearer, "papers", &shared_paper, None)
        .await
        .expect("a key holder may reshare what the key opens");
    let refused = issuer
        .issue(&bearer, "papers", &bob_paper, None)
        .await
        .expect_err("the key opens paper 2 only");
    assert!(
        matches!(refused, ShareError::Unauthorized { .. }),
        "expected Unauthorized, got {refused:?}"
    );

    let recorded = recorded.lock().expect("sink");
    assert_eq!(
        recorded.len(),
        2,
        "two mints succeeded and three were refused, so two rows: {recorded:?}"
    );
    for event in recorded.iter() {
        assert_eq!(event.op, AuthOp::CapabilityMinted);
        assert_eq!(
            event.table_name.as_deref(),
            Some("papers"),
            "a mint names the table it shared"
        );
        assert!(event.pk.is_some(), "a mint names the row it shared");
    }
    assert_eq!(
        recorded[0].user_id.as_deref(),
        Some("alice"),
        "the mint runs as the caller, so the row names them"
    );
    assert_eq!(
        recorded[1].user_id, None,
        "a key holder with no identity mints without one"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn the_grant_row_itself_is_refused_when_the_sharer_cannot_read_the_paper() {
    // Connetto checks the resource the caller names and hands back a key, and
    // the application then writes the permission row. Nothing in connetto sees
    // that insert, so what stops it naming a different paper is the policy on
    // the sharing table, which is the same policy source as everything else.
    let reader = setup().await;
    let mut conn = reader.get().await.expect("reader connection");
    AsyncRunQueryDsl::execute(
        sql_query("SELECT set_config('app.user_id', 'bob', false)"),
        &mut *conn,
    )
    .await
    .expect("bind bob");

    AsyncRunQueryDsl::execute(
        sql_query("INSERT INTO paper_shares VALUES (3, 'key:bobs-own')"),
        &mut *conn,
    )
    .await
    .expect("bob may grant over the paper he owns");

    let refused = AsyncRunQueryDsl::execute(
        sql_query("INSERT INTO paper_shares VALUES (1, 'key:not-bobs')"),
        &mut *conn,
    )
    .await
    .expect_err("bob cannot grant over alice's paper");
    assert!(
        refused
            .to_string()
            .to_lowercase()
            .contains("row-level security"),
        "expected an RLS refusal, got {refused}"
    );
}

// Everything below needs no database: a token is checked by arithmetic.

#[tokio::test]
async fn an_expired_capability_is_refused() {
    let authority = TokenAuthority::generate(&AuthConfig::default()).expect("keypair");
    let subject = CapabilitySubject::new(<String as CapabilityKey>::mint());
    let issued_at = SystemTime::now() - Duration::from_secs(3600);
    let ttl = Duration::from_secs(60);

    let expired = authority
        .mint_capability(&subject, issued_at, ttl)
        .expect("mint");
    authority
        .check_grant::<String, String>(&connetto_core::messages::Grant::new(expired))
        .expect_err("a capability minted an hour ago with a minute of life is refused");

    let live = authority
        .mint_capability(&subject, SystemTime::now(), ttl)
        .expect("mint");
    let checked = authority
        .check_grant::<String, String>(&connetto_core::messages::Grant::new(live))
        .expect("a live capability checks out");
    assert_eq!(
        checked,
        Subject::Capability(subject),
        "the check reads back the subject that was signed"
    );
}

/// A row source that always finds the row, so the lifetime assertions need no
/// database.
struct AlwaysFound;

impl RowSource for AlwaysFound {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn read_row(
        &self,
        _caller: &Principal,
        _table: &str,
        _key: &[Value<PgValues>],
    ) -> Result<Option<SourceRow>, Self::Error> {
        Ok(Some(SourceRow {
            table_id: 0,
            values: Vec::new(),
        }))
    }
}

#[tokio::test]
async fn a_lifetime_over_the_ceiling_is_refused_rather_than_shortened() {
    let config = AuthConfig {
        capability_ttl: Duration::from_secs(60),
        capability_max_ttl: Duration::from_secs(600),
        ..AuthConfig::default()
    };
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let issuer = CapabilityIssuer::new(
        authority,
        Arc::new(connetto_server::PermissiveAuth),
        Arc::new(AlwaysFound),
        &config,
    );
    let caller = caller(Some("alice"), &[]);

    let refused = issuer
        .issue(&caller, "papers", &[], Some(Duration::from_secs(601)))
        .await
        .expect_err("over the ceiling");
    assert!(
        matches!(refused, ShareError::TtlTooLong { .. }),
        "expected TtlTooLong, got {refused:?}"
    );
    issuer
        .issue(&caller, "papers", &[], Some(Duration::from_secs(600)))
        .await
        .expect("exactly the ceiling is allowed");
}

#[tokio::test]
async fn no_minted_token_carries_a_permission() {
    // Asserted by reading the signed payload rather than the claims struct, so
    // a field added to that struct later fails here.
    let authority = TokenAuthority::generate(&AuthConfig::default()).expect("keypair");
    let key = <String as CapabilityKey>::mint();
    let token = authority
        .mint_capability(
            &CapabilitySubject::<String>::new(key.clone()),
            SystemTime::now(),
            Duration::from_secs(60),
        )
        .expect("mint");

    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    let claims: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&base64url(payload)).expect("the payload is JSON");
    let mut names: Vec<&str> = claims.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["aud", "exp", "iat", "iss", "knd", "sub"],
        "a capability names a subject, an issuer, an audience and a lifetime, \
         and says nothing about what the subject may do"
    );
    assert_eq!(claims["sub"], serde_json::Value::String(key));
    assert_eq!(claims["knd"], serde_json::Value::String("key".to_owned()));
}

/// Decode unpadded base64url, which is what a JWT segment is.
fn base64url(segment: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(segment.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0_u32;
    for byte in segment.bytes() {
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .expect("a base64url character");
        acc = (acc << 6) | u32::try_from(value).expect("six bits");
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).expect("one byte"));
        }
    }
    out
}
