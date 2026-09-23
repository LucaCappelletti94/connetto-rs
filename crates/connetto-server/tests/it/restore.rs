//! R70 step 2: a client whose replica is ahead of a server restored to an
//! earlier point, once per restore method (R70 decision 3).
//!
//! The real server and client binaries run as in `e2e.rs`. The client syncs
//! three rows, the deployment takes a backup, two more rows reach the client,
//! and the server is stopped and its database restored from the backup. A
//! restarted server then takes one new row, the client logs in again and
//! relaunches on the replica it holds, and it is read back. The decided outcome
//! leaves the client holding exactly what the restored server holds, and no
//! refresh token from before the restore still works (R70 decisions 4, 5 and 10).

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use diesel::sqlite::SqliteConnection;
use diesel::{Connection, ExpressionMethods, QueryDsl};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tempfile::TempDir;

use connetto_client::{ReplicaKey, cipher};
use connetto_test_harness::{Fixture, PUBLICATION, SLOT};
use openidconnect::reqwest;

use super::e2e::{
    Authorization, ChildGuard, NO_POLICIES, PG_DDL, PG_SERIAL, QUERY, ReplicaDir, build_auth_stack,
    client_bin, free_port, keyring_entry, mint_refresh_token, mint_token, orders, reset_fixture,
    spawn_client_env, spawn_server_cfg, wait_for_port, wait_for_rows, with_user_url,
};

/// How the deployment backs up and restores.
#[derive(Clone, Copy, Debug)]
enum Method {
    /// `pg_basebackup`, then recovery to the backup's consistent point, which
    /// promotes onto a new timeline, as a second cluster.
    PointInTime,
    /// `pg_dumpall --globals-only` and `pg_dump`, restored into a freshly
    /// initialised second cluster.
    FreshCluster,
    /// `pg_dump`, restored with `--clean` into the cluster it was taken from.
    SameCluster,
}

/// The backup half, taken while the server runs.
const BASE_BACKUP: &str = "rm -rf /tmp/base && pg_basebackup -D /tmp/base -X stream -c fast";
const DUMP: &str = "pg_dumpall --globals-only -f /tmp/globals.sql && \
                    pg_dump -Fc -d postgres -f /tmp/db.dump";

/// Recovery to the base backup's consistent point on the spare port.
/// `restore_command` is required for targeted recovery, and every segment it
/// needs is already in `pg_wal` because the backup streamed it. `wal_level`
/// is repeated because the primary took it on its command line, which a base
/// backup does not carry.
const RECOVER_TO_BACKUP: &str = "touch /tmp/base/recovery.signal && \
     printf \"port = 5433\\nwal_level = logical\\nrecovery_target = 'immediate'\\nrecovery_target_action = 'promote'\\nrestore_command = 'false'\\n\" \
       >> /tmp/base/postgresql.auto.conf && \
     chmod 700 /tmp/base && \
     pg_ctl -D /tmp/base -l /tmp/pitr.log -w -t 60 start && \
     until [ \"$(psql -p 5433 -At -c 'SELECT pg_is_in_recovery()')\" = f ]; do sleep 0.2; done";

/// A fresh cluster on the spare port, with the dump restored into it.
const RESTORE_INTO_FRESH: &str = "rm -rf /tmp/fresh && \
     initdb -D /tmp/fresh -U postgres --auth=trust >/dev/null && \
     echo 'host all all all trust' >> /tmp/fresh/pg_hba.conf && \
     pg_ctl -D /tmp/fresh -l /tmp/fresh.log -w -t 60 \
       -o \"-p 5433 -c listen_addresses='*' -c wal_level=logical -c fsync=off\" start && \
     psql -p 5433 -d postgres -q -f /tmp/globals.sql >/dev/null 2>&1 || true; \
     pg_restore -p 5433 -d postgres /tmp/db.dump";

/// The dump restored over the cluster it came from.
const RESTORE_INTO_SAME: &str = "pg_restore --clean --if-exists -d postgres /tmp/db.dump";

/// The replica schema, idempotent because the client binary replays it on
/// every open and this client opens its replica twice.
const REOPENABLE_SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS orders \
    (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// The application launching on its replica.
fn launch(ws: &str, db: &Path, token: &str) -> ChildGuard {
    spawn_client_env(
        ws,
        db,
        "restore-client",
        REOPENABLE_SQLITE_DDL,
        PG_DDL,
        NO_POLICIES,
        "orders",
        QUERY,
        token,
        None,
    )
}

/// What the run observed.
#[derive(Debug)]
#[expect(dead_code, reason = "the demonstration reports through Debug")]
struct Observation {
    method: Method,
    /// Order ids the client held just before the restore.
    client_before: Vec<i32>,
    /// Slots the restored cluster held before the operator recreated one.
    slots_after_restore: i64,
    /// Order ids the restored server holds, new row included.
    server_after: Vec<i32>,
    /// Order ids the client holds once it has had time to converge.
    client_after: Vec<i32>,
    /// The restored cluster's timeline.
    timeline: i64,
    /// Whether the restored cluster reports the system identifier the backed-up one did.
    same_system_identifier: bool,
    /// What `/auth/refresh` answers the holder's current refresh token, which
    /// was rotated after the backup.
    holder_refresh_after_restore: u16,
    /// What it answers a refresh token rotated away after the backup, the one
    /// a thief would hold.
    stale_refresh_after_restore: u16,
}

/// Order ids in the client's replica, empty while it cannot be opened.
fn client_ids(db_path: &Path) -> Vec<i32> {
    let path = db_path.to_string_lossy();
    let Some(key) = keyring_entry(&path)
        .ok()
        .and_then(|entry| entry.get_password().ok())
        .and_then(|hex| hex.parse::<ReplicaKey>().ok())
    else {
        return Vec::new();
    };
    let Ok(mut conn) = SqliteConnection::establish(&path) else {
        return Vec::new();
    };
    if cipher::unlock(&mut conn, &key).is_err() {
        return Vec::new();
    }
    diesel::RunQueryDsl::load(
        orders::table.select(orders::id).order(orders::id),
        &mut conn,
    )
    .unwrap_or_default()
}

async fn server_ids(pool: &Pool<AsyncPgConnection>) -> Vec<i32> {
    let mut conn = pool.get().await.expect("admin connection");
    orders::table
        .select(orders::id)
        .order(orders::id)
        .load(&mut conn)
        .await
        .expect("read the server's orders")
}

async fn insert_order(pool: &Pool<AsyncPgConnection>, id: i32) {
    let mut conn = pool.get().await.expect("admin connection");
    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(id),
            orders::price.eq(1.0),
            orders::quantity.eq(1),
            orders::status.eq("restore"),
        ))
        .execute(&mut conn)
        .await
        .expect("insert an order");
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    Pool::builder()
        .build(AsyncDieselConnectionManager::<AsyncPgConnection>::new(url))
        .await
        .expect("build pool")
}

/// A token signing key pair on disk, so an access token outlives the server
/// restart the way it does in a deployment that supplies its keys.
fn signing_keys(dir: &TempDir) -> (String, String) {
    let private = dir.path().join("jwt.pem");
    let public = dir.path().join("jwt.pub.pem");
    let run = |args: &[&str]| {
        let status = Command::new("openssl")
            .args(args)
            .status()
            .expect("run openssl");
        assert!(status.success(), "openssl {args:?} failed");
    };
    let (private, public) = (
        private.to_string_lossy().into_owned(),
        public.to_string_lossy().into_owned(),
    );
    run(&["genpkey", "-algorithm", "ed25519", "-out", &private]);
    run(&["pkey", "-in", &private, "-pubout", "-out", &public]);
    (private, public)
}

/// Present a refresh token, returning the status and the rotated token.
async fn refresh(auth_base: &str, token: &str) -> (u16, Option<String>) {
    let response = reqwest::Client::new()
        .post(format!("{auth_base}/auth/refresh"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "refresh_token": token }).to_string())
        .send()
        .await
        .expect("POST /auth/refresh");
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    (
        status,
        body["refresh_token"].as_str().map(ToOwned::to_owned),
    )
}

/// Restore the backup `method` took, recreate the slot as an operator must,
/// and return where the restored database listens, how many slots it held
/// before the recreation, its timeline and its system identifier.
async fn restore(
    fixture: &Fixture,
    method: Method,
    primary_url: String,
) -> (String, i64, i64, String) {
    let target_url = match method {
        Method::PointInTime => {
            fixture.shell(RECOVER_TO_BACKUP).await;
            fixture.spare_url().to_owned()
        }
        Method::FreshCluster => {
            fixture.shell(RESTORE_INTO_FRESH).await;
            fixture.spare_url().to_owned()
        }
        Method::SameCluster => {
            fixture
                .shell(&format!(
                    "psql -d postgres -q -c \"SELECT pg_drop_replication_slot('{SLOT}')\""
                ))
                .await;
            fixture.shell(RESTORE_INTO_SAME).await;
            primary_url
        }
    };
    let port_flag = match method {
        Method::SameCluster => "",
        Method::PointInTime | Method::FreshCluster => "-p 5433",
    };
    let read = |sql: &'static str| {
        let script = format!("psql {port_flag} -d postgres -At -c '{sql}'");
        async move {
            fixture
                .shell(&script)
                .await
                .trim()
                .parse::<i64>()
                .expect("an integer")
        }
    };
    let slots = read("SELECT count(*) FROM pg_replication_slots").await;
    let timeline = read("SELECT timeline_id FROM pg_control_checkpoint()").await;
    let identifier = system_identifier(fixture, port_flag).await;
    fixture
        .shell(&format!(
            "psql {port_flag} -d postgres -q -c \"SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')\" \
             -c \"SELECT 1 FROM pg_publication WHERE pubname = '{PUBLICATION}'\""
        ))
        .await;
    (target_url, slots, timeline, identifier)
}

/// The system identifier of the cluster `port_flag` names, as Postgres prints it.
async fn system_identifier(fixture: &Fixture, port_flag: &str) -> String {
    fixture
        .shell(&format!(
            "psql {port_flag} -d postgres -At -c 'SELECT system_identifier FROM pg_control_system()'"
        ))
        .await
        .trim()
        .to_owned()
}

/// Take the backup, then move past it on every front the restore rewinds. Two
/// rows reach the client, the holder rotates its refresh token, and a second
/// session rotates away the token that `stale` still names. Returns the
/// holder's rotated token and the client's rows.
async fn back_up_then_advance(
    fixture: &Fixture,
    method: Method,
    primary: &Pool<AsyncPgConnection>,
    auth_base: &str,
    holder: String,
    stale: &str,
    db: &Path,
) -> (String, Vec<i32>) {
    fixture
        .shell(match method {
            Method::PointInTime => BASE_BACKUP,
            Method::FreshCluster | Method::SameCluster => DUMP,
        })
        .await;
    insert_order(primary, 4).await;
    insert_order(primary, 5).await;
    let (status, rotated) = refresh(auth_base, &holder).await;
    assert_eq!(status, 200, "the holder rotates after the backup");
    let (status, _) = refresh(auth_base, stale).await;
    assert_eq!(
        status, 200,
        "and so does the session whose old token goes stale"
    );
    assert_eq!(
        wait_for_rows(db, 5, Duration::from_secs(30)).await,
        5,
        "the client passes the backup"
    );
    (rotated.expect("a rotated refresh token"), client_ids(db))
}

/// The primary with the `orders` fixture, the auth tables and three rows.
async fn seeded_primary(fixture: &Fixture, url: &str) -> Pool<AsyncPgConnection> {
    let primary = pool_for(url).await;
    reset_fixture(&primary, fixture).await;
    fixture.provision_auth_tables().await;
    insert_order(&primary, 2).await;
    insert_order(&primary, 3).await;
    primary
}

/// Wait until every listener accepts a connection.
async fn await_listening(addrs: [&str; 2]) {
    for addr in addrs {
        assert!(
            wait_for_port(addr, Duration::from_secs(30)).await,
            "{addr} did not open"
        );
    }
}

async fn demonstrate(method: Method) -> Observation {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    assert!(client_bin().exists(), "build the client binary first");
    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire_restorable().await;
    let primary_url = fixture.admin_url().to_owned();
    let primary = seeded_primary(&fixture, &primary_url).await;

    let keys = tempfile::tempdir().expect("tempdir");
    let (private, public) = signing_keys(&keys);
    let port = free_port();
    let auth_port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");
    let auth_stack = build_auth_stack(auth_port).await;
    let mut envs: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    envs.push(("CONNETTO_JWT_PRIVATE_KEY_FILE", &private));
    envs.push(("CONNETTO_JWT_PUBLIC_KEY_FILE", &public));
    envs.push(("CONNETTO_AUTH", "database"));
    let auth_bind = format!("127.0.0.1:{auth_port}");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(30);

    let reader = with_user_url(&primary_url, "app_reader", "app_reader");
    let server = spawn_server_cfg(
        &primary_url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader),
        &authorization,
        &envs,
    );
    await_listening([&bind, &auth_bind]).await;
    let (token, _) = mint_token(&auth_stack.auth_base).await;
    let holder = mint_refresh_token(&auth_stack.auth_base).await;
    let stale = mint_refresh_token(&auth_stack.auth_base).await;

    let mut dir = ReplicaDir::new();
    let db = dir.replica("restore-client.db");
    let client = launch(&ws, &db, &token);
    assert_eq!(
        wait_for_rows(&db, 3, secs).await,
        3,
        "the client syncs the seed"
    );

    let (holder, client_before) = back_up_then_advance(
        &fixture,
        method,
        &primary,
        &auth_stack.auth_base,
        holder,
        &stale,
        &db,
    )
    .await;

    // A client binary exits when its server goes away, so the restart below is
    // the application relaunching on the replica it already holds.
    drop(client);
    drop(server);
    let backed_up_identifier = system_identifier(&fixture, "").await;
    let (target_url, slots_after_restore, timeline, restored_identifier) =
        restore(&fixture, method, primary_url).await;

    let restored = pool_for(&target_url).await;
    let reader = with_user_url(&target_url, "app_reader", "app_reader");
    let _server = spawn_server_cfg(
        &target_url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader),
        &authorization,
        &envs,
    );
    await_listening([&bind, &auth_bind]).await;
    let (holder_refresh_after_restore, _) = refresh(&auth_stack.auth_base, &holder).await;
    let (stale_refresh_after_restore, _) = refresh(&auth_stack.auth_base, &stale).await;
    insert_order(&restored, 6).await;
    let (token, _) = mint_token(&auth_stack.auth_base).await;
    let _client = launch(&ws, &db, &token);
    // No count to wait for, since which count is right is what is being
    // observed, so the client gets a fixed time to catch up or resync.
    tokio::time::sleep(Duration::from_secs(15)).await;

    Observation {
        method,
        client_before,
        slots_after_restore,
        server_after: server_ids(&restored).await,
        client_after: client_ids(&db),
        timeline,
        same_system_identifier: backed_up_identifier == restored_identifier,
        holder_refresh_after_restore,
        stale_refresh_after_restore,
    }
}

/// Every restore method leaves the client matching the server and every refresh token from before it refused.
fn assert_recovered(observed: &Observation) {
    assert_eq!(
        observed.client_after, observed.server_after,
        "the client resyncs to what the restored server holds: {observed:#?}"
    );
    assert_eq!(
        (
            observed.holder_refresh_after_restore,
            observed.stale_refresh_after_restore
        ),
        (401, 401),
        "the restore revoked every session: {observed:#?}"
    );
}

#[tokio::test]
#[ignore = "needs Docker and the release connetto-server and connetto-client binaries"]
async fn a_point_in_time_restore_resyncs_clients_and_revokes_sessions() {
    let observed = demonstrate(Method::PointInTime).await;
    assert!(observed.same_system_identifier, "{observed:#?}");
    assert_eq!(observed.timeline, 2, "{observed:#?}");
    assert_recovered(&observed);
}

#[tokio::test]
#[ignore = "needs Docker and the release connetto-server and connetto-client binaries"]
async fn a_dump_into_a_fresh_cluster_resyncs_clients_and_revokes_sessions() {
    let observed = demonstrate(Method::FreshCluster).await;
    assert!(
        !observed.same_system_identifier,
        "only the identifier tells this restore apart: {observed:#?}"
    );
    assert_eq!(observed.timeline, 1, "{observed:#?}");
    assert_recovered(&observed);
}

#[tokio::test]
#[ignore = "needs Docker and the release connetto-server and connetto-client binaries"]
async fn a_dump_into_the_same_cluster_resyncs_clients_and_revokes_sessions() {
    let observed = demonstrate(Method::SameCluster).await;
    assert!(observed.same_system_identifier, "{observed:#?}");
    assert_recovered(&observed);
}

/// A membership-guarded schema, so the change path asks the authorization
/// store about `docs` rows from facts derived from `project_members`.
const MEMBERSHIP_DDL: &str = "CREATE TABLE docs (id BIGINT PRIMARY KEY, project_id BIGINT NOT NULL);\n\
     CREATE TABLE project_members (project_id BIGINT NOT NULL, user_id TEXT NOT NULL, \
     PRIMARY KEY (project_id, user_id));";
const MEMBERSHIP_POLICIES: &str = "ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
     CREATE POLICY docs_members ON docs FOR ALL USING (project_id IN \
     (SELECT project_id FROM project_members WHERE user_id = current_setting('app.user_id', true)));";

/// Every tuple in the store whose user names `who`.
async fn tuples_naming(authorization: &Authorization, who: &str) -> Vec<String> {
    use openfga_client::client::{OpenFgaServiceClient, ReadRequest};
    let mut client = OpenFgaServiceClient::connect(authorization.endpoint.clone())
        .await
        .expect("connect to the authorization service");
    let mut found = Vec::new();
    let mut continuation_token = String::new();
    loop {
        let page = client
            .read(ReadRequest {
                store_id: authorization.store.clone(),
                continuation_token,
                ..ReadRequest::default()
            })
            .await
            .expect("read the store")
            .into_inner();
        found.extend(
            page.tuples
                .into_iter()
                .filter_map(|tuple| tuple.key)
                .filter(|key| key.user.contains(who))
                .map(|key| format!("{} {} {}", key.user, key.relation, key.object)),
        );
        if page.continuation_token.is_empty() {
            return found;
        }
        continuation_token = page.continuation_token;
    }
}

/// Poll the store until a tuple names `who`, or the timeout passes.
async fn await_tuples(authorization: &Authorization, who: &str) -> Vec<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let found = tuples_naming(authorization, who).await;
        if !found.is_empty() || std::time::Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
#[ignore = "R70 step 2 demonstration, prints what a restore does and asserts nothing"]
async fn authorization_facts_across_a_restore() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire_restorable().await;
    let url = fixture.admin_url().to_owned();
    fixture
        .setup(&[
            MEMBERSHIP_DDL,
            "CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT SELECT ON docs, project_members TO app_reader",
            "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_reader",
            "INSERT INTO project_members VALUES (1, 'alice')",
        ])
        .await;
    fixture
        .start_replication(&["docs", "project_members"])
        .await;
    let authorization = Authorization::provision(&fixture, MEMBERSHIP_POLICIES).await;
    let bind = format!("127.0.0.1:{}", free_port());
    let reader = with_user_url(&url, "app_reader", "app_reader");
    let secs = Duration::from_secs(30);
    let auth_stack = build_auth_stack(free_port()).await;
    let auth: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let server = spawn_server_cfg(
        &url,
        &bind,
        MEMBERSHIP_DDL,
        "",
        Some(&reader),
        &authorization,
        &auth,
    );
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}"
    );
    let alice_at_boot = await_tuples(&authorization, "alice").await;

    fixture.shell(DUMP).await;
    fixture
        .exec("INSERT INTO project_members VALUES (1, 'mallory')")
        .await;
    let mallory_granted = await_tuples(&authorization, "mallory").await;

    drop(server);
    fixture
        .shell(&format!(
            "psql -d postgres -q -c \"SELECT pg_drop_replication_slot('{SLOT}')\""
        ))
        .await;
    fixture.shell(RESTORE_INTO_SAME).await;
    fixture
        .shell(&format!(
            "psql -d postgres -q -c \"SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')\""
        ))
        .await;
    let _server = spawn_server_cfg(
        &url,
        &bind,
        MEMBERSHIP_DDL,
        "",
        Some(&reader),
        &authorization,
        &auth,
    );
    assert!(
        wait_for_port(&bind, secs).await,
        "the restored server did not open {bind}"
    );
    tokio::time::sleep(Duration::from_secs(5)).await;

    eprintln!(
        "alice at boot: {alice_at_boot:?}\nmallory granted after the backup: {mallory_granted:?}\n\
         mallory in the restored database: {}\nmallory in the store after the restored boot: {:?}",
        fixture
            .shell("psql -d postgres -At -c \"SELECT count(*) FROM project_members WHERE user_id = 'mallory'\"")
            .await
            .trim(),
        tuples_naming(&authorization, "mallory").await,
    );
}
