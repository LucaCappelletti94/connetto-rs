//! Device enrolment on a native client, end to end (R74 step 3, proof 1).
//!
//! A real keyring build signs in against the in-process auth router and a
//! containerised OIDC provider, then connects over a real WebSocket to an
//! in-process `SessionManager` whose handshake authority verifies the auth
//! service's tokens. Each scenario runs in a child process whose keyring
//! auto-detection resolves to sealed files on disk, so a desktop's D-Bus
//! Secret Service is never reached, and every wait runs against a deadline.
//!
//! Needs Docker, since the fixture starts its own Postgres and the login
//! walks a containerised provider.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use connetto_client::{
    AccountChoice, Auth, BrowserOpener, CertificateError, ClientEvent, Keyring, KeyringAuth,
    KeyringKeyStore, KeyringStore, NativeClient, NativeClientBuilder, NativeDurable,
    REPLICA_PREFIX, SyncStatus, device_key_record, replica_db_name,
};
use connetto_core::device_cert::{DeploymentId, DeviceCertificate, DeviceIssuer, KeyHome, RootCa};
use connetto_core::messages::EnrolRefusal;
use connetto_core::traits::{HandshakeAuthority, RefreshTokenStore};
use connetto_server::device_cert::{
    DeviceCertConfig, DeviceEnrolment, Enrolment, MemoryEnrolments,
};
use connetto_server::{
    AbuseConfig, AuthConfig, AuthService, GenericOidcProvider, InMemoryAuthStore, ManagerBuilder,
    Materializer, PgReadConnector, PgSnapshotSource, ProviderRegistry, RedirectPolicy,
    RequestGuard, RuntimeWritableCatalog, SessionManager, ThrottleConfig, TierLimits,
    TokenAuthority, WebSocketTransport, auth_router, pg_write_target,
};
use connetto_test_harness::{
    ConnettoDefaults, Fixture, MOCK_OAUTH_PROVIDER, MockOauth, RosterAuth,
};
use openidconnect::reqwest;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use tempfile::tempdir;

/// The longest any bounded wait in a phase runs.
const BOUND: Duration = Duration::from_secs(60);
/// A day, the unit the issuer validity is spelled in.
const DAY: Duration = Duration::from_hours(24);

/// Names the phase a driver re-execs, so the child runs one scenario.
const PHASE: &str = "CONNETTO_R74_PHASE";

/// A one-table fixture schema the client and the server each name in their own
/// DDL, the way the suites that sync a table spell it.
const PG_DDL: &str = "CREATE TABLE devices (id INT PRIMARY KEY, label TEXT);";
// `IF NOT EXISTS` because `connect` replays the caller's DDL on every open.
const SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, label TEXT);";

/// A manager whose computed subscriptions read through connetto's connector.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>;

/// One keyring service per scenario, so a shared store never crosses two.
const APP_ENROL: &str = "r74-enrolment";
const APP_RENEW: &str = "r74-renewal";
const APP_REISSUE: &str = "r74-reissue";
const APP_CAP: &str = "r74-cap";
const APP_REVOKE: &str = "r74-revoke";
const APP_NONE: &str = "r74-no-issuer";
const APP_RESTART: &str = "r74-restart";
const APP_OFFLINE: &str = "r74-offline";
const APP_FORGET: &str = "r74-forget";

/// What the lost-device list shows about these test devices.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Descriptor {
    name: String,
    city: String,
}

/// Re-run `phase` in a child process whose keyring auto-detection resolves to
/// sealed files, and fail this test, with the child's output, unless it
/// passes. The builder's `.keyring()` store is detected, never named, and a
/// desktop's D-Bus Secret Service dismisses headless, so the phase runs where
/// detection settles on files.
fn run_phase(phase: &str) {
    let dir = tempdir().expect("tempdir");
    let credentials = dir.path().join("credentials");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&credentials).expect("credentials");
    std::fs::create_dir_all(&state).expect("state");
    std::fs::write(credentials.join("connetto.wrap-key"), [1u8; 32]).expect("wrap key");
    let output = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "enrolment::enrolment_phase",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("STATE_DIRECTORY")
        .env("CREDENTIALS_DIRECTORY", credentials)
        .env("STATE_DIRECTORY", state)
        .env(PHASE, phase)
        .output()
        .expect("spawn the phase");
    assert!(
        output.status.success(),
        "the {phase} phase failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The phase the drivers re-exec, run in a child with the sealed-file keyring
/// env. Run alone it does nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a phase the enrolment drivers run in a child process"]
async fn enrolment_phase() {
    let Ok(phase) = std::env::var(PHASE) else {
        return;
    };
    match phase.as_str() {
        "first" => first_connect().await,
        "renewal" => renewal().await,
        "reissue" => reissue().await,
        "cap" => cap().await,
        "revoke" => revoke().await,
        "spectator" => spectator().await,
        "restart" => restart().await,
        "offline" => offline().await,
        "forget" => forget().await,
        other => panic!("unknown enrolment phase {other:?}"),
    }
}

/// An issuer valid for a year and a month from now, under a fresh root.
///
/// The key is made with the suite's own `rcgen` and the issuer loads it from
/// PKCS #8 bytes, so the two `rcgen` majors in the graph never meet as one
/// value.
fn issuer() -> DeviceIssuer {
    let now = SystemTime::now();
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(0x5eed)),
        now - DAY,
        3650 * DAY,
    )
    .expect("root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let cert = root
        .sign_issuer(&key.public_key_der(), now - DAY, 395 * DAY, [1; 16])
        .expect("issuer");
    DeviceIssuer::from_pkcs8(cert, &key.serialize_der(), root.certificate()).expect("load")
}

/// Serve the auth router with one containerised provider, returning the base
/// URL, the service and the provider guard.
async fn spawn_auth() -> (String, Arc<AuthService<InMemoryAuthStore>>, MockOauth) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the auth listener");
    let port = listener.local_addr().expect("address").port();
    let base = format!("http://127.0.0.1:{port}");
    let callback = format!("{base}/auth/callback");

    let idp = MockOauth::start().await;
    let provider = GenericOidcProvider::discover(
        idp.oidc_config(MOCK_OAUTH_PROVIDER, callback),
        reqwest::Client::new(),
    )
    .await
    .expect("discover the provider");

    let config = AuthConfig::default();
    let service = Arc::new(AuthService::new(
        Arc::new(TokenAuthority::generate(&config).expect("token authority")),
        Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes())),
        Arc::new(RequestGuard::default()),
    ));
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(provider));
    let router = auth_router(
        Arc::clone(&service),
        Arc::new(registry),
        RedirectPolicy::default(),
        connetto_server::CookieSameSite::Strict,
    );
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve the auth router");
    });
    (base, service, idp)
}

/// A manager whose handshake authority verifies `service`'s tokens.
fn manager(fixture: &Fixture, service: &Arc<AuthService<InMemoryAuthStore>>) -> Arc<Manager> {
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(Duration::from_secs(30))),
        AbuseConfig::default(),
    ));
    let pool = fixture.admin().clone();
    let authority: Arc<dyn HandshakeAuthority> = Arc::new(service.handshake_authority());
    ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .with_write_catalog(RuntimeWritableCatalog::default())
            .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        // No RLS in the fixture DDL, so the snapshot never asks the policy.
        RosterAuth::granting_nobody(),
        authority,
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoDefaults>(pool, PG_DDL).expect("build write target"),
    )
    .with_guard(guard)
    .build()
}

/// Serve `manager` on a fresh loopback listener, each connection in its own
/// task, and return the address and the guard.
async fn spawn_server(
    manager: Arc<Manager>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the sync listener");
    let addr = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move {
                let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
                let _ = manager.serve(transport).await;
            });
        }
    });
    (addr, server)
}

/// Serve a manager that verifies `service`'s tokens and enrols through
/// `config` into `store`, returning the WebSocket address and the server
/// guard.
async fn sync_server(
    fixture: &Fixture,
    service: &Arc<AuthService<InMemoryAuthStore>>,
    config: DeviceCertConfig,
    store: Arc<MemoryEnrolments<String>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let manager = manager(fixture, service);
    assert!(
        manager
            .install_device_enrolment(Arc::new(DeviceEnrolment::new(config, store)))
            .is_ok(),
        "installs once"
    );
    spawn_server(manager).await
}

/// A fresh-login keyring sign-in as `subject`, the services named by `app_id`.
fn fresh_login(base: &str, app_id: &str, subject: &str) -> KeyringAuth {
    Auth::new(base, MOCK_OAUTH_PROVIDER)
        .with_account(AccountChoice::New)
        .keyring(app_id)
        .with_browser_opener(fake_browser(subject))
}

/// The silent sign-back-in the restart and re-enrolment phases use.
fn last_used(base: &str, app_id: &str) -> KeyringAuth {
    Auth::new(base, MOCK_OAUTH_PROVIDER)
        .keyring(app_id)
        .with_browser_opener(no_browser())
}

/// A browser opener that fails the test, for a sign-in that must not log in
/// interactively.
fn no_browser() -> BrowserOpener {
    Arc::new(|_url: &str| panic!("the sign-in opened a browser"))
}

/// A fake browser. Given connetto's login URL, walk the real OIDC redirect
/// chain until the authenticator's loopback listener receives the code.
fn fake_browser(subject: &str) -> BrowserOpener {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let subject = subject.to_owned();
    Arc::new(move |login_url: &str| {
        let http = http.clone();
        let subject = subject.clone();
        let login_url = login_url.to_owned();
        tokio::spawn(async move {
            let mut next_url = login_url;
            let mut submitted = false;
            for _ in 0..6 {
                let resp = http.get(&next_url).send().await.expect("hop");
                if !submitted && resp.url().path().ends_with("/authorize") {
                    let form_url = resp.url().to_string();
                    let posted = http
                        .post(form_url)
                        .form(&[("username", subject.as_str())])
                        .send()
                        .await
                        .expect("submit the login form");
                    submitted = true;
                    let Some(loc) = posted.headers().get("location") else {
                        break;
                    };
                    loc.to_str()
                        .expect("utf8 location")
                        .clone_into(&mut next_url);
                    continue;
                }
                match resp.headers().get("location") {
                    Some(loc) => {
                        loc.to_str()
                            .expect("utf8 location")
                            .clone_into(&mut next_url);
                    }
                    None => break,
                }
            }
        });
        Ok(())
    })
}

/// The device key record the build's keyring keeps for `user_id`.
fn device_record(user_id: &str) -> String {
    device_key_record(&replica_db_name(REPLICA_PREFIX, user_id).expect("a user id serializes"))
}

/// A signed-in build over `addr`, the sign-in it names and the data directory
/// it keeps.
fn signed_in(
    addr: std::net::SocketAddr,
    sign_in: KeyringAuth,
    dir: &Path,
) -> NativeDurable<connetto_client::NativeTransport, (), Keyring, KeyringKeyStore> {
    NativeClientBuilder::new(format!("ws://{addr}/"), super::support::bundle(SQLITE_DDL))
        .signed_in(sign_in)
        .durable(dir)
}

/// Await an event matching `is` within `deadline`, skipping every other event.
async fn next_event(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    deadline: Duration,
    is: impl Fn(&ClientEvent) -> bool,
) -> Option<ClientEvent> {
    let until = Instant::now() + deadline;
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Ok(event)) if is(&event) => return Some(event),
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            _ => return None,
        }
    }
}

/// Poll `device_certificate` until it holds a certificate, bounded by
/// `deadline`.
async fn wait_for_certificate(
    client: &NativeClient<connetto_client::NativeTransport>,
    deadline: Duration,
) -> Option<DeviceCertificate> {
    let until = Instant::now() + deadline;
    loop {
        if let Some(cert) = client.device_certificate() {
            return Some(cert);
        }
        if Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Poll the enrolment store until it holds at least `count` records, bounded
/// by `deadline`.
async fn wait_for_records(
    store: &MemoryEnrolments<String>,
    count: usize,
    deadline: Duration,
) -> Option<Vec<Enrolment<String>>> {
    let until = Instant::now() + deadline;
    loop {
        let records = store.records();
        if records.len() >= count {
            return Some(records);
        }
        if Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The validity span a certificate holds. The issuer writes X.509 times at
/// whole seconds and floors both ends over one exact lifetime, so the span
/// equals the granted one.
fn span(cert: &DeviceCertificate) -> Duration {
    cert.not_after()
        .duration_since(cert.not_before())
        .expect("not_after follows not_before")
}

/// A first connect enrols the device, and the server's record names the
/// certificate's key and carries the descriptor as sent.
#[test]
fn a_first_connect_enrols_and_records_the_descriptor() {
    run_phase("first");
}

async fn first_connect() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (addr, _server) = sync_server(
        &fixture,
        &service,
        DeviceCertConfig::new(issuer()),
        Arc::clone(&store),
    )
    .await;
    let dir = tempdir().expect("a data directory");
    let descriptor = Descriptor {
        name: "pippo".into(),
        city: "Milan".into(),
    };

    let client = signed_in(
        addr,
        fresh_login(&base, APP_ENROL, "enrol-user"),
        dir.path(),
    )
    .with_device_descriptor(&descriptor)
    .connect()
    .await
    .expect("the signed-in build connects");

    let cert = wait_for_certificate(&client, BOUND)
        .await
        .expect("the enrolment grants");
    let session = client
        .session()
        .expect("a provider build reports its session");
    let records = wait_for_records(&store, 1, BOUND)
        .await
        .expect("the record lands");
    assert_eq!(records.len(), 1, "one certificate is issued");
    assert_eq!(records[0].user, session.user_id());
    assert_eq!(records[0].key, cert.identity().key());
    assert_eq!(&records[0].serial[..], cert.serial());
    assert_eq!(
        records[0].descriptor,
        rmp_serde::to_vec_named(&descriptor).expect("serializes")
    );
    assert_eq!(cert.identity().account(), session.user_id());
    assert_eq!(
        client.device_key_home(),
        Some(KeyHome::Software),
        "a Linux build without a key chip reports its software key"
    );
    client.close().await;
}

/// Past half-life the client renews on its own, at the stored lifetime, and
/// the server records the new serial under the same key.
#[test]
fn a_renewal_past_half_life_replaces_the_certificate() {
    run_phase("renewal");
}

async fn renewal() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (addr, _server) = sync_server(
        &fixture,
        &service,
        DeviceCertConfig::new(issuer()),
        Arc::clone(&store),
    )
    .await;
    let dir = tempdir().expect("a data directory");
    let lifetime = Duration::from_secs(4);

    let client = signed_in(
        addr,
        fresh_login(&base, APP_RENEW, "enrol-user"),
        dir.path(),
    )
    .with_certificate_lifetime(lifetime)
    .connect()
    .await
    .expect("the signed-in build connects");

    let first = wait_for_certificate(&client, BOUND)
        .await
        .expect("the first enrolment grants");
    assert_eq!(
        span(&first),
        lifetime,
        "the enrolment takes the builder lifetime"
    );
    let records = wait_for_records(&store, 2, BOUND)
        .await
        .expect("the renewal records");
    assert_eq!(
        records.len(),
        2,
        "the refusal records nothing, the grant does"
    );
    assert_ne!(
        records[0].serial, records[1].serial,
        "a new serial is issued"
    );
    assert_eq!(records[0].key, records[1].key, "the renewal keeps the key");

    let until = Instant::now() + BOUND;
    let mut renewed = None;
    loop {
        if let Some(cert) = client.device_certificate()
            && &records[1].serial[..] == cert.serial()
        {
            renewed = Some(cert);
            break;
        }
        if Instant::now() >= until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let renewed = renewed.expect("the client holds the renewed certificate");
    assert_eq!(
        span(&renewed),
        lifetime,
        "the renewal asks the stored lifetime"
    );
    assert_eq!(renewed.identity().key(), first.identity().key());
    client.close().await;
}

/// `reissue_certificate` grants the asked lifetime, and a lifetime over the
/// server's ceiling is refused without touching the held certificate.
#[test]
fn a_reissue_grants_the_asked_lifetime_and_refuses_over_the_ceiling() {
    run_phase("reissue");
}

async fn reissue() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let config = DeviceCertConfig::new(issuer())
        .with_default_lifetime(Duration::from_secs(30))
        .with_lifetime_ceiling(Duration::from_secs(60));
    let (addr, _server) = sync_server(&fixture, &service, config, Arc::clone(&store)).await;
    let dir = tempdir().expect("a data directory");

    let client = signed_in(
        addr,
        fresh_login(&base, APP_REISSUE, "enrol-user"),
        dir.path(),
    )
    .connect()
    .await
    .expect("the signed-in build connects");

    let first = wait_for_certificate(&client, BOUND)
        .await
        .expect("the enrolment grants");
    assert_eq!(
        span(&first),
        Duration::from_secs(30),
        "without a builder lifetime the server default is granted"
    );

    match client.reissue_certificate(Duration::from_secs(120)).await {
        Err(CertificateError::OverCeiling { ceiling }) => {
            assert_eq!(ceiling, Duration::from_secs(60));
        }
        other => panic!("the over-ceiling reissue is refused, got {other:?}"),
    }
    assert_eq!(
        client.device_certificate().expect("still held").serial(),
        first.serial(),
        "the refusal leaves the held certificate"
    );

    client
        .reissue_certificate(Duration::from_secs(45))
        .await
        .expect("under the ceiling");
    let reissued = client.device_certificate().expect("the reissue stores");
    assert_ne!(
        reissued.serial(),
        first.serial(),
        "a new certificate is issued"
    );
    assert_eq!(
        span(&reissued),
        Duration::from_secs(45),
        "the asked lifetime is granted"
    );
    let records = wait_for_records(&store, 2, BOUND)
        .await
        .expect("the reissue records");
    assert!(
        records
            .iter()
            .any(|record| &record.serial[..] == reissued.serial()),
        "the server recorded the reissued serial"
    );
    client.close().await;
}

/// A builder lifetime over the ceiling enrols at the ceiling and says so with
/// one typed event, which the application saw before the certificate landed.
#[test]
fn a_builder_lifetime_over_the_ceiling_enrols_at_the_ceiling_and_says_so() {
    run_phase("cap");
}

async fn cap() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let config = DeviceCertConfig::new(issuer())
        .with_default_lifetime(Duration::from_secs(3600))
        .with_lifetime_ceiling(Duration::from_secs(3600));
    let (addr, _server) = sync_server(&fixture, &service, config, Arc::clone(&store)).await;
    let dir = tempdir().expect("a data directory");
    let requested = Duration::from_hours(24);

    let (client, pump) = signed_in(addr, fresh_login(&base, APP_CAP, "enrol-user"), dir.path())
        .with_certificate_lifetime(requested)
        .connect_with_pump()
        .await
        .expect("the signed-in build connects");
    let mut events = client.client().events();
    tokio::spawn(pump);

    match next_event(&mut events, BOUND, |event| {
        matches!(event, ClientEvent::CertificateLifetimeCapped { .. })
    })
    .await
    {
        Some(ClientEvent::CertificateLifetimeCapped {
            requested: got,
            ceiling,
        }) => {
            assert_eq!(got, requested);
            assert_eq!(ceiling, Duration::from_secs(3600));
        }
        other => panic!("the cap is stated on the event stream, got {other:?}"),
    }
    let cert = wait_for_certificate(&client, BOUND)
        .await
        .expect("the ceiling grant lands");
    assert_eq!(
        span(&cert),
        Duration::from_secs(3600),
        "the renewal retries at the ceiling"
    );
    let records = wait_for_records(&store, 1, BOUND)
        .await
        .expect("the record lands");
    assert_eq!(records.len(), 1, "the refusal records nothing");
    client.close().await;
}

/// A revoked key is refused as revoked, the device deletes itself and says so,
/// and the next build re-enrols under a fresh key the server records.
#[test]
fn a_revoked_key_is_refused_and_the_next_build_enrols_fresh() {
    run_phase("revoke");
}

async fn revoke() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (addr, _server) = sync_server(
        &fixture,
        &service,
        DeviceCertConfig::new(issuer()),
        Arc::clone(&store),
    )
    .await;
    let dir = tempdir().expect("a data directory");

    let client = signed_in(
        addr,
        fresh_login(&base, APP_REVOKE, "enrol-user"),
        dir.path(),
    )
    .connect()
    .await
    .expect("the signed-in build connects");

    let first = wait_for_certificate(&client, BOUND)
        .await
        .expect("the enrolment grants");
    let key = first.identity().key();
    store.revoke_key(key);

    let mut events = client.client().events();
    assert!(
        matches!(
            client.reissue_certificate(Duration::from_secs(3600)).await,
            Err(CertificateError::Revoked)
        ),
        "the revoked key is refused as revoked"
    );
    assert!(
        client.device_certificate().is_none(),
        "the certificate is gone"
    );
    assert!(
        matches!(
            next_event(&mut events, BOUND, |event| matches!(
                event,
                ClientEvent::DeviceRevoked
            ))
            .await,
            Some(ClientEvent::DeviceRevoked)
        ),
        "the device says it was revoked"
    );

    let session = client
        .session()
        .expect("a provider build reports its session");
    let record = device_record(session.user_id());
    let keys = KeyringStore::new(APP_REVOKE);
    assert!(
        keys.load(&record).await.expect("keyring read").is_none(),
        "the key record is gone"
    );
    client.close().await;

    let second =
        NativeClientBuilder::new(format!("ws://{addr}/"), super::support::bundle(SQLITE_DDL))
            .signed_in(last_used(&base, APP_REVOKE))
            .durable(dir.path())
            .connect()
            .await
            .expect("the second build signs back in and connects");
    let second_cert = wait_for_certificate(&second, BOUND)
        .await
        .expect("the fresh key enrols");
    assert_ne!(
        second_cert.identity().key(),
        key,
        "the next open made a different key"
    );
    let records = wait_for_records(&store, 2, BOUND)
        .await
        .expect("the fresh enrolment records");
    assert_eq!(records[1].key, second_cert.identity().key());
    assert_eq!(&records[1].serial[..], second_cert.serial());
    second.close().await;
}

/// A server without enrolment installed still syncs the client, which stays a
/// spectator to certificates and is told the issuer is unavailable.
#[test]
fn a_server_without_enrolment_stays_a_spectator() {
    run_phase("spectator");
}

async fn spectator() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let (addr, _server) = spawn_server(manager(&fixture, &service)).await;
    let dir = tempdir().expect("a data directory");

    let (client, pump) = signed_in(addr, fresh_login(&base, APP_NONE, "enrol-user"), dir.path())
        .connect_with_pump()
        .await
        .expect("the signed-in build connects");
    let mut events = client.client().events();
    tokio::spawn(pump);

    assert!(
        matches!(
            next_event(&mut events, BOUND, |event| matches!(
                event,
                ClientEvent::SyncStatus(SyncStatus::Connected)
            ))
            .await,
            Some(ClientEvent::SyncStatus(SyncStatus::Connected))
        ),
        "the build syncs"
    );
    assert!(client.device_certificate().is_none());
    assert!(
        matches!(
            client.reissue_certificate(Duration::from_secs(3600)).await,
            Err(CertificateError::Refused(EnrolRefusal::IssuerUnavailable))
        ),
        "no issuer is named to the reissue"
    );
    assert!(client.device_certificate().is_none());
    client.close().await;
}

/// A second build over the same directory and keyring signs back in and
/// picks up the stored certificate, which it does not re-enrol.
#[test]
fn a_restarted_build_sees_its_certificate_before_the_connect() {
    run_phase("restart");
}

async fn restart() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (addr, _server) = sync_server(
        &fixture,
        &service,
        DeviceCertConfig::new(issuer()),
        Arc::clone(&store),
    )
    .await;
    let dir = tempdir().expect("a data directory");

    let client = signed_in(
        addr,
        fresh_login(&base, APP_RESTART, "enrol-user"),
        dir.path(),
    )
    .connect()
    .await
    .expect("the signed-in build connects");
    let first = wait_for_certificate(&client, BOUND)
        .await
        .expect("the enrolment grants");
    client.close().await;
    // A second build over the same dir and keyring signs back in silently
    // and picks up the stored certificate, which it does not re-enrol.
    let (second, pump) = signed_in(addr, last_used(&base, APP_RESTART), dir.path())
        .connect_with_pump()
        .await
        .expect("the second build signs back in and connects");
    let restarted = second
        .device_certificate()
        .expect("the stored certificate is held before the pump runs");
    tokio::spawn(pump);
    assert_eq!(
        restarted.serial(),
        first.serial(),
        "the same serial is held"
    );
    assert_eq!(
        restarted.identity().key(),
        first.identity().key(),
        "the same key is held"
    );
    let records = wait_for_records(&store, 1, BOUND)
        .await
        .expect("the record is held");
    assert_eq!(records.len(), 1, "the restart re-enrols nothing");
    second.close().await;
}

/// A build whose server is unreachable refuses the reissue as offline and
/// holds no certificate.
#[test]
fn an_offline_build_refuses_the_reissue_as_offline() {
    run_phase("offline");
}

async fn offline() {
    let (base, _service, _idp) = spawn_auth().await;
    let dir = tempdir().expect("a data directory");

    let client = NativeClientBuilder::new("ws://127.0.0.1:1/", super::support::bundle(SQLITE_DDL))
        .signed_in(fresh_login(&base, APP_OFFLINE, "enrol-user"))
        .durable(dir.path())
        .connect()
        .await
        .expect("the build opens offline");

    assert!(client.device_certificate().is_none());
    assert!(
        matches!(
            client.reissue_certificate(Duration::from_secs(3600)).await,
            Err(CertificateError::Offline)
        ),
        "the reissue is refused as offline"
    );
    client.close().await;
}

/// `forget_device` wipes the replica and deletes the device key record.
#[test]
fn a_forget_deletes_the_device_key_record() {
    run_phase("forget");
}

async fn forget() {
    let fixture = Fixture::acquire().await;
    let (base, service, _idp) = spawn_auth().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (addr, _server) = sync_server(
        &fixture,
        &service,
        DeviceCertConfig::new(issuer()),
        Arc::clone(&store),
    )
    .await;
    let dir = tempdir().expect("a data directory");

    let client = signed_in(
        addr,
        fresh_login(&base, APP_FORGET, "enrol-user"),
        dir.path(),
    )
    .connect()
    .await
    .expect("the signed-in build connects");

    wait_for_certificate(&client, BOUND)
        .await
        .expect("the enrolment grants");
    let session = client
        .session()
        .expect("a provider build reports its session");
    let record = device_record(session.user_id());
    let keys = KeyringStore::new(APP_FORGET);
    assert!(
        keys.load(&record).await.expect("keyring read").is_some(),
        "the key is stored"
    );

    client
        .forget_device(true)
        .await
        .expect("the device is forgotten");
    assert!(
        keys.load(&record).await.expect("keyring read").is_none(),
        "the key record is gone"
    );
}
