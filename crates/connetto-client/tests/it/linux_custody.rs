//! R71: what one process writes to a durable Linux store, a fresh process with
//! a fresh session keyring reads back, and a wipe leaves nothing behind.
//!
//! Each run spawns this test binary twice or more, once per phase, so nothing
//! held in memory or in keyutils survives between writer and reader.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ContentPlace, Gate, Grant, HeldCredential,
    KeyFile, KeyringKeyStore, KeyringStore, LinuxStore, Located, ReplicaPlace, SyncSchema,
    provision_replica_key, teardown,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{RefreshTokenStore as _, ReplicaKeyStore as _};
use diesel::prelude::*;

const PHASE: &str = "CONNETTO_R71_PHASE";
const DIR: &str = "CONNETTO_R71_DIR";
const KEY_FILE: &str = "CONNETTO_R71_KEY_FILE";
/// Set by `scripts/linux-secret-store-tests.sh secret-service` once a private bus with an unlocked keyring is up.
const PRIVATE_BUS: &str = "CONNETTO_R71_PRIVATE_BUS";
/// Names the Secret Service explicitly instead of detecting it.
const NAMED_SECRET_SERVICE: &str = "CONNETTO_R71_NAMED_SECRET_SERVICE";
const SERVICE: &str = "connetto-r71-custody";
const ACCOUNT: &str = "\"alice\"";
const TOKEN: &str = "alice-refresh";
const NOTE: &str = "connetto-r71-tier-note";
const TIER_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    /// A device-local tier table.
    notes (id) {
        /// Note identifier.
        id -> Integer,
        /// Note content.
        body -> Nullable<Text>,
    }
}

fn stores() -> (KeyringStore, KeyringKeyStore) {
    match std::env::var_os(KEY_FILE) {
        Some(key) => {
            let state = PathBuf::from(std::env::var_os(DIR).expect("dir")).join("state");
            let store = LinuxStore::KeyFile(KeyFile::new(key, state));
            (
                KeyringStore::with_linux_store(SERVICE, store.clone()),
                KeyringKeyStore::with_linux_store(SERVICE, store),
            )
        }
        None if std::env::var_os(NAMED_SECRET_SERVICE).is_some() => (
            KeyringStore::with_linux_store(SERVICE, LinuxStore::SecretService),
            KeyringKeyStore::with_linux_store(SERVICE, LinuxStore::SecretService),
        ),
        None => (KeyringStore::new(SERVICE), KeyringKeyStore::new(SERVICE)),
    }
}

fn replica_url(dir: &Path) -> String {
    dir.join("replica.sqlite")
        .to_str()
        .expect("utf-8 path")
        .to_owned()
}

/// The replica at exactly `url`, its key recorded as `replica`, where the
/// custody phases look for it.
struct At {
    url: String,
    exists: bool,
}

impl ReplicaPlace for At {
    fn locate(&self, _name: &str) -> Result<Located, ClientError> {
        Ok(Located::new(
            "replica",
            self.url.clone(),
            self.exists,
            ContentPlace::InMemory,
        ))
    }
}

/// The replica at `url` beside its device-local tier, created when `fresh`,
/// with its key read from this phase's key store.
async fn open(url: &str, fresh: bool) -> ConnettoConnection<FakeTransport> {
    let transport = FakeTransport::accepting();
    let mut once = Some(transport);
    ClientBuilder::new(
        SyncSchema::new(SchemaBundle::new(
            "",
            "",
            "",
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            Some(TIER_DDL),
        )),
        move || core::future::ready(once.take().ok_or("spent")),
    )
    .signed_in(
        HeldCredential::new(Grant::new("user:token"), "token")
            .expect("a string identity serializes"),
    )
    .durable(
        At {
            url: url.to_owned(),
            exists: !fresh,
        },
        stores().1,
    )
    .with_gate(Gate::off())
    .connect_driven()
    .await
    .expect("the replica opens")
}

/// One phase of a multi-process run, chosen by the environment. Run alone it does nothing.
#[tokio::test]
#[ignore = "a phase the custody tests run in a child process"]
async fn custody_phase() {
    let Ok(phase) = std::env::var(PHASE) else {
        return;
    };
    let dir = PathBuf::from(std::env::var_os(DIR).expect("dir"));
    let _keyring = connetto_test_harness::isolated_session_keyring();
    if let Some(credentials) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        let entries: Vec<_> = std::fs::read_dir(credentials)
            .expect("list the credentials")
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only connetto.wrap-key sits in the credentials directory"
        );
    }
    let (tokens, keys) = stores();
    let url = replica_url(&dir);
    match phase.as_str() {
        "write" => write_phase(&tokens, &keys, &url).await,
        "read" => read_phase(&tokens, &keys, &url).await,
        "wipe" => wipe_phase(&tokens, &keys, &url).await,
        "empty" => empty_phase(&tokens, &keys).await,
        "stored-as-text" => stored_as_text_phase(&tokens).await,
        other => panic!("unknown phase {other}"),
    }
}

async fn write_phase(tokens: &KeyringStore, keys: &KeyringKeyStore, url: &str) {
    provision_replica_key(keys, "replica")
        .await
        .expect("provision");
    tokens.store(ACCOUNT, TOKEN).await.expect("store the token");
    let mut conn = open(url, true).await;
    diesel::insert_into(notes::table)
        .values((notes::id.eq(1), notes::body.eq(NOTE)))
        .execute(conn.conn())
        .expect("write the tier");
}

async fn read_phase(tokens: &KeyringStore, keys: &KeyringKeyStore, url: &str) {
    let backend = tokens.backend().await.expect("the store opens");
    assert!(backend.survives_reboot(), "{backend:?}");
    keys.load("replica")
        .await
        .expect("load")
        .expect("the key survived, so nothing is re-minted");
    assert_eq!(
        tokens.load(ACCOUNT).await.expect("load").as_deref(),
        Some(TOKEN)
    );
    assert_eq!(tokens.accounts().await.expect("accounts"), [ACCOUNT]);
    let mut conn = open(url, false).await;
    let rows: Vec<Option<String>> = notes::table
        .select(notes::body)
        .load(conn.conn())
        .expect("read the tier");
    assert_eq!(rows, [Some(NOTE.to_owned())]);
}

async fn wipe_phase(tokens: &KeyringStore, keys: &KeyringKeyStore, url: &str) {
    teardown::wipe_replica(Path::new(url), keys, "replica", &[], false)
        .await
        .expect("wipe");
    tokens.clear(ACCOUNT).await.expect("log out");
}

async fn empty_phase(tokens: &KeyringStore, keys: &KeyringKeyStore) {
    assert_eq!(
        keys.load("replica").await.expect("load"),
        None,
        "the key is gone"
    );
    assert_eq!(
        tokens.load(ACCOUNT).await.expect("load"),
        None,
        "the token is gone"
    );
    assert!(
        tokens.accounts().await.expect("accounts").is_empty(),
        "the index is gone"
    );
}

async fn stored_as_text_phase(tokens: &KeyringStore) {
    let service = oo7::dbus::Service::new().await.expect("the Secret Service");
    let collection = service
        .default_collection()
        .await
        .expect("the default collection");
    let items = collection
        .search_items(&[("service", SERVICE), ("record", ACCOUNT)])
        .await
        .expect("search");
    let secret = items
        .first()
        .expect("the token item")
        .secret()
        .await
        .expect("secret");
    assert_eq!(secret.content_type(), oo7::ContentType::Text);
    assert_eq!(
        &*secret, b"YWxpY2UtcmVmcmVzaA==",
        "the item holds base64 text"
    );
    collection
        .create_item(
            SERVICE,
            &[("service", SERVICE), ("record", "corrupt")],
            oo7::Secret::text("not base64!"),
            true,
            None,
        )
        .await
        .expect("plant a value connetto never writes");
    let err = tokens
        .load("corrupt")
        .await
        .expect_err("a value that is not base64 refuses");
    assert!(
        matches!(
            err,
            connetto_client::ClientError::SecretStore(connetto_client::SecretStoreError::Encoding)
        ),
        "got {err}"
    );
    tokens
        .clear("corrupt")
        .await
        .expect("remove the planted value");
}

fn run_phase(phase: &str, dir: &Path, env: &[(&str, OsString)]) {
    let status = Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "linux_custody::custody_phase",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env(PHASE, phase)
        .env(DIR, dir)
        .env_remove("CREDENTIALS_DIRECTORY")
        .env_remove("STATE_DIRECTORY")
        .envs(env.iter().map(|(name, value)| (name, value)))
        .status()
        .expect("spawn the phase");
    assert!(status.success(), "the {phase} phase failed");
}

fn round_trip(dir: &Path, env: &[(&str, OsString)]) {
    for phase in ["write", "read", "wipe", "empty"] {
        run_phase(phase, dir, env);
    }
}

fn records(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.expect("entry").path())
                .filter(|path| path.file_name().is_some_and(|name| name.len() == 64))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_fresh_process_reads_what_another_wrote_under_the_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let credentials = dir.path().join("credentials");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&credentials).expect("credentials");
    std::fs::create_dir_all(&state).expect("state");
    std::fs::write(credentials.join("connetto.wrap-key"), [4_u8; 32]).expect("credential");
    let env = [
        (
            "CREDENTIALS_DIRECTORY",
            credentials.clone().into_os_string(),
        ),
        ("STATE_DIRECTORY", state.clone().into_os_string()),
    ];
    for phase in ["write", "read"] {
        run_phase(phase, dir.path(), &env);
    }
    let sealed = records(&state.join("connetto-secrets"));
    assert_eq!(sealed.len(), 3, "the key, the token and the account index");
    for record in &sealed {
        let mode = std::fs::metadata(record)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{}", record.display());
    }
    let credential_files: Vec<_> = std::fs::read_dir(&credentials).expect("list").collect();
    assert_eq!(
        credential_files.len(),
        1,
        "nothing is written beside the credential"
    );
    for phase in ["wipe", "empty"] {
        run_phase(phase, dir.path(), &env);
    }
    assert!(
        records(&state.join("connetto-secrets")).is_empty(),
        "the wipe left no record file"
    );
}

#[test]
fn a_fresh_process_reads_what_another_wrote_under_a_named_key_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("wrap.key");
    std::fs::write(&key, [6_u8; 32]).expect("key file");
    round_trip(dir.path(), &[(KEY_FILE, key.into_os_string())]);
}

/// Needs a private session bus with an unlocked `gnome-keyring-daemon`, which
/// `scripts/linux-secret-store-tests.sh secret-service` sets up.
#[test]
#[ignore = "needs the private Secret Service bus scripts/linux-secret-store-tests.sh secret-service starts"]
fn a_fresh_process_reads_what_another_wrote_under_the_secret_service() {
    assert!(
        std::env::var_os(PRIVATE_BUS).is_some(),
        "run under scripts/linux-secret-store-tests.sh, never against a desktop's own keyring"
    );
    let named: [(&str, OsString); 1] = [(NAMED_SECRET_SERVICE, "1".into())];
    for env in [&[][..], &named[..]] {
        let dir = tempfile::tempdir().expect("tempdir");
        for phase in ["write", "read", "stored-as-text", "wipe", "empty"] {
            run_phase(phase, dir.path(), env);
        }
    }
}

/// The command line `sudo -n` runs as root, or a refusal naming what the group needs.
fn sudo(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let output = Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("spawn sudo");
    assert!(
        output.status.success(),
        "sudo {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Runs one phase in a transient system service that systemd hands the
/// encrypted wrap key and a state directory (R71 decision 7).
fn run_unit_phase(phase: &str, dir: &Path, credential: &Path, state: &str) {
    let uid = String::from_utf8(Command::new("id").arg("-u").output().expect("id").stdout)
        .expect("utf-8");
    let exe = std::env::current_exe().expect("the test binary");
    let args: Vec<OsString> = vec![
        "systemd-run".into(),
        "--wait".into(),
        "--pipe".into(),
        "--collect".into(),
        "--quiet".into(),
        format!("--uid={}", uid.trim()).into(),
        format!("--property=StateDirectory={state}").into(),
        {
            let mut property =
                OsString::from("--property=LoadCredentialEncrypted=connetto.wrap-key:");
            property.push(credential);
            property
        },
        format!("--setenv={PHASE}={phase}").into(),
        {
            let mut setenv = OsString::from(format!("--setenv={DIR}="));
            setenv.push(dir);
            setenv
        },
        exe.into_os_string(),
        "linux_custody::custody_phase".into(),
        "--exact".into(),
        "--ignored".into(),
        "--nocapture".into(),
    ];
    let args: Vec<&std::ffi::OsStr> = args.iter().map(OsString::as_os_str).collect();
    sudo(&args);
}

/// A transient service writes and a second one reads back, with systemd
/// decrypting the credential and creating the state directory.
#[test]
#[ignore = "needs passwordless sudo and systemd, which the CI runner has"]
fn a_second_transient_service_reads_what_the_first_wrote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("wrap.key");
    std::fs::write(&key, [8_u8; 32]).expect("key");
    let credential = dir.path().join("wrap.cred");
    sudo(&[
        "systemd-creds".as_ref(),
        "encrypt".as_ref(),
        "--with-key=host".as_ref(),
        "--name=connetto.wrap-key".as_ref(),
        key.as_os_str(),
        credential.as_os_str(),
    ]);
    std::fs::remove_file(&key).expect("only the encrypted credential stays");
    let state = format!("connetto-r71-{}", std::process::id());
    for phase in ["write", "read"] {
        run_unit_phase(phase, dir.path(), &credential, &state);
    }
    let sealed = Path::new("/var/lib").join(&state).join("connetto-secrets");
    let records = records(&sealed);
    assert_eq!(records.len(), 3, "the key, the token and the account index");
    for record in &records {
        let mode = std::fs::metadata(record)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{}", record.display());
    }
    for phase in ["wipe", "empty"] {
        run_unit_phase(phase, dir.path(), &credential, &state);
    }
    sudo(&[
        "rm".as_ref(),
        "-rf".as_ref(),
        Path::new("/var/lib").join(&state).as_os_str(),
    ]);
}

/// Runs the probe in a fresh container under Docker's default seccomp
/// profile, with the wrap key mounted read-only the way Docker mounts a secret.
fn run_container_phase(probe: &Path, phase: &str, key: &Path, state: &Path) {
    let mut mount_probe = probe.as_os_str().to_owned();
    mount_probe.push(":/probe:ro");
    let mut mount_key = key.as_os_str().to_owned();
    mount_key.push(":/run/secrets/connetto-wrap-key:ro");
    let mut mount_state = state.as_os_str().to_owned();
    mount_state.push(":/state");
    let uid = String::from_utf8(Command::new("id").arg("-u").output().expect("id").stdout)
        .expect("utf-8");
    let output = Command::new("docker")
        .args(["run", "--rm", "--user", uid.trim(), "-v"])
        .arg(mount_probe)
        .arg("-v")
        .arg(mount_key)
        .arg("-v")
        .arg(mount_state)
        .args([
            "ubuntu:24.04",
            "/probe",
            phase,
            "key-file",
            "/run/secrets/connetto-wrap-key",
            "/state",
        ])
        .output()
        .expect("spawn docker");
    assert!(
        output.status.success(),
        "the {phase} container failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `CONNETTO_R71_PROBE` names the built `secret_store_probe` example.
#[test]
#[ignore = "needs Docker and the secret_store_probe example, which CI builds"]
fn a_restarted_container_reads_its_keys_back_through_a_mounted_key_file() {
    let probe = PathBuf::from(
        std::env::var_os("CONNETTO_R71_PROBE").expect("CONNETTO_R71_PROBE names the probe"),
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("wrap.key");
    std::fs::write(&key, [2_u8; 32]).expect("key");
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).expect("state");
    run_container_phase(&probe, "write", &key, &state);
    run_container_phase(&probe, "read", &key, &state);

    let short = dir.path().join("short.key");
    std::fs::write(&short, [2_u8; 31]).expect("short key");
    let mut mount_probe = probe.into_os_string();
    mount_probe.push(":/probe:ro");
    let mut mount_short = short.into_os_string();
    mount_short.push(":/run/secrets/connetto-wrap-key:ro");
    let refused = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(mount_probe)
        .arg("-v")
        .arg(mount_short)
        .args([
            "ubuntu:24.04",
            "/probe",
            "read",
            "key-file",
            "/run/secrets/connetto-wrap-key",
            "/tmp/state",
        ])
        .output()
        .expect("spawn docker");
    assert!(!refused.status.success(), "a 31-byte key is refused");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("31 bytes"),
        "the refusal names the length: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
}
