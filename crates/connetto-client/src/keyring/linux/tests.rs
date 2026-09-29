use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::sealed::{Sealed, read_wrap_key, stem};
use super::secret_service::ensure_default;
use super::{Backend, Detected, Environment, Opened, SEALED_DIR, choose, detect};
use crate::ClientError;
use crate::keyring::SecretStoreError;

const CURRENT: [u8; 32] = [7; 32];
const PREVIOUS: [u8; 32] = [9; 32];

fn sealed(dir: &Path, current: &[u8; 32], previous: Option<&[u8; 32]>) -> Sealed {
    Sealed::open(dir.to_owned(), current, previous).expect("open the sealed store")
}

fn records(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut found: Vec<_> = std::fs::read_dir(dir)
        .expect("list the state directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.file_name().is_some_and(|name| name.len() == 64))
        .collect();
    found.sort();
    found
}

fn is_unsealable(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::SecretStore(SecretStoreError::Unsealable { .. })
    )
}

#[test]
fn a_second_open_reads_what_the_first_wrote_and_two_services_stay_apart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = sealed(dir.path(), &CURRENT, None);
    first
        .write("tokens", "\"alice\"", b"alice-refresh")
        .expect("write alice");
    first
        .write("keys", "\"alice\"", b"alice-key")
        .expect("write alice's key");
    drop(first);

    let second = sealed(dir.path(), &CURRENT, None);
    assert_eq!(
        second
            .read("tokens", "\"alice\"")
            .expect("read")
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"alice-refresh"[..])
    );
    assert_eq!(
        second
            .read("keys", "\"alice\"")
            .expect("read")
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"alice-key"[..]),
        "the same name under another service is its own record"
    );
    second.clear("tokens", "\"alice\"").expect("clear");
    assert!(second.read("tokens", "\"alice\"").expect("read").is_none());
    assert!(
        second.read("keys", "\"alice\"").expect("read").is_some(),
        "the clear stayed in its service"
    );
}

#[test]
fn a_record_holds_no_secret_bytes_and_every_file_is_private() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = sealed(dir.path(), &CURRENT, None);
    store
        .write("keys", "replica", b"0123456789abcdef-key-material")
        .expect("write");
    let files = records(dir.path());
    assert_eq!(files.len(), 1, "one record and no temporary left behind");
    let blob = std::fs::read(&files[0]).expect("read the record");
    assert!(
        !blob
            .windows(b"key-material".len())
            .any(|window| window == b"key-material"),
        "the record holds ciphertext only"
    );
    let mode = std::fs::metadata(&files[0])
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(dir.path())
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode & 0o077,
        0,
        "the state directory is closed to others, got {dir_mode:o}"
    );
    assert!(
        !std::fs::read_dir(dir.path())
            .expect("list")
            .any(|entry| entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")),
        "the write renamed its temporary into place"
    );
}

#[test]
fn a_tampered_swapped_or_wrongly_keyed_record_refuses_and_nothing_is_minted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = sealed(dir.path(), &CURRENT, None);
    store
        .write("keys", "alice", b"alice-key")
        .expect("write alice");
    store.write("keys", "bob", b"bob-key").expect("write bob");
    let before = records(dir.path());
    assert_eq!(before.len(), 2);

    let wrong = sealed(dir.path(), &PREVIOUS, None);
    let err = wrong
        .read("keys", "alice")
        .expect_err("a wrong key refuses");
    assert!(is_unsealable(&err), "got {err}");
    assert_eq!(records(dir.path()), before, "the refusal wrote nothing");

    let alice = dir.path().join(stem("keys", "alice"));
    let bob = dir.path().join(stem("keys", "bob"));
    std::fs::copy(&alice, &bob).expect("rename alice's record onto bob's name");
    let err = store
        .read("keys", "bob")
        .expect_err("a swapped record refuses");
    assert!(is_unsealable(&err), "got {err}");

    let mut tampered = std::fs::read(&alice).expect("read alice");
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    std::fs::write(&alice, tampered).expect("flip a byte");
    let err = store
        .read("keys", "alice")
        .expect_err("a flipped byte refuses");
    assert!(is_unsealable(&err), "got {err}");
}

#[test]
fn a_rotated_key_reseals_once_and_leaves_current_records_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let old = sealed(dir.path(), &PREVIOUS, None);
    old.write("keys", "rotated", b"rotated-secret")
        .expect("write under the old key");
    old.write("keys", "interrupted", b"interrupted-secret")
        .expect("write under the old key");
    drop(old);
    let current = sealed(dir.path(), &CURRENT, None);
    current
        .write("keys", "fresh", b"fresh-secret")
        .expect("write under the new key");
    drop(current);
    let fresh_path = dir.path().join(stem("keys", "fresh"));
    let fresh_before = std::fs::read(&fresh_path).expect("read fresh");
    // A crash between the temporary write and the rename leaves both files.
    std::fs::write(
        dir.path().join(format!("{}.tmp-deadbeef", "0".repeat(64))),
        b"partial",
    )
    .expect("stale temporary");

    let rotating = sealed(dir.path(), &CURRENT, Some(&PREVIOUS));
    assert!(!rotating.previous_key_needed(), "every record resealed");
    assert_eq!(
        std::fs::read(&fresh_path).expect("read fresh"),
        fresh_before,
        "a current record is left byte for byte"
    );
    drop(rotating);

    let after = sealed(dir.path(), &CURRENT, None);
    for (name, secret) in [
        ("rotated", &b"rotated-secret"[..]),
        ("interrupted", &b"interrupted-secret"[..]),
        ("fresh", &b"fresh-secret"[..]),
    ] {
        assert_eq!(
            after
                .read("keys", name)
                .expect("opens without the previous key")
                .as_deref()
                .map(Vec::as_slice),
            Some(secret),
            "{name} opens under the current key alone"
        );
    }
    assert!(
        !std::fs::read_dir(dir.path())
            .expect("list")
            .any(|entry| entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")),
        "the stale temporary is gone"
    );
}

#[test]
fn a_wrap_key_of_any_other_length_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wrap.key");
    std::fs::write(&path, [1_u8; 31]).expect("write a short key");
    let err = read_wrap_key(&path).expect_err("31 bytes refuse");
    assert!(
        matches!(
            err,
            ClientError::SecretStore(SecretStoreError::WrapKeyLength { len: 31, .. })
        ),
        "got {err}"
    );
    std::fs::write(&path, [1_u8; 32]).expect("write a full key");
    assert!(read_wrap_key(&path).is_ok());
}

fn environment(sandboxed: bool, credentials: Option<&Path>, state: Option<&Path>) -> Environment {
    Environment {
        sandboxed,
        credentials: credentials.map(Path::to_owned),
        state: state.map(Path::to_owned),
    }
}

#[tokio::test]
async fn detection_prefers_the_sandbox_then_a_credential_then_the_secret_service() {
    let credentials = tempfile::tempdir().expect("credentials");
    std::fs::write(credentials.path().join(super::CREDENTIAL), CURRENT).expect("credential");
    let state = tempfile::tempdir().expect("state");
    let with_credential = environment(false, Some(credentials.path()), Some(state.path()));

    let (fake, bus) = FakeSecretService::start(Answer::Never).await;
    assert!(matches!(
        choose(
            &environment(true, Some(credentials.path()), None),
            Some(bus.clone())
        ),
        Ok(Detected::Sandbox)
    ));
    assert!(matches!(
        choose(&with_credential, Some(bus.clone())),
        Ok(Detected::Credential(_))
    ));
    assert!(
        matches!(
            choose(
                &environment(false, Some(state.path()), None),
                Some(bus.clone())
            ),
            Ok(Detected::SecretService(_))
        ),
        "a credentials directory without connetto's credential is not a credential"
    );

    let opened = detect(&with_credential, Some(bus))
        .await
        .expect("the credential opens");
    assert!(matches!(
        opened,
        Opened::Sealed {
            credential: true,
            ..
        }
    ));
    assert!(
        fake.calls().is_empty(),
        "a credential wins over the Secret Service"
    );
    assert!(state.path().join(SEALED_DIR).is_dir());

    let err = detect(&environment(false, None, None), None)
        .await
        .err()
        .expect("nothing is reachable");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::NoStore { probed }) if probed.contains("sandbox") && probed.contains("credential") && probed.contains("Secret Service")),
        "the refusal names what it probed"
    );
}

#[tokio::test]
async fn detection_with_only_the_secret_service_goes_through_its_unlock() {
    let (fake, bus) = FakeSecretService::start(Answer::Dismiss).await;
    let err = detect(&environment(false, None, None), Some(bus))
        .await
        .err()
        .expect("the fake's dialog is dismissed");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::Dismissed)),
        "got {err}"
    );
    assert_eq!(fake.calls(), ["ReadAlias", "Unlock", "Prompt"]);
}

#[tokio::test]
async fn a_credential_with_no_state_directory_refuses() {
    let credentials = tempfile::tempdir().expect("credentials");
    std::fs::write(credentials.path().join(super::CREDENTIAL), CURRENT).expect("credential");
    let err = detect(&environment(false, Some(credentials.path()), None), None)
        .await
        .err()
        .expect("a unit with no StateDirectory= refuses");
    assert!(err.to_string().contains("StateDirectory"), "got {err}");
}

#[test]
fn only_keyutils_is_lost_at_reboot() {
    for backend in [
        Backend::SecretService,
        Backend::SandboxKeyring,
        Backend::SystemdCredential {
            previous_key_needed: false,
        },
        Backend::KeyFile {
            previous_key_needed: true,
        },
    ] {
        assert!(backend.survives_reboot(), "{backend:?}");
    }
    assert!(!Backend::Keyutils.survives_reboot());
}

#[derive(Clone, Copy, Debug)]
enum Answer {
    /// The service creates or unlocks at once and hands back no prompt.
    Immediate,
    /// The service drops the connection after showing the prompt, as a crashed daemon does.
    Hangup,
    Never,
    Dismiss,
    Complete,
}

const COLLECTION: &str = "/org/freedesktop/secrets/collection/login";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/p1";

struct FakeState {
    answer: Answer,
    alias: Option<OwnedObjectPath>,
    locked: bool,
    calls: Vec<String>,
}

#[derive(Clone)]
struct FakeSecretService {
    state: Arc<Mutex<FakeState>>,
}

impl FakeSecretService {
    /// A fake whose default collection exists, locked, on a private peer-to-peer bus.
    async fn start(answer: Answer) -> (Self, zbus::Connection) {
        Self::start_with(answer, true).await
    }

    async fn start_with(answer: Answer, has_default: bool) -> (Self, zbus::Connection) {
        let fake = Self {
            state: Arc::new(Mutex::new(FakeState {
                answer,
                alias: has_default.then(|| OwnedObjectPath::try_from(COLLECTION).expect("path")),
                locked: true,
                calls: Vec::new(),
            })),
        };
        let (server, client) = tokio::net::UnixStream::pair().expect("socket pair");
        let guid = zbus::Guid::generate();
        let server = zbus::connection::Builder::unix_stream(server)
            .server(guid)
            .expect("server")
            .p2p()
            .serve_at("/org/freedesktop/secrets", Service(fake.clone()))
            .expect("serve the service")
            .serve_at(COLLECTION, Collection(fake.clone()))
            .expect("serve the collection")
            .serve_at(PROMPT, Prompt(fake.clone()))
            .expect("serve the prompt")
            .build();
        let client = zbus::connection::Builder::unix_stream(client).p2p().build();
        let (server, client) = tokio::join!(server, client);
        // The server connection lives as long as the test by leaking into a background task.
        let server = server.expect("server connection");
        tokio::spawn(async move {
            let _server = server;
            std::future::pending::<()>().await;
        });
        (fake, client.expect("client connection"))
    }

    fn calls(&self) -> Vec<String> {
        self.state.lock().expect("fake state").calls.clone()
    }

    fn record(&self, call: &str) {
        self.state
            .lock()
            .expect("fake state")
            .calls
            .push(call.to_owned());
    }
}

struct Service(FakeSecretService);

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
#[expect(
    clippy::needless_pass_by_value,
    reason = "zbus hands interface arguments over owned"
)]
impl Service {
    fn read_alias(&self, name: &str) -> OwnedObjectPath {
        self.0.record("ReadAlias");
        assert_eq!(name, "default");
        self.0
            .state
            .lock()
            .expect("fake state")
            .alias
            .clone()
            .unwrap_or_else(|| OwnedObjectPath::try_from("/").expect("path"))
    }

    fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        self.0.record("CreateCollection");
        assert_eq!(alias, "default");
        let label = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|value| <&str>::try_from(value).ok().map(str::to_owned));
        assert_eq!(label.as_deref(), Some("Default keyring"));
        let mut state = self.0.state.lock().expect("fake state");
        if matches!(state.answer, Answer::Immediate) {
            let created = OwnedObjectPath::try_from(COLLECTION).expect("path");
            state.alias = Some(created.clone());
            state.locked = false;
            return (created, OwnedObjectPath::try_from("/").expect("path"));
        }
        (
            OwnedObjectPath::try_from("/").expect("path"),
            OwnedObjectPath::try_from(PROMPT).expect("path"),
        )
    }

    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.0.record("Unlock");
        assert_eq!(objects.len(), 1);
        let mut state = self.0.state.lock().expect("fake state");
        if matches!(state.answer, Answer::Immediate) {
            state.locked = false;
            return (objects, OwnedObjectPath::try_from("/").expect("path"));
        }
        (Vec::new(), OwnedObjectPath::try_from(PROMPT).expect("path"))
    }
}

struct Collection(FakeSecretService);

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.state.lock().expect("fake state").locked
    }
}

struct Prompt(FakeSecretService);

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        window_id: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) {
        self.0.record("Prompt");
        assert!(
            window_id.is_empty(),
            "connetto has no window to parent the dialog to"
        );
        let answer = self.0.state.lock().expect("fake state").answer;
        match answer {
            Answer::Immediate | Answer::Never => {}
            Answer::Hangup => {
                let connection = connection.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let _ = connection.close().await;
                });
            }
            Answer::Dismiss => {
                Self::completed(&emitter, true, Value::from(""))
                    .await
                    .expect("emit");
            }
            Answer::Complete => {
                {
                    let mut state = self.0.state.lock().expect("fake state");
                    state.locked = false;
                    state.alias = Some(OwnedObjectPath::try_from(COLLECTION).expect("path"));
                }
                let collection = zbus::zvariant::ObjectPath::try_from(COLLECTION).expect("path");
                Self::completed(&emitter, false, Value::from(collection))
                    .await
                    .expect("emit");
            }
        }
    }

    fn dismiss(&self) {
        self.0.record("Dismiss");
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

#[tokio::test]
async fn an_unanswered_unlock_is_dismissed_at_the_bound_and_refused() {
    let (fake, bus) = FakeSecretService::start(Answer::Never).await;
    let err = ensure_default(&bus, Duration::from_millis(200))
        .await
        .expect_err("an unanswered dialog refuses");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::TimedOut(_))),
        "got {err}"
    );
    assert_eq!(fake.calls(), ["ReadAlias", "Unlock", "Prompt", "Dismiss"]);
}

#[tokio::test]
async fn a_dismissed_unlock_is_refused() {
    let (fake, bus) = FakeSecretService::start(Answer::Dismiss).await;
    let err = ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect_err("a dismissed dialog refuses");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::Dismissed)),
        "got {err}"
    );
    assert!(
        !fake.calls().contains(&"Dismiss".to_owned()),
        "an answered prompt is not dismissed"
    );
}

#[tokio::test]
async fn an_answered_unlock_opens_and_a_second_call_needs_no_prompt() {
    let (fake, bus) = FakeSecretService::start(Answer::Complete).await;
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("unlocked");
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("already unlocked");
    assert_eq!(fake.calls(), ["ReadAlias", "Unlock", "Prompt", "ReadAlias"]);
}

#[tokio::test]
async fn a_missing_default_collection_is_created_through_the_prompt() {
    let (fake, bus) = FakeSecretService::start_with(Answer::Complete, false).await;
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("created");
    assert_eq!(fake.calls(), ["ReadAlias", "CreateCollection", "Prompt"]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_prompt_that_never_completes_does_not_stall_a_one_worker_runtime() {
    let (_fake, bus) = FakeSecretService::start(Answer::Never).await;
    let waiting =
        tokio::spawn(async move { ensure_default(&bus, Duration::from_millis(500)).await });
    let other = tokio::spawn(async { tokio::time::sleep(Duration::from_millis(20)).await });
    tokio::time::timeout(Duration::from_millis(300), other)
        .await
        .expect("another task ran while the prompt waited")
        .expect("the other task");
    assert!(!waiting.is_finished(), "the prompt is still waiting");
    let err = waiting
        .await
        .expect("join")
        .expect_err("refused at the bound");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::TimedOut(_))),
        "got {err}"
    );
}

#[tokio::test]
async fn the_sandbox_keyring_keeps_base64_text_a_second_open_reads_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keyrings").join("default.keyring");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("keyrings directory");
    let secret = || oo7::Secret::from(vec![5_u8; 64]);

    let first = super::sandbox::Sandbox::load(&path, secret())
        .await
        .expect("open");
    first
        .write("tokens", "\"alice\"", "alice-refresh")
        .await
        .expect("write");
    drop(first);

    let second = super::sandbox::Sandbox::load(&path, secret())
        .await
        .expect("reopen");
    assert_eq!(
        second
            .read("tokens", "\"alice\"")
            .await
            .expect("read")
            .as_deref(),
        Some("alice-refresh")
    );
    let raw = oo7::file::UnlockedKeyring::load(&path, secret())
        .await
        .expect("open the file directly")
        .lookup_item(&super::attributes("tokens", "\"alice\""))
        .await
        .expect("lookup")
        .expect("the item exists");
    let stored = raw.as_unlocked().secret();
    assert_eq!(stored.content_type(), oo7::ContentType::Text);
    assert_eq!(
        &*stored, b"YWxpY2UtcmVmcmVzaA==",
        "the item holds base64 text"
    );
    second.clear("tokens", "\"alice\"").await.expect("clear");
    assert!(
        second
            .read("tokens", "\"alice\"")
            .await
            .expect("read")
            .is_none()
    );
}

#[tokio::test]
async fn a_named_credential_that_the_unit_does_not_hand_over_refuses_naming_it() {
    let err = super::open_named(
        &super::LinuxStore::SystemdCredential,
        &environment(false, None, None),
    )
    .await
    .err()
    .expect("no credentials directory");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::NoStore { probed }) if probed.contains("connetto.wrap-key")),
        "got {err}"
    );
}

#[tokio::test]
async fn a_named_key_file_with_a_previous_key_reseals_and_reports_it_no_longer_needed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (key, previous) = (dir.path().join("wrap.key"), dir.path().join("previous.key"));
    std::fs::write(&key, CURRENT).expect("key");
    std::fs::write(&previous, PREVIOUS).expect("previous key");
    let old = sealed(&dir.path().join("state").join(SEALED_DIR), &PREVIOUS, None);
    old.write("tokens", "alice", b"alice-refresh")
        .expect("write under the old key");
    drop(old);

    let store = super::Store::named(super::LinuxStore::KeyFile(
        super::KeyFile::new(&key, dir.path().join("state")).with_previous(&previous),
    ));
    assert_eq!(
        store.backend().await.expect("opens"),
        Backend::KeyFile {
            previous_key_needed: false
        }
    );
    std::fs::remove_file(&previous).expect("retire the previous key");
    let reopened = super::Store::named(super::LinuxStore::KeyFile(super::KeyFile::new(
        &key,
        dir.path().join("state"),
    )));
    assert_eq!(
        reopened
            .read("tokens", "alice")
            .await
            .expect("read")
            .as_deref(),
        Some("alice-refresh")
    );
}

#[tokio::test]
async fn a_service_that_unlocks_without_a_prompt_needs_no_dialog() {
    let (fake, bus) = FakeSecretService::start(Answer::Immediate).await;
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("unlocked at once");
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("already unlocked");
    assert_eq!(fake.calls(), ["ReadAlias", "Unlock", "ReadAlias"]);
}

#[tokio::test]
async fn a_service_that_creates_the_default_without_a_prompt_needs_no_dialog() {
    let (fake, bus) = FakeSecretService::start_with(Answer::Immediate, false).await;
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("created at once");
    ensure_default(&bus, Duration::from_secs(5))
        .await
        .expect("found the second time");
    assert_eq!(fake.calls(), ["ReadAlias", "CreateCollection", "ReadAlias"]);
}

#[test]
fn a_truncated_record_refuses_rather_than_minting_or_panicking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = sealed(dir.path(), &CURRENT, Some(&PREVIOUS));
    store.write("keys", "alice", b"alice-key").expect("write");
    let path = dir.path().join(stem("keys", "alice"));
    let whole = std::fs::read(&path).expect("read");
    // Empty, shorter than the header, and cut inside the nonce.
    for length in [0, 3, 5 + 10] {
        std::fs::write(&path, &whole[..length]).expect("truncate");
        let err = store
            .read("keys", "alice")
            .expect_err("a truncated record refuses");
        assert!(is_unsealable(&err), "length {length}: got {err}");
    }
}

#[test]
fn the_sandbox_keyring_lives_where_libsecret_puts_it() {
    use std::ffi::OsString;
    let path = |xdg: Option<&str>, home: Option<&str>| {
        super::sandbox::keyring_path_from(xdg.map(OsString::from), home.map(OsString::from))
    };
    assert_eq!(
        path(Some("/data"), Some("/home/app")),
        Some("/data/keyrings/default.keyring".into())
    );
    for ignored in [Some(""), Some("relative/data"), None] {
        assert_eq!(
            path(ignored, Some("/home/app")),
            Some("/home/app/.local/share/keyrings/default.keyring".into()),
            "XDG_DATA_HOME {ignored:?} falls back to HOME"
        );
    }
    assert_eq!(path(None, Some("")), None);
    assert_eq!(path(None, None), None);
}

/// A private session bus, stopped on drop.
struct PrivateBus {
    daemon: std::process::Child,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        use std::io::BufRead as _;
        let mut daemon = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start dbus-daemon");
        let mut address = String::new();
        std::io::BufReader::new(daemon.stdout.take().expect("daemon stdout"))
            .read_line(&mut address)
            .expect("read the bus address");
        Self {
            daemon,
            address: address.trim().to_owned(),
        }
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("bus address")
            .build()
            .await
            .expect("connect to the private bus")
    }

    /// Serves a fake Secret portal that answers with `secret`, or never answers.
    async fn serve_portal(&self, secret: Option<Vec<u8>>) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .expect("bus address")
            .name("org.freedesktop.portal.Desktop")
            .expect("portal name")
            .serve_at("/org/freedesktop/portal/desktop", FakePortal { secret })
            .expect("serve the portal")
            .build()
            .await
            .expect("portal connection")
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

struct FakePortal {
    secret: Option<Vec<u8>>,
}

#[zbus::interface(name = "org.freedesktop.portal.Secret")]
impl FakePortal {
    async fn retrieve_secret(
        &self,
        fd: zbus::zvariant::OwnedFd,
        options: HashMap<String, OwnedValue>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> OwnedObjectPath {
        use std::io::Write as _;
        let token = options
            .get("handle_token")
            .and_then(|value| <&str>::try_from(value).ok())
            .expect("a handle token")
            .to_owned();
        let sender = header.sender().expect("a sender").to_owned();
        let request = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/portal/desktop/request/{}/{token}",
            sender.trim_start_matches(':').replace('.', "_")
        ))
        .expect("request path");
        if let Some(secret) = &self.secret {
            std::fs::File::from(std::os::fd::OwnedFd::from(fd))
                .write_all(secret)
                .expect("hand the secret over");
            connection
                .emit_signal(
                    Some(zbus::names::BusName::from(sender.clone())),
                    &request,
                    "org.freedesktop.portal.Request",
                    "Response",
                    &(0_u32, HashMap::<&str, Value<'_>>::new()),
                )
                .await
                .expect("answer the request");
        }
        request
    }

    #[zbus(property)]
    #[expect(
        clippy::unused_self,
        reason = "a zbus property is read through the object"
    )]
    fn version(&self) -> u32 {
        1
    }
}

const PORTAL_SECRET: [u8; 64] = [11; 64];

#[tokio::test(flavor = "multi_thread")]
async fn the_sandbox_keyring_opens_with_the_portals_secret_and_reopens() {
    let bus = PrivateBus::start();
    let _portal = bus.serve_portal(Some(PORTAL_SECRET.to_vec())).await;
    let client = bus.connect().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keyrings").join("default.keyring");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("keyrings directory");

    let first =
        super::sandbox::Sandbox::open_with(&client, Duration::from_secs(5), Some(path.clone()))
            .await
            .expect("the portal answers");
    first
        .write("tokens", "\"alice\"", "alice-refresh")
        .await
        .expect("write");
    drop(first);

    let second =
        super::sandbox::Sandbox::open_with(&client, Duration::from_secs(5), Some(path.clone()))
            .await
            .expect("reopen");
    assert_eq!(
        second
            .read("tokens", "\"alice\"")
            .await
            .expect("read")
            .as_deref(),
        Some("alice-refresh")
    );
    let direct = super::sandbox::Sandbox::load(&path, oo7::Secret::from(PORTAL_SECRET.to_vec()))
        .await
        .expect("the file opens under the portal's secret");
    assert!(
        direct
            .read("tokens", "\"alice\"")
            .await
            .expect("read")
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_portal_that_never_answers_is_refused_at_the_bound() {
    let bus = PrivateBus::start();
    let _portal = bus.serve_portal(None).await;
    let client = bus.connect().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let err = super::sandbox::Sandbox::open_with(
        &client,
        Duration::from_millis(300),
        Some(dir.path().join("default.keyring")),
    )
    .await
    .err()
    .expect("an unanswered portal refuses");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::TimedOut(_))),
        "got {err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_with_no_data_directory_refuses_before_asking_the_portal() {
    let bus = PrivateBus::start();
    let client = bus.connect().await;
    let err = super::sandbox::Sandbox::open_with(&client, Duration::from_secs(5), None)
        .await
        .err()
        .expect("no data directory refuses");
    assert!(err.to_string().contains("no data directory"), "got {err}");
}

/// One side of the session-bus run, driven by the environment. Run alone it does nothing.
/// One side of a session-bus run, chosen by the environment. Run alone it does nothing.
#[tokio::test]
#[ignore = "a phase the session-bus tests run in a child process"]
async fn session_bus_phase() {
    let Ok(phase) = std::env::var("CONNETTO_R71_SESSION_PHASE") else {
        return;
    };
    match phase.as_str() {
        "open" => {
            let sandbox = super::sandbox::Sandbox::open()
                .await
                .expect("open through the session bus");
            sandbox
                .write("tokens", "\"alice\"", "alice-refresh")
                .await
                .expect("write");
        }
        "named-sandbox" => {
            let store = super::Store::named(super::LinuxStore::SandboxKeyring);
            assert_eq!(
                store.backend().await.expect("opens"),
                Backend::SandboxKeyring
            );
            store
                .write("tokens", "\"alice\"", "alice-refresh")
                .await
                .expect("write");
            assert_eq!(
                store
                    .read("tokens", "\"alice\"")
                    .await
                    .expect("read")
                    .as_deref(),
                Some("alice-refresh")
            );
            store.clear("tokens", "\"alice\"").await.expect("clear");
            assert!(
                store
                    .read("tokens", "\"alice\"")
                    .await
                    .expect("read")
                    .is_none()
            );
        }
        "detected-sandbox" => {
            let opened = detect(&environment(true, None, None), None)
                .await
                .expect("a sandbox opens through the portal");
            assert!(matches!(opened, Opened::Sandbox(_)));
        }
        "no-secret-service" => {
            let store = super::Store::named(super::LinuxStore::SecretService);
            let err = store.backend().await.expect_err("no session bus refuses");
            assert!(
                matches!(err, ClientError::SecretStore(SecretStoreError::NoStore { probed }) if probed == "the Secret Service"),
                "got {err}"
            );
        }
        other => panic!("unknown phase {other}"),
    }
}

/// Runs `phase` in a child process whose session bus and data home are the given ones.
async fn run_session_phase(phase: &'static str, bus_address: &str, data_home: &Path) {
    let exe = std::env::current_exe().expect("the test binary");
    let (address, data_home) = (bus_address.to_owned(), data_home.to_owned());
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(exe)
            .args([
                "keyring::linux::tests::session_bus_phase",
                "--exact",
                "--ignored",
            ])
            .env("CONNETTO_R71_SESSION_PHASE", phase)
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .env("XDG_DATA_HOME", data_home)
            .status()
    })
    .await
    .expect("join")
    .expect("spawn the phase");
    assert!(status.success(), "the {phase} phase failed");
}

fn data_home() -> tempfile::TempDir {
    let data = tempfile::tempdir().expect("data home");
    std::fs::create_dir_all(data.path().join("keyrings")).expect("keyrings directory");
    data
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sandbox_opens_through_the_session_bus_at_libsecrets_path() {
    let bus = PrivateBus::start();
    let _portal = bus.serve_portal(Some(PORTAL_SECRET.to_vec())).await;
    let data = data_home();
    run_session_phase("open", &bus.address, data.path()).await;

    let path = data.path().join("keyrings").join("default.keyring");
    let keyring = super::sandbox::Sandbox::load(&path, oo7::Secret::from(PORTAL_SECRET.to_vec()))
        .await
        .expect("the child wrote libsecret's file under XDG_DATA_HOME");
    assert_eq!(
        keyring
            .read("tokens", "\"alice\"")
            .await
            .expect("read")
            .as_deref(),
        Some("alice-refresh")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_sandbox_store_keeps_secrets_through_the_store() {
    let bus = PrivateBus::start();
    let _portal = bus.serve_portal(Some(PORTAL_SECRET.to_vec())).await;
    let data = data_home();
    run_session_phase("named-sandbox", &bus.address, data.path()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn detection_inside_a_sandbox_opens_the_portal_keyring() {
    let bus = PrivateBus::start();
    let _portal = bus.serve_portal(Some(PORTAL_SECRET.to_vec())).await;
    let data = data_home();
    run_session_phase("detected-sandbox", &bus.address, data.path()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_secret_service_with_no_session_bus_refuses_naming_it() {
    let data = data_home();
    run_session_phase(
        "no-secret-service",
        "unix:path=/nonexistent/connetto-r71-bus",
        data.path(),
    )
    .await;
}

#[test]
fn an_unusable_state_directory_refuses_naming_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"").expect("a regular file");
    let err = Sealed::open(file.join("state"), &CURRENT, None)
        .err()
        .expect("a state directory under a file refuses");
    assert!(
        matches!(&err, ClientError::SecretStore(SecretStoreError::Backend(message)) if message.contains("not-a-directory")),
        "got {err}"
    );
}

#[tokio::test]
async fn a_secret_service_that_answers_with_errors_refuses() {
    let (server, client) = tokio::net::UnixStream::pair().expect("socket pair");
    let guid = zbus::Guid::generate();
    // An object server with nothing at the Secret Service's path answers every call with an error.
    let server = zbus::connection::Builder::unix_stream(server)
        .server(guid)
        .expect("server")
        .p2p()
        .serve_at("/unrelated", FakePortal { secret: None })
        .expect("serve")
        .build();
    let client = zbus::connection::Builder::unix_stream(client).p2p().build();
    let (_server, client) = tokio::join!(server, client);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        ensure_default(&client.expect("client"), Duration::from_secs(5)),
    )
    .await
    .expect("the error comes back rather than a hang")
    .expect_err("a service with no objects refuses");
    assert!(
        matches!(&err, ClientError::SecretStore(SecretStoreError::Backend(message)) if message.starts_with("the Secret Service")),
        "got {err}"
    );
}

#[tokio::test]
async fn a_service_that_hangs_up_mid_prompt_is_refused_as_dismissed() {
    let (fake, bus) = FakeSecretService::start(Answer::Hangup).await;
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        ensure_default(&bus, Duration::from_secs(5)),
    )
    .await
    .expect("a hang-up ends the wait rather than the bound")
    .expect_err("refused");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::Dismissed)),
        "got {err}"
    );
    assert!(
        !fake.calls().contains(&"Dismiss".to_owned()),
        "nothing is left to dismiss"
    );
}

#[tokio::test]
async fn a_sandbox_item_that_is_not_connettos_base64_text_refuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("default.keyring");
    let secret = || oo7::Secret::from(PORTAL_SECRET.to_vec());
    let raw = oo7::file::UnlockedKeyring::load(&path, secret())
        .await
        .expect("open");
    for (name, text) in [("garbled", "not base64!"), ("binary", "/w==")] {
        raw.create_item(
            "tokens",
            &super::attributes("tokens", name),
            oo7::Secret::text(text),
            true,
        )
        .await
        .expect("plant a value connetto never writes");
    }
    drop(raw);
    let sandbox = super::sandbox::Sandbox::load(&path, secret())
        .await
        .expect("reopen");
    for name in ["garbled", "binary"] {
        let err = sandbox.read("tokens", name).await.expect_err("refused");
        assert!(
            matches!(err, ClientError::SecretStore(SecretStoreError::Encoding)),
            "{name}: got {err}"
        );
    }
}

fn key_file_store(dir: &Path, key: &[u8; 32]) -> super::LinuxStore {
    let path = dir.join(format!("wrap-{}.key", key[0]));
    std::fs::write(&path, key).expect("key file");
    super::LinuxStore::KeyFile(super::KeyFile::new(path, dir.join("state")))
}

#[tokio::test]
async fn a_record_that_is_not_text_refuses_as_badly_encoded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = super::Store::named(key_file_store(dir.path(), &CURRENT));
    sealed(&dir.path().join("state").join(SEALED_DIR), &CURRENT, None)
        .write("tokens", "alice", &[0xff, 0xfe])
        .expect("plant bytes connetto never writes");
    let err = store.read("tokens", "alice").await.expect_err("refused");
    assert!(
        matches!(err, ClientError::SecretStore(SecretStoreError::Encoding)),
        "got {err}"
    );
}

#[test]
fn a_directory_where_a_record_belongs_refuses_reads_and_clears() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = sealed(dir.path(), &CURRENT, None);
    std::fs::create_dir(dir.path().join(stem("keys", "alice")))
        .expect("a directory in the record's place");
    let err = store.read("keys", "alice").expect_err("read refuses");
    assert!(
        err.to_string().contains("reading a sealed record"),
        "got {err}"
    );
    let err = store.clear("keys", "alice").expect_err("clear refuses");
    assert!(
        err.to_string().contains("removing a sealed record"),
        "got {err}"
    );
}

#[test]
fn a_record_left_under_the_previous_key_after_opening_is_resealed_when_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rotating = sealed(dir.path(), &CURRENT, Some(&PREVIOUS));
    sealed(dir.path(), &PREVIOUS, None)
        .write("keys", "late", b"late-secret")
        .expect("another process writes under the previous key");
    assert_eq!(
        rotating
            .read("keys", "late")
            .expect("read")
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"late-secret"[..])
    );
    assert_eq!(
        sealed(dir.path(), &CURRENT, None)
            .read("keys", "late")
            .expect("opens under the current key alone")
            .as_deref()
            .map(Vec::as_slice),
        Some(&b"late-secret"[..])
    );
}

#[test]
fn opening_skips_names_it_does_not_own_and_records_under_neither_key() {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let stranger = dir
        .path()
        .join(std::ffi::OsStr::from_bytes(b"not-utf8-\xff"));
    std::fs::write(&stranger, b"left alone").expect("a file with a non-UTF-8 name");
    sealed(dir.path(), &[5; 32], None)
        .write("keys", "foreign", b"foreign-secret")
        .expect("a record under a third key");
    let foreign = dir.path().join(stem("keys", "foreign"));
    let before = std::fs::read(&foreign).expect("read");

    let rotating = sealed(dir.path(), &CURRENT, Some(&PREVIOUS));
    assert!(!rotating.previous_key_needed());
    assert_eq!(
        std::fs::read(&foreign).expect("read"),
        before,
        "a record under neither key is untouched"
    );
    assert!(
        stranger.exists(),
        "a name that is not connetto's is left alone"
    );
    let err = rotating.read("keys", "foreign").expect_err("refused");
    assert!(is_unsealable(&err), "got {err}");
}

#[tokio::test]
async fn a_named_credential_opens_the_sealed_store_and_bad_state_directories_refuse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let credentials = dir.path().join("credentials");
    std::fs::create_dir_all(&credentials).expect("credentials");
    std::fs::write(credentials.join(super::CREDENTIAL), CURRENT).expect("credential");
    let state = dir.path().join("state");
    let opened = super::open_named(
        &super::LinuxStore::SystemdCredential,
        &environment(false, Some(&credentials), Some(&state)),
    )
    .await
    .expect("the named credential opens");
    assert!(matches!(
        opened,
        Opened::Sealed {
            credential: true,
            ..
        }
    ));

    let file = dir.path().join("a-file");
    std::fs::write(&file, b"").expect("a regular file");
    let under_file = file.join("state");
    let err = super::open_named(
        &super::LinuxStore::SystemdCredential,
        &environment(false, Some(&credentials), Some(&under_file)),
    )
    .await
    .err()
    .expect("a state directory under a file refuses");
    assert!(err.to_string().contains("a-file"), "got {err}");
    let key = dir.path().join("wrap.key");
    std::fs::write(&key, CURRENT).expect("key");
    let err = super::open_named(
        &super::LinuxStore::KeyFile(super::KeyFile::new(&key, &under_file)),
        &environment(false, None, None),
    )
    .await
    .err()
    .expect("a key file's state directory under a file refuses");
    assert!(err.to_string().contains("a-file"), "got {err}");
    let err = super::open_named(
        &super::LinuxStore::KeyFile(super::KeyFile::new(dir.path().join("missing.key"), &state)),
        &environment(false, None, None),
    )
    .await
    .err()
    .expect("a missing key file refuses");
    assert!(
        err.to_string().contains("reading the wrap key"),
        "got {err}"
    );
}

#[tokio::test]
async fn store_failures_reach_the_refresh_and_key_stores_as_errors() {
    use connetto_core::traits::{RefreshTokenStore as _, ReplicaKeyStore as _};
    let dir = tempfile::tempdir().expect("tempdir");
    let (first, second) = (
        key_file_store(dir.path(), &CURRENT),
        key_file_store(dir.path(), &PREVIOUS),
    );
    let tokens = crate::KeyringStore::with_linux_store("svc", first.clone());
    tokens
        .store("\"alice\"", "alice-refresh")
        .await
        .expect("store");
    crate::KeyringKeyStore::with_linux_store("keys", first)
        .store(
            "replica",
            &crate::ReplicaKey::from_bytes([1; crate::ReplicaKey::LEN]),
        )
        .await
        .expect("store a key");

    let rekeyed = crate::KeyringStore::with_linux_store("svc", second.clone());
    assert!(
        rekeyed.accounts().await.is_err(),
        "an index under another key refuses to list"
    );
    assert!(
        rekeyed.store("\"bob\"", "bob-refresh").await.is_err(),
        "and to add an account"
    );
    assert!(rekeyed.clear("\"alice\"").await.is_err(), "and to drop one");
    let err = crate::KeyringKeyStore::with_linux_store("keys", second)
        .load("replica")
        .await
        .expect_err("a key under another wrap key refuses");
    assert!(is_unsealable(&err), "got {err}");

    let records = dir.path().join("state").join(SEALED_DIR);
    let carol = records.join(stem("svc", "\"carol\""));
    std::fs::create_dir(&carol).expect("a directory in carol's place");
    std::fs::write(carol.join("occupant"), b"").expect("non-empty");
    assert!(
        tokens.store("\"carol\"", "carol-refresh").await.is_err(),
        "an unwritable record refuses"
    );
    assert!(
        tokens.clear("\"carol\"").await.is_err(),
        "an unremovable record refuses"
    );
}
