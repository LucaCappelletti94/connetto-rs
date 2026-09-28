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
        (
            OwnedObjectPath::try_from("/").expect("path"),
            OwnedObjectPath::try_from(PROMPT).expect("path"),
        )
    }

    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.0.record("Unlock");
        assert_eq!(objects.len(), 1);
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
    async fn prompt(&self, window_id: &str, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) {
        self.0.record("Prompt");
        assert!(
            window_id.is_empty(),
            "connetto has no window to parent the dialog to"
        );
        let answer = self.0.state.lock().expect("fake state").answer;
        match answer {
            Answer::Never => {}
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
