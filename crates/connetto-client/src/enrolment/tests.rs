use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use base64::Engine as _;
use connetto_core::device_cert::{
    AttestationLevel, CertificateRequest, CertificateSerial, CertificateSigner, DeploymentId,
    DeviceCertificate, DeviceIssuer, DeviceKey, DeviceKeyError, KeyHome, RevocationList, Revoked,
    RootCa, public_key_info,
};
use connetto_core::messages::{
    ControlMessage, DeviceAttestation, EnrolRefusal, SignedList, SyncStatus,
};
use diesel::Connection as _;
use diesel::connection::SimpleConnection as _;
use diesel::sqlite::SqliteConnection;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_bytes::ByteBuf;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

#[cfg(feature = "peer")]
use super::Peer;
use super::task::next_look;
use super::{
    Answer, CERTIFICATE_DDL, CertificateError, DeviceKeys, EnrolHandle, Enroller, Held, Intake,
    KeptList, Link, ListInbox, Standing, TOLERANCE, delete, intake, load, run, store,
};
use crate::ClientError;
use crate::ClientEvent;
#[cfg(feature = "peer")]
use crate::PeerError;
use crate::device_key::{KeyRecords, OpenedKey, open_software_key};
#[cfg(feature = "peer")]
use connetto_peer::test_support::loopback_multicast;

const HOUR: Duration = Duration::from_hours(1);
const MINUTE: Duration = Duration::from_mins(1);

#[derive(Default)]
struct Memory(Mutex<HashMap<String, String>>);

impl KeyRecords for Memory {
    fn read(&self, name: &str) -> impl Future<Output = Result<Option<String>, ClientError>> + Send {
        std::future::ready(Ok(self.0.lock().get(name).cloned()))
    }

    fn write(
        &self,
        name: &str,
        secret: &str,
    ) -> impl Future<Output = Result<(), ClientError>> + Send {
        self.0.lock().insert(name.to_owned(), secret.to_owned());
        std::future::ready(Ok(()))
    }

    fn delete(&self, name: &str) -> impl Future<Output = Result<(), ClientError>> + Send {
        self.0.lock().remove(name);
        std::future::ready(Ok(()))
    }
}

/// A certificate for a fresh software key, valid from `not_before` for `lifetime`.
async fn held(not_before: SystemTime, lifetime: Duration) -> Held {
    let records = Memory::default();
    let issuer_key = open_software_key(&records, "issuer")
        .await
        .expect("issuer key");
    let issuer_pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(
            records
                .0
                .lock()
                .get(&crate::device_key_record("issuer"))
                .expect("stored"),
        )
        .expect("base64");
    let device = open_software_key(&records, "device")
        .await
        .expect("device key");
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        not_before - 10 * HOUR,
        3650 * 24 * HOUR,
    )
    .expect("root");
    let issuer_der = root
        .sign_issuer(
            &public_key_info(&issuer_key.key),
            not_before - 10 * HOUR,
            400 * 24 * HOUR,
            CertificateSerial::new([2; 16]).expect("the serial is positive"),
        )
        .expect("issuer");
    let issuer = DeviceIssuer::from_pkcs8(issuer_der.clone(), &issuer_pkcs8, root.certificate())
        .expect("load issuer");
    let key: &dyn DeviceKey = &device.key;
    let csr = CertificateRequest::build(&CertificateSigner::new(key), &[1; 32]).expect("csr");
    let request = CertificateRequest::parse(&csr).expect("parse");
    let certificate = issuer
        .issue(
            &request,
            "alice",
            not_before,
            lifetime,
            CertificateSerial::new([3; 16]).expect("the serial is positive"),
            AttestationLevel::Unproven,
        )
        .expect("issue");
    Held {
        leaf: DeviceCertificate::parse(&certificate).expect("profile"),
        certificate,
        issuer: issuer_der,
        lifetime: Some(lifetime),
    }
}

/// The start of a certificate, on a whole second as X.509 carries it.
fn whole_second() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[tokio::test]
async fn standing_follows_the_lifecycle_boundaries() {
    let start = whole_second();
    let held = held(start, 24 * HOUR).await;
    let at = |offset: Duration| Standing::of(Some(&held), start + offset);
    let before = |offset: Duration| Standing::of(Some(&held), start - offset);
    assert_eq!(Standing::of(None, start), Standing::NoKey);
    assert_eq!(at(Duration::ZERO), Standing::Fresh);
    assert_eq!(at(Duration::from_secs(12 * 3600 - 1)), Standing::Fresh);
    assert_eq!(at(12 * HOUR), Standing::Aging, "half-life is the boundary");
    assert_eq!(
        at(24 * HOUR + TOLERANCE),
        Standing::Aging,
        "within the tolerance past its end"
    );
    assert_eq!(
        at(24 * HOUR + TOLERANCE + Duration::from_secs(1)),
        Standing::Expired
    );
    assert_eq!(
        before(TOLERANCE),
        Standing::Fresh,
        "within the tolerance before its start"
    );
    assert_eq!(
        before(TOLERANCE + Duration::from_secs(1)),
        Standing::ClockOff
    );
}

#[tokio::test]
async fn a_fresh_certificate_is_looked_at_again_at_half_life_or_within_the_hour() {
    let start = whole_second();
    let short = held(start, 4 * HOUR).await;
    assert_eq!(next_look(Some(&short), start + HOUR), HOUR);
    assert_eq!(
        next_look(Some(&short), start + Duration::from_secs(7_000)),
        Duration::from_secs(200)
    );
    let long = held(start, 30 * 24 * HOUR).await;
    assert_eq!(
        next_look(Some(&long), start),
        HOUR,
        "never sleeps past the hourly look"
    );
    assert_eq!(next_look(None, start), HOUR);
    assert_eq!(
        next_look(Some(&short), start + 3 * HOUR + HOUR / 2),
        HOUR / 2 + TOLERANCE,
        "an aging one wakes at its expiry plus the tolerance"
    );
    // An aging certificate far from its expiry is still looked at within
    // the hour, so a failed renewal is retried and a jumped clock caught,
    // and a not-yet-valid one wakes at its window's open (decision 9).
    let long_aging = held(start, 30 * 24 * HOUR).await;
    let at = start + 15 * 24 * HOUR + HOUR;
    assert_eq!(
        next_look(Some(&long_aging), at),
        HOUR,
        "an aging certificate is looked at again within the hour"
    );
    let behind = held(at + 10 * MINUTE, 12 * HOUR).await;
    assert_eq!(
        next_look(Some(&behind), at),
        5 * MINUTE,
        "a not-yet-valid one wakes at its window's open"
    );
    let far_behind = held(at + 2 * HOUR, 12 * HOUR).await;
    assert_eq!(
        next_look(Some(&far_behind), at),
        HOUR,
        "the window's open is never slept past the hourly look"
    );
}

#[tokio::test]
async fn the_replica_keeps_one_certificate_and_forgets_it() {
    let mut db = SqliteConnection::establish(":memory:").expect("open");
    db.batch_execute(CERTIFICATE_DDL).expect("ddl");
    assert!(load(&mut db).expect("empty").is_none());
    let first = held(whole_second(), 24 * HOUR).await;
    store(&mut db, &first).expect("store");
    let second = Held {
        lifetime: None,
        ..held(whole_second(), 2 * HOUR).await
    };
    store(&mut db, &second).expect("replace");
    let loaded = load(&mut db).expect("load").expect("held");
    assert_eq!(loaded.certificate, second.certificate);
    assert_eq!(loaded.issuer, second.issuer);
    assert_eq!(loaded.lifetime, None);
    assert_eq!(loaded.leaf, second.leaf);
    delete(&mut db).expect("delete");
    assert!(load(&mut db).expect("emptied").is_none());
}

#[tokio::test]
async fn a_lower_number_never_replaces_a_higher_and_an_equal_one_with_other_content_is_ignored() {
    let start = whole_second();
    let records = Memory::default();
    let issuer_key = open_software_key(&records, "issuer")
        .await
        .expect("issuer key");
    let pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(
            records
                .0
                .lock()
                .get(&crate::device_key_record("issuer"))
                .expect("stored"),
        )
        .expect("base64");
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(9)),
        start - HOUR,
        3650 * 24 * HOUR,
    )
    .expect("root");
    let issuer_der = root
        .sign_issuer(
            &public_key_info(&issuer_key.key),
            start - HOUR,
            400 * 24 * HOUR,
            CertificateSerial::new([4; 16]).expect("the serial is positive"),
        )
        .expect("issuer");
    let issuer =
        DeviceIssuer::from_pkcs8(issuer_der.clone(), &pkcs8, root.certificate()).expect("load");
    let roots = [root.certificate().to_vec()];
    let list = |number: u64, serial: u8| {
        let der = issuer
            .sign_list(
                number,
                &[Revoked {
                    serial: vec![serial; 16],
                    at: start,
                }],
                start,
                start + HOUR,
            )
            .expect("sign");
        RevocationList::verify(&der, &issuer_der, &roots).expect("verifies")
    };
    let kept_of = |list: &RevocationList| KeptList {
        signer_key: list.issuer().as_bytes().to_vec(),
        number: list.number(),
        list: list.der().to_vec(),
        signer: issuer_der.clone(),
    };
    let five = list(5, 1);
    assert_eq!(
        intake(None, &five),
        Intake::Newer,
        "the first list from a signer"
    );
    let kept = kept_of(&five);
    assert_eq!(intake(Some(&kept), &list(6, 1)), Intake::Newer);
    assert_eq!(
        intake(Some(&kept), &list(4, 2)),
        Intake::Stale,
        "a lower number"
    );
    assert_eq!(
        intake(Some(&kept), &five),
        Intake::Stale,
        "the kept list again"
    );
    assert_eq!(
        intake(Some(&kept), &list(5, 2)),
        Intake::Conflicting,
        "the kept number with other content"
    );
}

// The run loop over a fake link (R74 step 4).

/// The evidence the fake key offers.
fn evidence() -> DeviceAttestation {
    DeviceAttestation::AndroidKeyChain(vec![ByteBuf::from(vec![0x30, 0x06])])
}

/// A real ring key and the PKCS #8 bytes the fake store reopens.
fn attesting_key() -> (AttestingKey, Vec<u8>) {
    let rng = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("the key generates");
    (
        AttestingKey::from_pkcs8(der.as_ref()),
        der.as_ref().to_vec(),
    )
}

/// A key that signs with ring and offers Android-style evidence.
struct AttestingKey {
    pair: EcdsaKeyPair,
    point: [u8; 65],
    rng: SystemRandom,
}

impl AttestingKey {
    fn from_pkcs8(der: &[u8]) -> Self {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der, &rng)
            .expect("the key reads back");
        let point = pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("a P-256 point");
        Self { pair, point, rng }
    }
}

impl DeviceKey for AttestingKey {
    fn public_point(&self) -> [u8; 65] {
        self.point
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        self.pair
            .sign(&self.rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::Software
    }

    fn attestation(&self, _csr: &[u8]) -> Result<Option<DeviceAttestation>, DeviceKeyError> {
        Ok(Some(evidence()))
    }
}

/// The keys the run opens, always the same attesting key.
struct RunKeys {
    der: Vec<u8>,
}

impl DeviceKeys for RunKeys {
    fn open(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<OpenedKey<Box<dyn DeviceKey>>, ClientError>> + Send + '_>>
    {
        let der = self.der.clone();
        Box::pin(async move {
            let key: Box<dyn DeviceKey> = Box::new(AttestingKey::from_pkcs8(&der));
            Ok(OpenedKey {
                key,
                created: false,
            })
        })
    }

    fn delete(&self) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

/// What the fake link observes, in order.
#[derive(Default)]
struct FakeState {
    /// The attestation each `EnrolRequest` carried.
    requests: Vec<Option<DeviceAttestation>>,
    /// The events the run emitted.
    emitted: Vec<ClientEvent>,
    /// The certificates the run stored.
    stored: Vec<Held>,
    /// The lists the run stored.
    lists: Vec<KeptList>,
    serials: u64,
    /// The lists a grant hands over beside its chain.
    grant_lists: Vec<SignedList>,
    /// Storing a list waits on it first, so a test sees what the run
    /// published while the list is not yet kept.
    list_gate: Option<Arc<tokio::sync::Notify>>,
    /// How many list stores have started.
    list_stores: usize,
}

/// How the fake link drives one enrolment.
#[derive(Clone, Copy)]
enum Ask {
    /// Grant the enrolment.
    Grant,
    /// Refuse the enrolment with this reason.
    Refused(EnrolRefusal),
    /// The enrolment goes out and no answer comes.
    Silent,
    /// The message is lost on the wire.
    Lost,
    /// The transport reports a protocol violation.
    Violated,
}

/// A link the run drives, answering enrolment as configured and recording
/// what it sees.
struct FakeLink {
    state: Arc<Mutex<FakeState>>,
    events: broadcast::Sender<ClientEvent>,
    end: watch::Receiver<()>,
    issuer: Arc<DeviceIssuer>,
    certificate: Vec<u8>,
    ask: Ask,
    /// A grant answer waits on it first, so a test holds the renewal open.
    gate: Option<Arc<tokio::sync::Notify>>,
    /// A granted leaf's `not_before`, so a test's clock can stand past
    /// `not_after` when the grant lands.
    grant_from: Option<SystemTime>,
}

impl Link for FakeLink {
    fn alive(&self) -> bool {
        true
    }

    fn events(&self) -> broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }

    fn emit(&self, event: ClientEvent) {
        self.state.lock().emitted.push(event);
    }

    fn ended(&self) -> impl Future<Output = ()> + Send {
        let mut end = self.end.clone();
        Box::pin(async move {
            let _ = end.changed().await;
        })
    }

    fn connected(&self) -> impl Future<Output = bool> + Send {
        Box::pin(async { true })
    }

    fn ask(
        &self,
        _request_id: String,
        msg: ControlMessage,
    ) -> impl Future<Output = Result<oneshot::Receiver<Answer>, ClientError>> + Send {
        let state = Arc::clone(&self.state);
        let issuer = Arc::clone(&self.issuer);
        let certificate = self.certificate.clone();
        let ask = self.ask;
        let gate = self.gate.clone();
        Box::pin(async move {
            match (ask, msg) {
                (Ask::Lost, _) => Err(ClientError::NotConnected),
                (Ask::Violated, _) => Err(ClientError::Protocol("the fake transport fails".into())),
                (_, ControlMessage::EnrolChallengeRequest(_)) => {
                    let (tx, rx) = oneshot::channel();
                    let _ = tx.send(Answer::Challenge([7; 32]));
                    Ok(rx)
                }
                (_, ControlMessage::EnrolRequest(request)) => {
                    let (tx, rx) = oneshot::channel();
                    {
                        let mut state = state.lock();
                        state.requests.push(request.attestation);
                    }
                    let answer = match ask {
                        Ask::Refused(refusal) => Answer::Refused(refusal),
                        Ask::Silent => {
                            // The request went out and no answer comes.
                            drop(tx);
                            return Ok(rx);
                        }
                        _ => {
                            if let Some(gate) = &gate {
                                gate.notified().await;
                            }
                            let request =
                                CertificateRequest::parse(&request.csr).expect("the csr parses");
                            let mut state = state.lock();
                            let mut bytes = [0x21_u8; 16];
                            bytes[8..].copy_from_slice(&state.serials.to_be_bytes());
                            state.serials += 1;
                            let serial =
                                CertificateSerial::new(bytes).expect("the serial is positive");
                            let leaf = issuer
                                .issue(
                                    &request,
                                    "alice",
                                    self.grant_from.unwrap_or_else(SystemTime::now),
                                    12 * HOUR,
                                    serial,
                                    AttestationLevel::Unproven,
                                )
                                .expect("the grant issues");
                            Answer::Grant(vec![leaf, certificate], state.grant_lists.clone())
                        }
                    };
                    let _ = tx.send(answer);
                    Ok(rx)
                }
                _ => {
                    let (tx, rx) = oneshot::channel();
                    let _ = tx.send(Answer::Refused(EnrolRefusal::InvalidRequest));
                    Ok(rx)
                }
            }
        })
    }

    fn store(&self, held: Held) -> impl Future<Output = Result<(), ClientError>> + Send {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().stored.push(held);
            Ok(())
        })
    }

    fn forget(&self) -> impl Future<Output = Result<(), ClientError>> + Send {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().stored.clear();
            Ok(())
        })
    }

    fn store_list(&self, kept: KeptList) -> impl Future<Output = Result<(), ClientError>> + Send {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let gate = {
                let mut state = state.lock();
                state.list_stores += 1;
                state.list_gate.clone()
            };
            if let Some(gate) = gate {
                gate.notified().await;
            }
            state.lock().lists.push(kept);
            Ok(())
        })
    }
}

/// The root, an issuer under it and the issuer's certificate.
struct Authority {
    root: Vec<u8>,
    issuer: DeviceIssuer,
    certificate: Vec<u8>,
}

async fn authority(not_before: SystemTime) -> Authority {
    let records = Memory::default();
    let issuer_key = open_software_key(&records, "issuer")
        .await
        .expect("the issuer key");
    let issuer_pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(
            records
                .0
                .lock()
                .get(&crate::device_key_record("issuer"))
                .expect("stored")
                .as_bytes(),
        )
        .expect("base64");
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        not_before - 10 * HOUR,
        3650 * 24 * HOUR,
    )
    .expect("the root");
    let certificate = root
        .sign_issuer(
            &public_key_info(&issuer_key.key),
            not_before - 10 * HOUR,
            400 * 24 * HOUR,
            CertificateSerial::new([2; 16]).expect("the serial is positive"),
        )
        .expect("the issuer signs");
    let issuer = DeviceIssuer::from_pkcs8(certificate.clone(), &issuer_pkcs8, root.certificate())
        .expect("the issuer loads");
    Authority {
        root: root.certificate().to_vec(),
        issuer,
        certificate,
    }
}

/// A test serial of sixteen `byte`s, positive for any byte from 1 to 127.
fn positive_serial(byte: u8) -> CertificateSerial {
    CertificateSerial::new([byte; 16]).expect("the test serial is positive")
}

/// A certificate `authority` issued for `key`, valid from `not_before` for
/// `lifetime`.
fn issue_for(
    authority: &Authority,
    key: &dyn DeviceKey,
    not_before: SystemTime,
    lifetime: Duration,
    serial: CertificateSerial,
) -> Held {
    let csr =
        CertificateRequest::build(&CertificateSigner::new(key), &[1; 32]).expect("the csr builds");
    let request = CertificateRequest::parse(&csr).expect("the csr parses");
    let certificate = authority
        .issuer
        .issue(
            &request,
            "alice",
            not_before,
            lifetime,
            serial,
            AttestationLevel::Unproven,
        )
        .expect("the issuer signs");
    Held {
        leaf: DeviceCertificate::parse(&certificate).expect("the profile"),
        certificate,
        issuer: authority.certificate.clone(),
        lifetime: Some(lifetime),
    }
}

/// Poll `is` until it holds, bounded.
async fn poll_until(mut is: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if is() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the condition never held within the bound"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn inbox() -> ListInbox {
    let (_, inbox) = mpsc::unbounded_channel();
    inbox
}

/// A deployment that refuses the device's level raises the event once, keeps
/// the device certificate-less, and the device asks again only on its next
/// connection, never on the hourly look (decision 33).
#[tokio::test(start_paused = true)]
async fn a_refused_attestation_is_raised_once_and_asks_again_only_on_the_next_connection() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events_rx) = broadcast::channel(64);
    let events_tx = events.clone();
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::AttestationRequired),
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, _handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| state.lock().requests.len() == 1).await;
    {
        let state = state.lock();
        assert_eq!(
            state.requests[0].as_ref(),
            Some(&evidence()),
            "the first enrolment carries the evidence"
        );
        assert_eq!(
            state.emitted,
            [ClientEvent::AttestationRequired],
            "the refusal is raised once"
        );
        assert!(
            state.stored.is_empty(),
            "a refused enrolment stores nothing"
        );
    }

    tokio::time::advance(HOUR).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        state.lock().requests.len(),
        1,
        "the hourly look asks nothing"
    );

    events_tx
        .send(ClientEvent::SyncStatus(SyncStatus::Connected))
        .expect("the run listens");
    poll_until(|| state.lock().requests.len() == 2).await;
    {
        let state = state.lock();
        assert_eq!(
            state.requests[1].as_ref(),
            Some(&evidence()),
            "the next connection asks again, with the evidence"
        );
        assert_eq!(state.emitted.len(), 2, "the refusal is raised again");
        assert!(state.stored.is_empty());
    }

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A device that holds a certificate renews on connect and sends no
/// attestation, since the level is the enrolment's (decision 13).
#[tokio::test]
async fn a_renewal_sends_no_attestation() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    let held = issue_for(
        &authority,
        &key,
        now - 6 * HOUR,
        12 * HOUR,
        CertificateSerial::new([3; 16]).expect("the serial is positive"),
    );
    let old_serial = held.leaf.serial().to_vec();
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, _handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| state.lock().stored.len() == 1).await;
    {
        let state = state.lock();
        assert_eq!(state.requests.len(), 1, "the connection renews once");
        assert!(
            state.requests[0].is_none(),
            "a renewal carries no attestation"
        );
        assert_ne!(
            state.stored[0].leaf.serial(),
            old_serial.as_slice(),
            "the renewal replaces the certificate"
        );
    }

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A grant's lists are kept before its certificate is published, so a
/// caller that sees the certificate also finds the lists the handshake
/// handed over, and the peer link starts with them.
#[tokio::test]
async fn a_grant_keeps_its_lists_before_publishing_the_certificate() {
    let (_, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    let list = authority
        .issuer
        .sign_list(
            1,
            &[Revoked {
                serial: positive_serial(9).as_bytes().to_vec(),
                at: now,
            }],
            now,
            now + 12 * HOUR,
        )
        .expect("the list signs");
    let gate = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(Mutex::new(FakeState {
        grant_lists: vec![SignedList {
            list,
            signer: authority.certificate.clone(),
        }],
        list_gate: Some(Arc::clone(&gate)),
        ..FakeState::default()
    }));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| state.lock().list_stores == 1).await;
    assert!(
        handle.certificate().is_none(),
        "the certificate stays unpublished while the grant's list is being kept"
    );
    gate.notify_one();
    poll_until(|| handle.certificate().is_some()).await;
    assert_eq!(state.lock().lists.len(), 1, "the grant's list is kept");

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A grant whose own lists revoke the certificate it carries revokes the
/// device, and that certificate is never published.
#[tokio::test]
async fn a_grant_listing_its_own_certificate_revokes_the_device_unpublished() {
    let (_, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    // The fake link's first grant carries this serial.
    let mut granted = [0x21_u8; 16];
    granted[8..].fill(0);
    let list = authority
        .issuer
        .sign_list(
            1,
            &[Revoked {
                serial: granted.to_vec(),
                at: now,
            }],
            now,
            now + 12 * HOUR,
        )
        .expect("the list signs");
    let gate = Arc::new(tokio::sync::Notify::new());
    let state = Arc::new(Mutex::new(FakeState {
        grant_lists: vec![SignedList {
            list,
            signer: authority.certificate.clone(),
        }],
        list_gate: Some(Arc::clone(&gate)),
        ..FakeState::default()
    }));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| state.lock().list_stores == 1).await;
    assert!(
        handle.certificate().is_none(),
        "the grant stays unpublished while its list is being kept"
    );
    gate.notify_one();
    poll_until(|| state.lock().emitted.contains(&ClientEvent::DeviceRevoked)).await;
    assert!(
        handle.certificate().is_none(),
        "the device holds no certificate"
    );
    assert!(
        state.lock().stored.is_empty(),
        "the stored certificate is deleted"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue refused as revoked deletes the device's key, says so, and the
/// caller gets the revocation.
#[tokio::test]
async fn a_reissue_refused_as_revoked_deletes_the_key_and_reports_revoked() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::Revoked),
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| !state.lock().requests.is_empty()).await;
    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(outcome, Err(CertificateError::Revoked)),
        "the caller gets the revocation"
    );
    {
        let state = state.lock();
        assert!(
            state
                .emitted
                .iter()
                .any(|event| matches!(event, ClientEvent::DeviceRevoked)),
            "the device says its key went"
        );
        assert!(state.stored.is_empty(), "a revoked device stores nothing");
    }

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue refused over the ceiling keeps the ceiling the server named, so
/// the caller can shorten its request.
#[tokio::test]
async fn a_reissue_refused_over_the_ceiling_reports_the_ceiling() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::OverCeiling { ceiling_secs: 600 }),
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| state.lock().requests.len() >= 2).await;
    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(
            outcome,
            Err(CertificateError::OverCeiling { ceiling })
                if ceiling == Duration::from_secs(600)
        ),
        "the caller gets the ceiling the server named"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue refused for any other reason keeps that reason, so the caller
/// knows what to act on.
#[tokio::test]
async fn a_reissue_refused_for_another_reason_reports_that_reason() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::ChallengeExpired),
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| !state.lock().requests.is_empty()).await;
    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(
            outcome,
            Err(CertificateError::Refused(EnrolRefusal::ChallengeExpired))
        ),
        "the refusal keeps its reason"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue the server never answers is offline, so the caller learns there
/// is no server and asks again when there is.
#[tokio::test]
async fn a_reissue_with_no_answer_is_offline() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Silent,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| !state.lock().requests.is_empty()).await;
    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(outcome, Err(CertificateError::Offline)),
        "no answer reads as no server"
    );
    assert_eq!(
        state.lock().requests.len(),
        2,
        "the request went out once per enrolment"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue lost on the wire is offline, the same read as a server that
/// never answers.
#[tokio::test]
async fn a_reissue_lost_on_the_wire_is_offline() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(outcome, Err(CertificateError::Offline)),
        "a lost message reads as no server"
    );
    assert!(
        state.lock().requests.is_empty(),
        "nothing reached the server"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A reissue the transport reports as a protocol violation keeps its device
/// kind, so the caller acts on the device and not the server.
#[tokio::test]
async fn a_reissue_violating_the_protocol_is_a_device_error() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Violated,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        #[cfg(feature = "peer")]
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    let outcome = handle.reissue(HOUR).await;
    assert!(
        matches!(
            outcome,
            Err(CertificateError::Device(ClientError::Protocol(_)))
        ),
        "a device failure keeps its device kind"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A loopback port the discovery's mDNS daemon binds, free at the probe.
#[cfg(feature = "peer")]
fn fresh_mdns_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("the loopback binds")
        .local_addr()
        .expect("the bound address")
        .port()
}

/// A peer node the run drives, on the suite's root and a loopback port (R76),
/// whose discovery autolinks `autolink` on the mDNS `port`.
#[cfg(feature = "peer")]
fn peer_with(authority: &Authority, autolink: bool, port: u16) -> Peer {
    let (tx, rx) = mpsc::unbounded_channel();
    let node = connetto_peer::Node::new(
        connetto_peer::Trust {
            roots: vec![authority.root.clone()],
            accepted: AttestationLevel::ALL.to_vec(),
        },
        Arc::new(connetto_peer::SystemClock),
        tx,
    )
    .expect("the roots hold keys");
    let (discovery_events, discovery_events_rx) = mpsc::unbounded_channel();
    Peer {
        node: node.clone(),
        discovery: connetto_peer::Discovery::new(node, autolink, discovery_events)
            .with_mdns_port(port)
            .loopback_only(),
        listen: "127.0.0.1:0".parse().expect("a loopback address"),
        events: rx,
        discovery_events: discovery_events_rx,
        #[cfg(all(feature = "peer", target_os = "android"))]
        java: None,
    }
}

/// A peer node the run drives, on the suite's root and a loopback port (R76).
#[cfg(feature = "peer")]
fn peer(authority: &Authority) -> Peer {
    peer_with(authority, true, fresh_mdns_port())
}

/// A second node holding its own identity under the same root, served on a
/// loopback port, to link against the task's node (R76).
#[cfg(feature = "peer")]
fn far_peer(
    authority: &Authority,
    serial: CertificateSerial,
) -> (
    connetto_peer::Node,
    tokio::sync::mpsc::UnboundedReceiver<connetto_peer::PeerEvent>,
) {
    let (key, _der) = attesting_key();
    let held = issue_for(authority, &key, whole_second(), 12 * HOUR, serial);
    let (tx, rx) = mpsc::unbounded_channel();
    let node = connetto_peer::Node::new(
        connetto_peer::Trust {
            roots: vec![authority.root.clone()],
            accepted: AttestationLevel::ALL.to_vec(),
        },
        Arc::new(connetto_peer::SystemClock),
        tx,
    )
    .expect("the roots hold keys");
    let key: Arc<dyn DeviceKey> = Arc::new(key);
    node.serve(
        std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        connetto_peer::Identity {
            certificate: held.certificate,
            issuer: held.issuer,
            key,
        },
    )
    .expect("the far node serves");
    (node, rx)
}

/// The close reasons a far node reports for its links, drained for `bound`.
#[cfg(feature = "peer")]
async fn far_closes(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<connetto_peer::PeerEvent>,
    bound: Duration,
) -> Vec<connetto_peer::CloseReason> {
    let until = Instant::now() + bound;
    let mut reasons = Vec::new();
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // The drain waits out the whole bound, so a close that arrives
        // after a long gap still lands.
        let Ok(Some(event)) = tokio::time::timeout(remaining, rx.recv()).await else {
            // The bound ran out or the sender dropped, so nothing else is
            // in time.
            break;
        };
        if let connetto_peer::PeerEvent::Unlinked { reason, .. } = event {
            reasons.push(reason);
        }
    }
    reasons
}

/// The far drain runs for the whole bound, so a close that arrives after a
/// long gap still lands.
#[cfg(feature = "peer")]
#[tokio::test]
async fn far_closes_drains_for_the_whole_bound() {
    use connetto_core::device_cert::{DeploymentId, DeviceIdentity, KeyId};
    let (tx, mut rx) = mpsc::unbounded_channel();
    let peer = DeviceIdentity::new(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(1)),
        "peer",
        KeyId::from_bytes([1; 32]),
    )
    .expect("an identity holds");
    let late = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = tx.send(connetto_peer::PeerEvent::Unlinked {
            peer,
            reason: connetto_peer::CloseReason::Closed,
        });
    });
    let reasons = far_closes(&mut rx, Duration::from_secs(3)).await;
    late.await.expect("the sender ends");
    assert_eq!(reasons, [connetto_peer::CloseReason::Closed]);
}

/// The open of a fresh device serves the peer listener (R76 proof 1).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_fresh_device_serves_its_peer_listener_at_open() {
    let (key, der) = attesting_key();
    let now = whole_second();
    let authority = authority(now).await;
    let held = issue_for(&authority, &key, now, 12 * HOUR, positive_serial(5));
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| handle.peer_address().is_some()).await;

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// The refusal of a device past its expiry, which also raises the event
/// (R76 proof 2).
#[cfg(feature = "peer")]
#[tokio::test]
async fn an_expired_device_refuses_to_link_and_raises_the_event() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    // Past its end plus the tolerance, so the window no longer holds it.
    let held = issue_for(
        &authority,
        &key,
        now - 22 * HOUR,
        12 * HOUR,
        positive_serial(5),
    );
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    let err = handle
        .link_peer("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect_err("the expiry refuses the link");
    assert!(
        matches!(err, PeerError::CertificateExpired),
        "the refusal names the expiry, got {err:?}"
    );
    poll_until(|| {
        state
            .lock()
            .emitted
            .contains(&ClientEvent::CertificateExpired)
    })
    .await;
    assert!(
        handle.peer_address().is_none(),
        "nothing serves an expired identity"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// The refusal of a device whose clock puts its certificate outside its
/// window (R76 proof 3).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_clock_off_device_refuses_to_link_outside_its_window() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    // Not yet valid by more than the tolerance, so the local clock is off.
    let held = issue_for(
        &authority,
        &key,
        now + 10 * MINUTE,
        12 * HOUR,
        positive_serial(5),
    );
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    let err = handle
        .link_peer("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect_err("the window refuses the link");
    assert!(
        matches!(err, PeerError::ClockOutsideWindow),
        "the refusal names the window, got {err:?}"
    );
    // The only window event is the task's own, raised once at open.
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .filter(|event| matches!(event, ClientEvent::ClockOutsideWindow { .. }))
            .count()
            == 1
    })
    .await;
    assert!(
        state
            .lock()
            .emitted
            .iter()
            .all(|event| !matches!(event, ClientEvent::CertificateExpired)),
        "a window refusal is not an expiry"
    );
    assert!(
        handle.peer_address().is_none(),
        "nothing serves a window-out identity"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A grant the local clock already puts past `not_after` lands the task in
/// the window refusal, so a dial is refused by the window, not the expiry,
/// and no expiry event joins the task's own (R76 proof 3).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_grant_past_its_window_refuses_the_dial_as_a_window() {
    let (_, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    // The server just granted it, so a window that does not hold it now says
    // the local clock runs ahead of `not_after`.
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
        gate: None,
        grant_from: Some(now - 13 * HOUR),
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| !state.lock().stored.is_empty()).await;
    let err = handle
        .link_peer("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect_err("the window refuses the dial");
    assert!(
        matches!(err, PeerError::ClockOutsideWindow),
        "the refusal names the window, got {err:?}"
    );
    // The window event is the task's own, raised once at the grant.
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::ClockOutsideWindow { ahead: true }))
    })
    .await;
    assert!(
        state
            .lock()
            .emitted
            .iter()
            .all(|event| !matches!(event, ClientEvent::CertificateExpired)),
        "a window refusal is not an expiry"
    );
    assert!(
        handle.peer_address().is_none(),
        "nothing serves a window-out identity"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// The refusal of a device that holds no certificate (R76 proof 4).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_certificate_less_device_refuses_to_link() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    let err = handle
        .link_peer("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect_err("no certificate refuses the link");
    assert!(
        matches!(err, PeerError::NoIdentity),
        "the refusal names the missing identity, got {err:?}"
    );
    assert!(
        handle.peer_address().is_none(),
        "nothing serves an identity-less device"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// The look that wakes at the expiry plus the tolerance closes the live peer
/// links and the listener (R76 proof 5).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_look_at_the_expiry_closes_the_live_peer_links() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    // Within the tolerance of its end, so the window holds the link for a
    // short while, the expiry plus the tolerance landing 30 s after the open.
    let held = issue_for(
        &authority,
        &key,
        now + Duration::from_secs(30) - 7 * MINUTE,
        2 * MINUTE,
        positive_serial(5),
    );
    let task_identity = held.leaf.identity().clone();
    let deadline = held.leaf.not_after() + TOLERANCE;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let (far, mut far_events) = far_peer(&authority, positive_serial(9));
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    // The open serves the aging identity.
    poll_until(|| handle.peer_address().is_some()).await;
    let addr = handle.peer_address().expect("the open bound a listener");
    // A live peer dials it.
    let peer_identity = far.link(addr).await.expect("the link completes");
    assert_eq!(
        peer_identity, task_identity,
        "the link answers the device's identity"
    );
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::PeerLinked { .. }))
    })
    .await;
    let linked_peer = state
        .lock()
        .emitted
        .iter()
        .find_map(|event| match event {
            ClientEvent::PeerLinked { peer } => Some(peer.clone()),
            _ => None,
        })
        .expect("the link reports its peer");
    assert_eq!(
        handle.linked_peers(),
        vec![linked_peer],
        "the device's node reports its live peer"
    );

    // The look wakes at the expiry plus the tolerance and closes the link. A late
    // wake can make this task and the look ready at once, so the close is polled for.
    tokio::time::sleep(
        deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default(),
    )
    .await;
    poll_until(|| handle.peer_address().is_none()).await;
    let task_reason = state.lock().emitted.iter().find_map(|event| {
        if let ClientEvent::PeerUnlinked { reason, .. } = event {
            Some(*reason)
        } else {
            None
        }
    });
    let far_reasons = far_closes(&mut far_events, Duration::from_secs(3)).await;
    assert!(
        task_reason == Some(connetto_peer::CloseReason::CertificateExpired)
            || far_reasons.contains(&connetto_peer::CloseReason::PeerExpired),
        "one end closed the link with its own deadline reason, task {task_reason:?} far {far_reasons:?}"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A renewal granted to an aging device keeps the peer port and the live
/// link, whose deadline the granted chain moves (R76 proof 6).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_granted_renewal_keeps_the_peer_port_and_the_live_link() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    // Aging with a short window, so the old chain's deadline lands 30 s
    // after the open.
    let held = issue_for(
        &authority,
        &key,
        now + Duration::from_secs(30) - 7 * MINUTE,
        2 * MINUTE,
        positive_serial(5),
    );
    let deadline = held.leaf.not_after() + TOLERANCE;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let gate = Arc::new(tokio::sync::Notify::new());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let (far, mut far_events) = far_peer(&authority, positive_serial(9));
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
        gate: Some(gate.clone()),
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| handle.peer_address().is_some()).await;
    let addr = handle.peer_address().expect("the open bound a listener");
    let _ = far.link(addr).await.expect("the link completes");
    // The renewal is open on the gate while the link lives on the old
    // chain's deadline.
    poll_until(|| state.lock().requests.len() == 1).await;
    gate.notify_waiters();
    poll_until(|| state.lock().stored.len() == 1).await;
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::PeerLinked { .. }))
    })
    .await;

    // Past the old deadline, the link is still live on both ends.
    tokio::time::sleep(
        (deadline + Duration::from_secs(5))
            .duration_since(SystemTime::now())
            .unwrap_or_default(),
    )
    .await;
    {
        let state = state.lock();
        assert!(
            state
                .emitted
                .iter()
                .all(|event| !matches!(event, ClientEvent::PeerUnlinked { .. })),
            "the link outlived the old deadline, so its deadline moved"
        );
    }
    assert_eq!(handle.peer_address(), Some(addr), "the grant kept the port");
    let far_reasons = far_closes(&mut far_events, Duration::from_secs(2)).await;
    assert!(
        far_reasons.is_empty(),
        "the far end kept the link, reasons {far_reasons:?}"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A peer-received list that revokes this device's own serial ends in
/// `ClientEvent::DeviceRevoked` with every peer link closed (R76 proof 7).
#[cfg(feature = "peer")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the two far links and the kept list are one scenario, in the order the revocation crosses them"
)]
async fn a_peer_list_revoking_the_own_serial_revokes_the_device() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    let held = issue_for(&authority, &key, now, 12 * HOUR, positive_serial(5));
    let own_serial = held.leaf.serial().to_vec();
    // The list revoking the device's own serial, signed before the fake
    // link takes the issuer.
    let list = authority
        .issuer
        .sign_list(
            1,
            &[Revoked {
                serial: own_serial.clone(),
                at: now,
            }],
            now,
            now + 12 * HOUR,
        )
        .expect("the list signs");
    let signer = authority.certificate.clone();
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let (keeper, mut keeper_events) = far_peer(&authority, positive_serial(9));
    let (other, mut other_events) = far_peer(&authority, positive_serial(10));
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| handle.peer_address().is_some()).await;
    let addr = handle.peer_address().expect("the open bound a listener");
    let _ = keeper.link(addr).await.expect("the first link");
    let _ = other.link(addr).await.expect("the second link");
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .filter(|event| matches!(event, ClientEvent::PeerLinked { .. }))
            .count()
            == 2
    })
    .await;

    // The list-keeping peer keeps the list revoking the device's own serial.
    keeper.keep_list(list, signer);

    poll_until(|| state.lock().emitted.contains(&ClientEvent::DeviceRevoked)).await;
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .filter(|event| matches!(event, ClientEvent::PeerUnlinked { .. }))
            .count()
            == 2
    })
    .await;
    assert!(handle.peer_address().is_none(), "the listener closed");
    {
        let state = state.lock();
        let task_reasons = state
            .emitted
            .iter()
            .filter_map(|event| {
                if let ClientEvent::PeerUnlinked { reason, .. } = event {
                    Some(*reason)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert!(
            task_reasons.contains(&connetto_peer::CloseReason::Revoked),
            "the device's own close names the revocation, reasons {task_reasons:?}"
        );
    }
    // The list-keeping peer closed the link with its own reason.
    let keeper_reasons = far_closes(&mut keeper_events, Duration::from_secs(3)).await;
    assert!(
        keeper_reasons.contains(&connetto_peer::CloseReason::PeerRevoked),
        "the list-keeping peer names its revocation, reasons {keeper_reasons:?}"
    );
    // The other link went as the device's own stop says, and its end
    // sees the close as the device's.
    let other_reasons = far_closes(&mut other_events, Duration::from_secs(3)).await;
    assert_eq!(
        other_reasons,
        vec![connetto_peer::CloseReason::Closed],
        "the other end sees the close as the device's"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A peer-received list the device already keeps changes nothing (R76
/// proof 8).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_stale_peer_list_changes_nothing() {
    let (key, der) = attesting_key();
    let now = SystemTime::now();
    let authority = authority(now).await;
    let held = issue_for(&authority, &key, now, 12 * HOUR, positive_serial(5));
    // A list from the test issuer, numbering one and naming a serial that
    // is not the device's own.
    let list = authority
        .issuer
        .sign_list(
            1,
            &[Revoked {
                serial: vec![8; 16],
                at: now,
            }],
            now,
            now + 12 * HOUR,
        )
        .expect("the list signs");
    let signer = authority.certificate.clone();
    let signer_key =
        connetto_core::device_cert::certificate_key_id(&signer).expect("the issuer's key");
    let kept = KeptList {
        signer_key: signer_key.as_bytes().to_vec(),
        number: 1,
        list: list.clone(),
        signer: signer.clone(),
    };
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    #[cfg(feature = "peer")]
    let peer = peer(&authority);
    let (far, _far_events) = far_peer(&authority, positive_serial(9));
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        vec![kept],
        inbox(),
        peer,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| handle.peer_address().is_some()).await;
    let addr = handle.peer_address().expect("the open bound a listener");
    let _ = far.link(addr).await.expect("the link completes");
    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::PeerLinked { .. }))
    })
    .await;

    // The far keeps the very list the device already holds.
    far.keep_list(list, signer);
    tokio::time::sleep(Duration::from_secs(2)).await;
    {
        let state = state.lock();
        assert!(state.lists.is_empty(), "the kept list is not re-stored");
        assert!(
            state
                .emitted
                .iter()
                .all(|event| !matches!(event, ClientEvent::PeerUnlinked { .. })),
            "no close for a stale list"
        );
    }
    assert!(handle.peer_address().is_some(), "the listener stays");

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// Whether `state` has reported the instance `fingerprint` found (R76).
#[cfg(feature = "peer")]
fn reports_found(state: &Arc<Mutex<FakeState>>, fingerprint: connetto_peer::Fingerprint) -> bool {
    state.lock().emitted.iter().any(|event| {
        matches!(
            event,
            ClientEvent::PeerFound {
                fingerprint: found,
                ..
            } if *found == fingerprint
        )
    })
}

/// Whether `state` has reported a peer link (R76).
#[cfg(feature = "peer")]
fn reports_linked(state: &Arc<Mutex<FakeState>>) -> bool {
    state
        .lock()
        .emitted
        .iter()
        .any(|event| matches!(event, ClientEvent::PeerLinked { .. }))
}

/// Two clients on loopback discover each other through mDNS and autolink with
/// no `link_peer` call, each reporting the other found (R76 proof 4).
#[cfg(feature = "peer")]
#[tokio::test]
async fn two_clients_discover_each_other_and_autolink() {
    if !loopback_multicast() {
        eprintln!("the host will not multicast on the loopback, so the discovery proof skips");
        return;
    }
    eprintln!("R76-PROOF-RAN two_clients_discover_each_other_and_autolink");
    let (key_a, der_a) = attesting_key();
    let (key_b, der_b) = attesting_key();
    let now = whole_second();
    let authority = authority(now).await;
    let held_a = issue_for(&authority, &key_a, now, 12 * HOUR, positive_serial(5));
    let held_b = issue_for(&authority, &key_b, now, 12 * HOUR, positive_serial(6));
    let fp_a = connetto_peer::Fingerprint::of(&held_a.certificate);
    let fp_b = connetto_peer::Fingerprint::of(&held_b.certificate);
    let port = fresh_mdns_port();
    let peer_a = peer_with(&authority, true, port);
    let peer_b = peer_with(&authority, true, port);
    let issuer = Arc::new(authority.issuer);
    let state_a = Arc::new(Mutex::new(FakeState::default()));
    let (events_a, _events_a) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let state_b = Arc::new(Mutex::new(FakeState::default()));
    let (events_b, _events_b) = broadcast::channel(64);
    let (fin_tx, fin_rx) = watch::channel(());
    let link_a = FakeLink {
        state: Arc::clone(&state_a),
        events: events_a,
        end: end_rx,
        issuer: Arc::clone(&issuer),
        certificate: authority.certificate.clone(),
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    let link_b = FakeLink {
        state: Arc::clone(&state_b),
        events: events_b,
        end: fin_rx,
        issuer: Arc::clone(&issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller_a, _handle_a) = Enroller::new(
        Arc::new(RunKeys { der: der_a }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held_a),
        Vec::new(),
        inbox(),
        peer_a,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller_b, _handle_b) = Enroller::new(
        Arc::new(RunKeys { der: der_b }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held_b),
        Vec::new(),
        inbox(),
        peer_b,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run_a = tokio::spawn(run(link_a, enroller_a));
    let run_b = tokio::spawn(run(link_b, enroller_b));

    poll_until(|| reports_found(&state_a, fp_b)).await;
    poll_until(|| reports_found(&state_b, fp_a)).await;
    poll_until(|| reports_linked(&state_a)).await;
    poll_until(|| reports_linked(&state_b)).await;

    end_tx.send(()).expect("the run ends");
    fin_tx.send(()).expect("the run ends");
    run_a.await.expect("the run ends");
    run_b.await.expect("the run ends");
}

/// Two clients on loopback with autolink off report each other found and link
/// only the one that calls `link_peer` (R76 proof 4).
#[cfg(feature = "peer")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the two reports and the call's one link are one scenario, in the order discovery crosses them"
)]
async fn clients_without_autolink_report_and_link_only_on_the_call() {
    if !loopback_multicast() {
        eprintln!("the host will not multicast on the loopback, so the discovery proof skips");
        return;
    }
    eprintln!("R76-PROOF-RAN clients_without_autolink_report_and_link_only_on_the_call");
    let (key_a, der_a) = attesting_key();
    let (key_b, der_b) = attesting_key();
    let now = whole_second();
    let authority = authority(now).await;
    let held_a = issue_for(&authority, &key_a, now, 12 * HOUR, positive_serial(5));
    let held_b = issue_for(&authority, &key_b, now, 12 * HOUR, positive_serial(6));
    let fp_a = connetto_peer::Fingerprint::of(&held_a.certificate);
    let fp_b = connetto_peer::Fingerprint::of(&held_b.certificate);
    let port = fresh_mdns_port();
    let peer_a = peer_with(&authority, false, port);
    let peer_b = peer_with(&authority, false, port);
    let issuer = Arc::new(authority.issuer);
    let state_a = Arc::new(Mutex::new(FakeState::default()));
    let (events_a, _events_a) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let state_b = Arc::new(Mutex::new(FakeState::default()));
    let (events_b, _events_b) = broadcast::channel(64);
    let (fin_tx, fin_rx) = watch::channel(());
    let link_a = FakeLink {
        state: Arc::clone(&state_a),
        events: events_a,
        end: end_rx,
        issuer: Arc::clone(&issuer),
        certificate: authority.certificate.clone(),
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    let link_b = FakeLink {
        state: Arc::clone(&state_b),
        events: events_b,
        end: fin_rx,
        issuer: Arc::clone(&issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller_a, handle_a) = Enroller::new(
        Arc::new(RunKeys { der: der_a }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held_a),
        Vec::new(),
        inbox(),
        peer_a,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    #[cfg(feature = "peer")]
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    #[cfg(feature = "peer")]
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller_b, _handle_b) = Enroller::new(
        Arc::new(RunKeys { der: der_b }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held_b),
        Vec::new(),
        inbox(),
        peer_b,
        #[cfg(feature = "peer")]
        hotspot_tx,
        #[cfg(feature = "peer")]
        bluetooth_tx,
    );
    let run_a = tokio::spawn(run(link_a, enroller_a));
    let run_b = tokio::spawn(run(link_b, enroller_b));

    poll_until(|| reports_found(&state_a, fp_b)).await;
    poll_until(|| reports_found(&state_b, fp_a)).await;
    // Seconds past the find, and nothing dials itself.
    tokio::time::sleep(Duration::from_secs(3)).await;
    {
        let (a, b) = (state_a.lock(), state_b.lock());
        assert!(
            a.emitted
                .iter()
                .all(|event| !matches!(event, ClientEvent::PeerLinked { .. })),
            "autolink off dials nothing"
        );
        assert!(
            b.emitted
                .iter()
                .all(|event| !matches!(event, ClientEvent::PeerLinked { .. })),
            "autolink off dials nothing"
        );
    }
    let address = state_a
        .lock()
        .emitted
        .iter()
        .find_map(|event| match event {
            ClientEvent::PeerFound {
                address,
                fingerprint,
            } if *fingerprint == fp_b => Some(*address),
            _ => None,
        })
        .expect("the found report carries the other's address");
    handle_a.link_peer(address).await.expect("the call links");
    poll_until(|| reports_linked(&state_a)).await;
    poll_until(|| reports_linked(&state_b)).await;

    end_tx.send(()).expect("the run ends");
    fin_tx.send(()).expect("the run ends");
    run_a.await.expect("the run ends");
    run_b.await.expect("the run ends");
}

/// A device key that will not open, for the refusal paths the task and the
/// handle report (R76 slice 5a).
struct RefusingKeys;

impl DeviceKeys for RefusingKeys {
    fn open(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<OpenedKey<Box<dyn DeviceKey>>, ClientError>> + Send + '_>>
    {
        Box::pin(async { Err(ClientError::Transport("the key will not open".into())) })
    }

    fn delete(&self) -> Pin<Box<dyn Future<Output = Result<(), ClientError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

/// A handle beside the machines' command channels, for the handle's hotspot
/// and Bluetooth calls (R76 slice 5a). The task runs no machines here, so a
/// test answers the commands itself.
#[cfg(feature = "peer")]
async fn handle_with_machines() -> (
    EnrolHandle,
    mpsc::UnboundedReceiver<crate::hotspot::Command>,
    mpsc::UnboundedReceiver<crate::bluetooth::Command>,
) {
    let authority = authority(whole_second()).await;
    let (hotspot_tx, hotspot_rx) = mpsc::unbounded_channel();
    let (bluetooth_tx, bluetooth_rx) = mpsc::unbounded_channel();
    let (_, handle) = Enroller::new(
        Arc::new(RefusingKeys),
        None,
        Vec::new(),
        vec![authority.root.clone()],
        None,
        Vec::new(),
        inbox(),
        peer(&authority),
        hotspot_tx,
        bluetooth_tx,
    );
    (handle, hotspot_rx, bluetooth_rx)
}

/// The hotspot's call answers from the machine's answer, and a machine that
/// drops the reply fails the call within its bound (R76).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_host_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::Host(reply) = command else {
            panic!("the host's request reaches the Bluetooth machine");
        };
        let offer = crate::hotspot::HotspotOffer::new(
            "camp",
            "opensesame",
            crate::hotspot::HotspotSecurity::Wpa2,
            Some(5678),
        );
        let _ = reply.send(Ok(crate::bluetooth::Hosted {
            offer,
            beacon: Ok(()),
        }));
    });
    let hosted = handle.host_hotspot().await.expect("the machine answers");
    assert_eq!(
        hosted.offer.ssid, "camp",
        "the machine's offer reaches the caller"
    );
    assert!(hosted.beacon.is_ok(), "the beacon stands beside the offer");
    machine.await.expect("the machine ends");

    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        // The machine dies without answering, so the reply is dropped.
        drop(command);
    });
    let error = handle
        .host_hotspot()
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(error, crate::hotspot::HotspotError::Failed),
        "a gone machine fails the call, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The join's call answers from the hotspot machine's gateway, and a machine
/// that drops the reply fails the call within its bound (R76).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_join_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, mut hotspot, _bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = hotspot.recv().await.expect("the machine runs");
        let crate::hotspot::Command::Join { reply, .. } = command else {
            panic!("the join's request reaches the hotspot machine");
        };
        let _ = reply.send(Ok("192.168.4.1".parse().expect("a private gateway")));
    });
    let offer = crate::hotspot::HotspotOffer::new(
        "camp",
        "opensesame",
        crate::hotspot::HotspotSecurity::Wpa2,
        Some(5678),
    );
    let gateway = handle
        .join_hotspot(&offer)
        .await
        .expect("the machine answers");
    assert_eq!(
        gateway,
        "192.168.4.1"
            .parse::<std::net::IpAddr>()
            .expect("a private gateway"),
        "the machine's gateway reaches the caller"
    );
    machine.await.expect("the machine ends");

    let (handle, mut hotspot, _bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = hotspot.recv().await.expect("the machine runs");
        drop(command);
    });
    let error = handle
        .join_hotspot(&offer)
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(error, crate::hotspot::JoinError::Failed),
        "a gone machine fails the join, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The personal host's call answers from the machine's typed offer, the
/// details as the caller typed them, and a machine that drops the reply
/// fails the call within its bound (R76 decision 26).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_personal_host_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::PersonalHost {
            ssid,
            passphrase,
            caller,
        } = command
        else {
            panic!("the personal host's request reaches the Bluetooth machine");
        };
        assert_eq!(ssid, "iphone");
        assert_eq!(passphrase, "the passphrase");
        let offer = crate::hotspot::HotspotOffer::new(
            "iphone",
            "the passphrase",
            crate::hotspot::HotspotSecurity::Wpa2,
            Some(5678),
        );
        let _ = caller.send(Ok(crate::bluetooth::Hosted {
            offer,
            beacon: Ok(()),
        }));
    });
    let hosted = handle
        .host_personal_hotspot("iphone", "the passphrase")
        .await
        .expect("the machine answers");
    assert_eq!(
        hosted.offer.ssid, "iphone",
        "the machine's typed offer reaches the caller"
    );
    assert!(hosted.beacon.is_ok(), "the beacon stands beside the offer");
    machine.await.expect("the machine ends");

    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        // The machine dies without answering, so the reply is dropped.
        drop(command);
    });
    let error = handle
        .host_personal_hotspot("iphone", "the passphrase")
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(error, crate::hotspot::HotspotError::Failed),
        "a gone machine fails the call, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The personal host's bound runs when the machine answers nothing (R76
/// decision 26).
#[cfg(feature = "peer")]
#[tokio::test(start_paused = true)]
async fn a_personal_host_call_answers_timed_out_when_the_machine_stays_silent() {
    let (handle, _hotspot, _bluetooth) = handle_with_machines().await;
    let error = handle
        .host_personal_hotspot("iphone", "the passphrase")
        .await
        .expect_err("nothing answers the personal host");
    assert!(
        matches!(error, crate::hotspot::HotspotError::TimedOut),
        "the bound runs, got {error:?}"
    );
}

/// The enable's call answers from the machine's answer, and a machine that
/// drops the reply fails the call within its bound (R76 decision 21).
#[cfg(feature = "peer")]
#[tokio::test]
async fn an_enable_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::Enable(reply) = command else {
            panic!("the enable's request reaches the Bluetooth machine");
        };
        let _ = reply.send(Ok(()));
    });
    handle
        .enable_bluetooth()
        .await
        .expect("the machine answers");
    machine.await.expect("the machine ends");

    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        drop(command);
    });
    let error = handle
        .enable_bluetooth()
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(error, crate::bluetooth::BluetoothError::Failed(_)),
        "a gone machine fails the enable, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The identity a nearby host proves in the exchange, as the fake machines
/// answer it.
#[cfg(feature = "peer")]
fn nearby_host_identity() -> connetto_core::device_cert::DeviceIdentity {
    connetto_core::device_cert::DeviceIdentity::new(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        "host",
        connetto_core::device_cert::KeyId::from_bytes([7; 32]),
    )
    .expect("an identity holds")
}

/// The nearby join's call answers from the machine's gateway, and a machine
/// that drops the reply fails the call within its bound (R76 decision 19).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_join_nearby_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::JoinNearby { host, reply, .. } = command else {
            panic!("the nearby join's request reaches the Bluetooth machine");
        };
        assert_eq!(host, 9, "the request names the host");
        let _ = reply.send(Ok((
            nearby_host_identity(),
            "192.168.4.1".parse().expect("a private gateway"),
        )));
    });
    let (identity, gateway) = handle.join_nearby(&9).await.expect("the machine answers");
    assert_eq!(
        identity,
        nearby_host_identity(),
        "the host's proven identity reaches the caller"
    );
    assert_eq!(
        gateway,
        "192.168.4.1"
            .parse::<std::net::IpAddr>()
            .expect("a private gateway"),
        "the machine's gateway reaches the caller"
    );
    machine.await.expect("the machine ends");

    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        drop(command);
    });
    let error = handle
        .join_nearby(&9)
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(
            error,
            crate::bluetooth::JoinNearbyError::Join(crate::hotspot::JoinError::Failed)
        ),
        "a gone machine fails the nearby join, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The fetch's call answers from the machine's offer, and a machine that
/// drops the reply fails the call within its bound (R76 decision 19).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_fetch_call_answers_from_the_machine_and_fails_when_the_machine_is_gone() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::Fetch { host, reply, .. } = command else {
            panic!("the fetch's request reaches the Bluetooth machine");
        };
        assert_eq!(host, 3, "the request names the host");
        let _ = reply.send(Ok((
            nearby_host_identity(),
            crate::hotspot::HotspotOffer::new(
                "camp",
                "opensesame",
                crate::hotspot::HotspotSecurity::Wpa2,
                Some(5678),
            ),
        )));
    });
    let (identity, offer) = handle.fetch_offer(&3).await.expect("the machine answers");
    assert_eq!(
        identity,
        nearby_host_identity(),
        "the host's proven identity reaches the caller"
    );
    assert_eq!(offer.ssid, "camp", "the machine's offer reaches the caller");
    machine.await.expect("the machine ends");

    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        drop(command);
    });
    let error = handle
        .fetch_offer(&3)
        .await
        .expect_err("the machine is gone");
    assert!(
        matches!(error, crate::bluetooth::BluetoothError::Failed(_)),
        "a gone machine fails the fetch, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// A machine's typed refusal crosses the handle's call unchanged, so the
/// app knows an exchange already runs when a fetch is refused (R76
/// decision 19).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_machine_refusal_keeps_its_typed_reason() {
    let (handle, _hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::Fetch { reply, .. } = command else {
            panic!("the fetch's request reaches the Bluetooth machine");
        };
        // An exchange already runs, so the machine answers `Busy`.
        let _ = reply.send(Err(crate::bluetooth::BluetoothError::Busy));
    });
    let error = handle
        .fetch_offer(&3)
        .await
        .expect_err("the exchange is running");
    assert!(
        matches!(error, crate::bluetooth::BluetoothError::Busy),
        "the refusal keeps its typed reason, got {error:?}"
    );
    machine.await.expect("the machine ends");
}

/// The runtime standings reach their machine with their values, and a stop
/// and a leave each reach the hotspot machine (R76).
#[cfg(feature = "peer")]
#[tokio::test]
async fn the_runtime_standings_and_their_cancels_reach_their_machines() {
    let (handle, mut hotspot, mut bluetooth) = handle_with_machines().await;
    let machine = tokio::spawn(async move {
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::SetScan(on) = command else {
            panic!("the scan's standing reaches the Bluetooth machine");
        };
        assert!(on);
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::SetAutojoin(on) = command else {
            panic!("the autojoin's standing reaches the Bluetooth machine");
        };
        assert!(!on);
        let command = bluetooth.recv().await.expect("the machine runs");
        let crate::bluetooth::Command::SetPrompt(on) = command else {
            panic!("the prompt's standing reaches the Bluetooth machine");
        };
        assert!(on);
        let command = hotspot.recv().await.expect("the machine runs");
        assert!(
            matches!(command, crate::hotspot::Command::StopHost),
            "the stop reaches the hotspot machine"
        );
        let command = hotspot.recv().await.expect("the machine runs");
        assert!(
            matches!(command, crate::hotspot::Command::Leave),
            "the leave reaches the hotspot machine"
        );
    });
    handle.set_hotspot_scan(true);
    handle.set_hotspot_autojoin(false);
    handle.set_bluetooth_prompt(true);
    handle.stop_hotspot();
    handle.leave_hotspot();
    machine.await.expect("the machine ends");
}

/// A device whose key will not open serves no peer listener, so the device
/// dials but does not serve until the key stands (R76).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_device_without_a_usable_key_serves_no_peer_listener() {
    let (key, _der) = attesting_key();
    let now = whole_second();
    let authority = authority(now).await;
    let held = issue_for(&authority, &key, now, 12 * HOUR, positive_serial(5));
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let peer = peer(&authority);
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RefusingKeys),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        hotspot_tx,
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    // The fresh standing takes the serve path and the key opens nothing, so
    // nothing serves for a bounded look.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        handle.peer_address().is_none(),
        "the key will not open, so the listener waits"
    );
    assert!(
        handle.peer_serving_fingerprint().is_none(),
        "nothing is served to the machines"
    );
    assert!(
        !state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::PeerListenFailed { .. })),
        "the key refusal is not a bind failure"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}

/// A peer listener that will not bind reports the failure to the
/// application, so the device dials but does not serve (R76).
#[cfg(feature = "peer")]
#[tokio::test]
async fn a_peer_listener_that_will_not_bind_reports_the_failure() {
    let (key, der) = attesting_key();
    let now = whole_second();
    let authority = authority(now).await;
    let held = issue_for(&authority, &key, now, 12 * HOUR, positive_serial(5));
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    // A listener on an address no interface holds, so the bind refuses.
    let listen: std::net::SocketAddr = "192.0.2.1:443".parse().expect("a test-net address");
    let (tx, rx) = mpsc::unbounded_channel();
    let node = connetto_peer::Node::new(
        connetto_peer::Trust {
            roots: vec![authority.root.clone()],
            accepted: AttestationLevel::ALL.to_vec(),
        },
        Arc::new(connetto_peer::SystemClock),
        tx,
    )
    .expect("the roots hold keys");
    let (discovery_events, discovery_events_rx) = mpsc::unbounded_channel();
    let peer = Peer {
        node: node.clone(),
        discovery: connetto_peer::Discovery::new(node, true, discovery_events)
            .with_mdns_port(fresh_mdns_port())
            .loopback_only(),
        listen,
        events: rx,
        discovery_events: discovery_events_rx,
        #[cfg(all(feature = "peer", target_os = "android"))]
        java: None,
    };
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
        gate: None,
        grant_from: None,
    };
    let (hotspot_tx, _hotspot_rx) = mpsc::unbounded_channel();
    let (bluetooth_tx, _bluetooth_rx) = mpsc::unbounded_channel();
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root.clone()],
        Some(held),
        Vec::new(),
        inbox(),
        peer,
        hotspot_tx,
        bluetooth_tx,
    );
    let run = tokio::spawn(run(link, enroller));

    poll_until(|| {
        state
            .lock()
            .emitted
            .iter()
            .any(|event| matches!(event, ClientEvent::PeerListenFailed { .. }))
    })
    .await;
    let failed = state
        .lock()
        .emitted
        .iter()
        .find_map(|event| match event {
            ClientEvent::PeerListenFailed { address, .. } => Some(*address),
            _ => None,
        })
        .expect("the failure names its address");
    assert_eq!(failed, listen, "the failure names the address it tried");
    assert!(
        handle.peer_address().is_none(),
        "nothing serves a refused bind"
    );

    end_tx.send(()).expect("the run ends");
    run.await.expect("the run ends");
}
