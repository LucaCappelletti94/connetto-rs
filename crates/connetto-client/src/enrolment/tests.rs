use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use base64::Engine as _;
use connetto_core::device_cert::{
    AttestationLevel, CertificateRequest, CertificateSigner, DeploymentId, DeviceCertificate,
    DeviceIssuer, DeviceKey, DeviceKeyError, KeyHome, RevocationList, Revoked, RootCa,
    public_key_info,
};
use connetto_core::messages::{ControlMessage, DeviceAttestation, EnrolRefusal, SyncStatus};
use diesel::Connection as _;
use diesel::connection::SimpleConnection as _;
use diesel::sqlite::SqliteConnection;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_bytes::ByteBuf;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::task::next_look;
use super::{
    Answer, CERTIFICATE_DDL, CertificateError, DeviceKeys, Enroller, Held, Intake, KeptList, Link,
    ListInbox, Standing, TOLERANCE, delete, intake, load, run, store,
};
use crate::ClientError;
use crate::ClientEvent;
use crate::device_key::{KeyRecords, OpenedKey, open_software_key};

const HOUR: Duration = Duration::from_hours(1);

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
            [2; 16],
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
            [3; 16],
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
        next_look(Some(&short), start + 3 * HOUR),
        HOUR,
        "an aging one is retried hourly"
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
            [4; 16],
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
    serials: u64,
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
                    let mut state = state.lock();
                    state.requests.push(request.attestation);
                    let answer = match ask {
                        Ask::Refused(refusal) => Answer::Refused(refusal),
                        Ask::Silent => {
                            // The request went out and no answer comes.
                            drop(tx);
                            return Ok(rx);
                        }
                        _ => {
                            let request =
                                CertificateRequest::parse(&request.csr).expect("the csr parses");
                            let mut serial = [0u8; 16];
                            serial[..8].copy_from_slice(&state.serials.to_be_bytes());
                            state.serials += 1;
                            let leaf = issuer
                                .issue(
                                    &request,
                                    "alice",
                                    SystemTime::now(),
                                    12 * HOUR,
                                    serial,
                                    AttestationLevel::Unproven,
                                )
                                .expect("the grant issues");
                            Answer::Grant(vec![leaf, certificate], Vec::new())
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

    fn store_list(&self, _kept: KeptList) -> impl Future<Output = Result<(), ClientError>> + Send {
        Box::pin(async { Ok(()) })
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
            [2; 16],
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

/// A certificate `authority` issued for `key`, valid from `not_before` for
/// `lifetime`.
fn issue_for(
    authority: &Authority,
    key: &dyn DeviceKey,
    not_before: SystemTime,
    lifetime: Duration,
    serial: [u8; 16],
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::AttestationRequired),
    };
    let (enroller, _handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let held = issue_for(&authority, &key, now - 6 * HOUR, 12 * HOUR, [3; 16]);
    let old_serial = held.leaf.serial().to_vec();
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Grant,
    };
    let (enroller, _handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        Some(held),
        Vec::new(),
        inbox(),
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

/// A reissue refused as revoked deletes the device's key, says so, and the
/// caller gets the revocation.
#[tokio::test]
async fn a_reissue_refused_as_revoked_deletes_the_key_and_reports_revoked() {
    let (_, der) = attesting_key();
    let authority = authority(SystemTime::now()).await;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let (events, _events) = broadcast::channel(64);
    let (end_tx, end_rx) = watch::channel(());
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::Revoked),
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::OverCeiling { ceiling_secs: 600 }),
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Refused(EnrolRefusal::ChallengeExpired),
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Silent,
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Lost,
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
    let link = FakeLink {
        state: Arc::clone(&state),
        events,
        end: end_rx,
        issuer: Arc::new(authority.issuer),
        certificate: authority.certificate,
        ask: Ask::Violated,
    };
    let (enroller, handle) = Enroller::new(
        Arc::new(RunKeys { der }),
        Some(HOUR),
        Vec::new(),
        vec![authority.root],
        None,
        Vec::new(),
        inbox(),
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
