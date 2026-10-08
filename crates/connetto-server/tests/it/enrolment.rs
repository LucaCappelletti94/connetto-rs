//! Device enrolment over a live session (R74 step 3).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{
    ANDROID_ATTESTATION_CHALLENGE, AttestationLevel, CertificateRequest, CertificateSerial,
    DeploymentId, DeviceCertificate, DeviceIssuer, KeyId, RootCa,
};
use connetto_core::messages::{
    ControlMessage, DeviceAttestation, EnrolChallenge, EnrolChallengeRequest, EnrolGrant,
    EnrolRefusal, EnrolRefused, EnrolRequest,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::device_cert::{
    AndroidStatus, DeviceCertConfig, DeviceEnrolment, MemoryEnrolments, RandomSource, StatusList,
};
use connetto_server::{AbuseConfig, LoopbackTransport, RequestGuard, ThrottleConfig, loopback};
use connetto_test_harness::{Fixture, RosterAuth, WITHHELD_ID};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PublicKeyData as _,
};
use serde_bytes::ByteBuf;

use super::ticket_shared::{
    OkSigner, TicketManager, build_manager_with_guard, do_handshake_anon, do_handshake_with,
    setup_reader,
};

const DAY: Duration = Duration::from_hours(24);

/// An issuer valid for a year and a month from now, under a fresh root.
fn issuer() -> (Vec<u8>, DeviceIssuer) {
    let (_, cert, issuer) = rooted_issuer();
    (cert, issuer)
}

/// A fresh root's certificate, an issuer's certificate it signed, and the issuer.
pub(super) fn rooted_issuer() -> (Vec<u8>, Vec<u8>, DeviceIssuer) {
    let now = SystemTime::now();
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(0x5eed)),
        now - DAY,
        3650 * DAY,
    )
    .expect("root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let cert = root
        .sign_issuer(
            &key.subject_public_key_info(),
            now - DAY,
            395 * DAY,
            CertificateSerial::new([1; 16]).expect("the serial is positive"),
        )
        .expect("issuer");
    let issuer = DeviceIssuer::new(cert.clone(), key, root.certificate()).expect("load");
    (root.certificate().to_vec(), cert, issuer)
}

/// A session for `identity`, `None` meaning anonymous, against a manager that
/// enrols through `config` into `store` unless `config` is `None`.
async fn session(
    fixture: &Fixture,
    identity: Option<&str>,
    config: Option<DeviceCertConfig>,
    store: &Arc<MemoryEnrolments<String>>,
) -> LoopbackTransport {
    let manager = enrolling_manager(
        fixture,
        config.map(|config| DeviceEnrolment::new(config, Arc::clone(store) as _)),
    )
    .await;
    connect(&manager, identity).await
}

/// A manager that enrols through `enrolment` when one is given.
pub(super) async fn enrolling_manager(
    fixture: &Fixture,
    enrolment: Option<DeviceEnrolment<String>>,
) -> Arc<TicketManager<OkSigner>> {
    let manager = build_manager_with_guard(
        setup_reader(fixture).await,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(RequestGuard::new(
            ThrottleConfig::default(),
            AbuseConfig::default(),
        )),
        OkSigner,
    );
    if let Some(enrolment) = enrolment {
        manager
            .install_device_enrolment(Arc::new(enrolment))
            .unwrap_or_else(|_| panic!("installed once"));
    }
    manager
}

/// A session for `identity`, `None` meaning anonymous, on `manager`.
pub(super) async fn connect(
    manager: &Arc<TicketManager<OkSigner>>,
    identity: Option<&str>,
) -> LoopbackTransport {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let (server_end, mut client) = loopback();
    tokio::spawn(Arc::clone(manager).serve(server_end));
    // One session per connection, as one per login, since a second live
    // connection on one session supersedes the first.
    let handle = format!("conn-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    match identity {
        Some(identity) => {
            do_handshake_with(
                &mut client,
                &handle,
                &[&format!("user:{identity}#{handle}")],
            )
            .await;
        }
        None => do_handshake_anon(&mut client, &handle).await,
    }
    client
}

/// Send `message` and return the next control frame, past any revocation
/// lists the server pushes unasked.
pub(super) async fn ask(client: &mut LoopbackTransport, message: ControlMessage) -> ControlMessage {
    client.send_control(message).await.expect("send");
    loop {
        match client.recv().await.expect("recv") {
            Some(
                IncomingFrame::Control(ControlMessage::RevocationUpdate(_))
                | IncomingFrame::Bulk(_),
            ) => {}
            Some(IncomingFrame::Control(reply)) => return reply,
            None => panic!("the session closed"),
        }
    }
}

pub(super) async fn challenge(client: &mut LoopbackTransport) -> ControlMessage {
    ask(
        client,
        ControlMessage::EnrolChallengeRequest(EnrolChallengeRequest {
            request_id: "c".into(),
        }),
    )
    .await
}

pub(super) async fn nonce(client: &mut LoopbackTransport) -> [u8; 32] {
    match challenge(client).await {
        ControlMessage::EnrolChallenge(EnrolChallenge {
            request_id, nonce, ..
        }) => {
            assert_eq!(request_id, "c");
            nonce
        }
        other => panic!("expected a challenge, got {other:?}"),
    }
}

pub(super) async fn enrol(
    client: &mut LoopbackTransport,
    key: &KeyPair,
    nonce: [u8; 32],
    lifetime_secs: Option<u64>,
    descriptor: Vec<u8>,
) -> ControlMessage {
    enrol_attested(client, key, nonce, lifetime_secs, descriptor, None).await
}

pub(super) async fn enrol_attested(
    client: &mut LoopbackTransport,
    key: &KeyPair,
    nonce: [u8; 32],
    lifetime_secs: Option<u64>,
    descriptor: Vec<u8>,
    attestation: Option<DeviceAttestation>,
) -> ControlMessage {
    ask(
        client,
        ControlMessage::EnrolRequest(EnrolRequest {
            request_id: "e".into(),
            csr: CertificateRequest::build(key, &nonce).expect("csr"),
            lifetime_secs,
            descriptor,
            attestation,
        }),
    )
    .await
}

pub(super) fn refused(reason: EnrolRefusal, request_id: &str) -> ControlMessage {
    ControlMessage::EnrolRefused(EnrolRefused {
        request_id: request_id.into(),
        reason,
    })
}

pub(super) fn device_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key")
}

/// One DER tag-length-value in the short form the fixtures take.
fn der_tl(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![
        tag,
        u8::try_from(content.len()).expect("the fixture stays short"),
    ];
    out.extend_from_slice(content);
    out
}

/// A `KeyMint` `KeyDescription` the server parses: the version leads, the
/// security level is second, the fixed challenge is fifth.
fn keymint_description(level: u8) -> Vec<u8> {
    let children = [
        der_tl(0x02, &[0x00, 0x01, 0xF4]),
        der_tl(0x0A, &[level]),
        der_tl(0x04, b""),
        der_tl(0x30, &[0x01, 0x01, 0xFF]),
        der_tl(0x04, ANDROID_ATTESTATION_CHALLENGE),
    ];
    der_tl(0x30, &children.concat())
}

/// A chip-proven Android attestation for `key`: the attestation root's DER,
/// the chain (leaf first), and a clean status list to check it against.
pub(super) fn chip_attestation(key: &KeyPair) -> (Vec<u8>, Vec<Vec<u8>>, StatusList) {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("attestation root key");
    let mut root_params =
        CertificateParams::new(vec!["attestation root".to_owned()]).expect("root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_cert = root_params
        .self_signed(&root_key)
        .expect("attestation root");

    let intermediate_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate key");
    let mut intermediate_params =
        CertificateParams::new(vec!["attestation intermediate".to_owned()])
            .expect("intermediate params");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_issuer = Issuer::new(
        CertificateParams::new(vec!["attestation root".to_owned()]).expect("root params"),
        &root_key,
    );
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .expect("intermediate");

    let mut leaf_params = CertificateParams::new(vec!["device".to_owned()]).expect("leaf params");
    leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
        keymint_description(1),
    )];
    let intermediate_issuer = Issuer::new(
        CertificateParams::new(vec!["attestation intermediate".to_owned()])
            .expect("intermediate params"),
        &intermediate_key,
    );
    let leaf_cert = leaf_params
        .signed_by(key, &intermediate_issuer)
        .expect("leaf");

    let file = tempfile::NamedTempFile::new().expect("a status list file");
    std::fs::write(file.path(), r#"{"entries": {}}"#).expect("a clean status list");
    let status = StatusList::new(AndroidStatus::File(file.path().to_path_buf()));

    (
        root_cert.der().to_vec(),
        vec![
            leaf_cert.der().to_vec(),
            intermediate_cert.der().to_vec(),
            root_cert.der().to_vec(),
        ],
        status,
    )
}

/// The attestation a chain enrolment sends, the leaf's certificate first.
pub(super) fn android_evidence(chain: Vec<Vec<u8>>) -> DeviceAttestation {
    DeviceAttestation::AndroidKeyChain(chain.into_iter().map(ByteBuf::from).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_in_device_enrols_and_is_recorded() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (issuer_cert, issuer) = issuer();
    let mut client = session(
        &fixture,
        Some("alice"),
        Some(DeviceCertConfig::new(issuer)),
        &store,
    )
    .await;
    let key = device_key();
    let handed = nonce(&mut client).await;

    let reply = enrol(&mut client, &key, handed, None, vec![0x91, 0x01]).await;
    let ControlMessage::EnrolGrant(EnrolGrant {
        request_id, chain, ..
    }) = reply
    else {
        panic!("expected a grant, got {reply:?}");
    };
    assert_eq!(request_id, "e");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].as_slice(), issuer_cert.as_slice());
    let leaf = DeviceCertificate::parse(&chain[0]).expect("the leaf meets the profile");
    let key_id = KeyId::of_public_key(&key.subject_public_key_info());
    assert_eq!(leaf.identity().account(), "alice");
    assert_eq!(leaf.identity().key(), key_id);
    let lifetime = leaf
        .not_after()
        .duration_since(leaf.not_before())
        .expect("ordered");
    assert_eq!(lifetime, DAY, "an unrequested lifetime is the default");

    let records = store.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].user, "alice");
    assert_eq!(records[0].key, key_id);
    assert_eq!(records[0].serial.as_slice(), leaf.serial());
    assert_eq!(records[0].descriptor, vec![0x91, 0x01]);
}

/// The serial a held draw hands the enrolment, its leading zero a
/// certificate cannot carry.
const ZERO_LEADING: [u8; 16] = [
    0x00, 109, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
];
/// The serial a redraw hands it, one the certificate can carry.
const REDRAWN: [u8; 16] = [
    109, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
];

/// A source that holds its first 16-octet draw, a serial with a leading
/// zero, and hands the redraw one the certificate can carry.
struct HeldDraw {
    held: AtomicU32,
}

impl RandomSource for HeldDraw {
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        if dest.len() == 16 {
            let held = self.held.fetch_add(1, Ordering::Relaxed);
            dest.copy_from_slice(if held == 0 { &ZERO_LEADING } else { &REDRAWN });
        } else {
            dest.fill(0x11);
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_zero_leading_draw_is_redrawn_and_recorded_as_issued() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (issuer_cert, issuer) = issuer();
    let enrolment = DeviceEnrolment::new(DeviceCertConfig::new(issuer), Arc::clone(&store) as _)
        .with_random(Box::new(HeldDraw {
            held: AtomicU32::new(0),
        }));
    let manager = enrolling_manager(&fixture, Some(enrolment)).await;
    let mut client = connect(&manager, Some("alice")).await;
    let key = device_key();
    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, handed, None, vec![0x91, 0x01]).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain, .. }) = reply else {
        panic!("expected a grant, got {reply:?}");
    };
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].as_slice(), issuer_cert.as_slice());
    let leaf = DeviceCertificate::parse(&chain[0]).expect("the leaf meets the profile");
    assert_eq!(leaf.serial(), REDRAWN.as_slice());
    let records = store.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].serial.as_slice(), leaf.serial());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_caller_cannot_enrol() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let mut client = session(
        &fixture,
        None,
        Some(DeviceCertConfig::new(issuer().1)),
        &store,
    )
    .await;
    assert_eq!(
        challenge(&mut client).await,
        refused(EnrolRefusal::Unidentified, "c")
    );
    let reply = enrol(&mut client, &device_key(), [0; 32], None, Vec::new()).await;
    assert_eq!(reply, refused(EnrolRefusal::Unidentified, "e"));
    assert_eq!(store.records(), Vec::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_without_an_issuer_refuses() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let mut client = session(&fixture, Some("alice"), None, &store).await;
    assert_eq!(
        challenge(&mut client).await,
        refused(EnrolRefusal::IssuerUnavailable, "c")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nonce_serves_one_request_only() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let mut client = session(
        &fixture,
        Some("alice"),
        Some(DeviceCertConfig::new(issuer().1)),
        &store,
    )
    .await;
    let key = device_key();
    let reply = enrol(&mut client, &key, [9; 32], None, Vec::new()).await;
    assert_eq!(
        reply,
        refused(EnrolRefusal::ChallengeExpired, "e"),
        "no challenge was asked"
    );

    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, [9; 32], None, Vec::new()).await;
    assert_eq!(
        reply,
        refused(EnrolRefusal::ChallengeExpired, "e"),
        "a nonce the server never handed"
    );
    let reply = enrol(&mut client, &key, handed, None, Vec::new()).await;
    assert_eq!(
        reply,
        refused(EnrolRefusal::ChallengeExpired, "e"),
        "the failed attempt spent it"
    );

    let handed = nonce(&mut client).await;
    assert!(matches!(
        enrol(&mut client, &key, handed, None, Vec::new()).await,
        ControlMessage::EnrolGrant(_)
    ));
    let reply = enrol(&mut client, &key, handed, None, Vec::new()).await;
    assert_eq!(
        reply,
        refused(EnrolRefusal::ChallengeExpired, "e"),
        "a nonce is spent once used"
    );
    assert_eq!(store.records().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_nonce_is_refused() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let config = DeviceCertConfig::new(issuer().1).with_challenge_window(Duration::ZERO);
    let mut client = session(&fixture, Some("alice"), Some(config), &store).await;
    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &device_key(), handed, None, Vec::new()).await;
    assert_eq!(reply, refused(EnrolRefusal::ChallengeExpired, "e"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lifetime_over_the_ceiling_is_refused_and_one_under_it_granted() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let config = DeviceCertConfig::new(issuer().1).with_lifetime_ceiling(7 * DAY);
    let mut client = session(&fixture, Some("alice"), Some(config), &store).await;
    let key = device_key();
    let nonce_one = nonce(&mut client).await;
    let over = 7 * 86_400 + 1;
    let reply = enrol(&mut client, &key, nonce_one, Some(over), Vec::new()).await;
    assert_eq!(
        reply,
        refused(
            EnrolRefusal::OverCeiling {
                ceiling_secs: 7 * 86_400
            },
            "e"
        )
    );

    let nonce_two = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, nonce_two, Some(7 * 86_400), Vec::new()).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain, .. }) = reply else {
        panic!("expected a grant, got {reply:?}");
    };
    let leaf = DeviceCertificate::parse(&chain[0]).expect("profile");
    let lifetime = leaf
        .not_after()
        .duration_since(leaf.not_before())
        .expect("ordered");
    assert_eq!(lifetime, 7 * DAY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_key_is_refused() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let key = device_key();
    let mut client = session(
        &fixture,
        Some("alice"),
        Some(DeviceCertConfig::new(issuer().1)),
        &store,
    )
    .await;
    let handed = nonce(&mut client).await;
    assert!(matches!(
        enrol(&mut client, &key, handed, None, Vec::new()).await,
        ControlMessage::EnrolGrant(_)
    ));
    store.revoke_key(KeyId::of_public_key(&key.subject_public_key_info()));
    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, handed, None, Vec::new()).await;
    assert_eq!(reply, refused(EnrolRefusal::Revoked, "e"));
    assert_eq!(store.records().len(), 1, "the renewal records nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_request_or_oversized_descriptor_is_refused() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let mut client = session(
        &fixture,
        Some("alice"),
        Some(DeviceCertConfig::new(issuer().1)),
        &store,
    )
    .await;

    nonce(&mut client).await;
    let reply = ask(
        &mut client,
        ControlMessage::EnrolRequest(EnrolRequest {
            request_id: "e".into(),
            csr: b"not a request".to_vec(),
            lifetime_secs: None,
            descriptor: Vec::new(),
            attestation: None,
        }),
    )
    .await;
    assert_eq!(reply, refused(EnrolRefusal::InvalidRequest, "e"));

    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &device_key(), handed, None, vec![0; 4097]).await;
    assert_eq!(reply, refused(EnrolRefusal::InvalidRequest, "e"));
    assert_eq!(store.records(), Vec::new());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_keeps_the_attestation_level_the_first_enrolment_recorded() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (_, issuer) = issuer();
    let key = device_key();
    let (root, chain, status) = chip_attestation(&key);
    let config = DeviceCertConfig::new(issuer)
        .with_android_roots(vec![root])
        .with_accepted_attestation([AttestationLevel::ChipProven]);
    let manager = enrolling_manager(
        &fixture,
        Some(DeviceEnrolment::new(config, Arc::clone(&store) as _).with_status_list(status)),
    )
    .await;
    let mut client = connect(&manager, Some("alice")).await;

    // The first enrolment: a chip-proven chain records `chip-proven`.
    let handed = nonce(&mut client).await;
    let reply = enrol_attested(
        &mut client,
        &key,
        handed,
        None,
        vec![],
        Some(android_evidence(chain)),
    )
    .await;
    let ControlMessage::EnrolGrant(EnrolGrant {
        request_id,
        chain: granted,
        ..
    }) = reply
    else {
        panic!("expected a grant, got {reply:?}");
    };
    assert_eq!(request_id, "e");
    let leaf = DeviceCertificate::parse(&granted[0]).expect("the leaf meets the profile");
    assert_eq!(leaf.attestation(), AttestationLevel::ChipProven);

    // A renewal without any attestation keeps the recorded level.
    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, handed, None, vec![]).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain: renewed, .. }) = reply else {
        panic!("a renewal keeps the stored level, got {reply:?}");
    };
    let renewed = DeviceCertificate::parse(&renewed[0]).expect("the renewal meets the profile");
    assert_eq!(renewed.attestation(), AttestationLevel::ChipProven);
}
