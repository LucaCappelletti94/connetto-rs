//! Device enrolment over a live session (R74 step 3).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{
    CertificateRequest, DeploymentId, DeviceCertificate, DeviceIssuer, KeyId, RootCa,
};
use connetto_core::messages::{
    ControlMessage, EnrolChallenge, EnrolChallengeRequest, EnrolGrant, EnrolRefusal, EnrolRefused,
    EnrolRequest,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::device_cert::{DeviceCertConfig, DeviceEnrolment, MemoryEnrolments};
use connetto_server::{AbuseConfig, LoopbackTransport, RequestGuard, ThrottleConfig, loopback};
use connetto_test_harness::{Fixture, RosterAuth, WITHHELD_ID};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _};

use super::ticket_shared::{
    OkSigner, build_manager_with_guard, do_handshake, do_handshake_anon, setup_reader,
};

const DAY: Duration = Duration::from_hours(24);

/// An issuer valid for a year and a month from now, under a fresh root.
fn issuer() -> (Vec<u8>, DeviceIssuer) {
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
            [1; 16],
        )
        .expect("issuer");
    let issuer = DeviceIssuer::new(cert.clone(), key, root.certificate()).expect("load");
    (cert, issuer)
}

/// A session for `identity`, `None` meaning anonymous, against a manager that
/// enrols through `config` into `store` unless `config` is `None`.
async fn session(
    fixture: &Fixture,
    identity: Option<&str>,
    config: Option<DeviceCertConfig>,
    store: &Arc<MemoryEnrolments<String>>,
) -> LoopbackTransport {
    let manager = build_manager_with_guard(
        setup_reader(fixture).await,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(RequestGuard::new(
            ThrottleConfig::default(),
            AbuseConfig::default(),
        )),
        OkSigner,
    );
    if let Some(config) = config {
        manager
            .install_device_enrolment(Arc::new(DeviceEnrolment::new(
                config,
                Arc::clone(store) as _,
            )))
            .unwrap_or_else(|_| panic!("installed once"));
    }
    let (server_end, mut client) = loopback();
    tokio::spawn(manager.serve(server_end));
    match identity {
        Some(identity) => do_handshake(&mut client, identity).await,
        None => do_handshake_anon(&mut client, "anon").await,
    }
    client
}

async fn ask(client: &mut LoopbackTransport, message: ControlMessage) -> ControlMessage {
    client.send_control(message).await.expect("send");
    loop {
        match client.recv().await.expect("recv") {
            Some(IncomingFrame::Control(reply)) => return reply,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("the session closed"),
        }
    }
}

async fn challenge(client: &mut LoopbackTransport) -> ControlMessage {
    ask(
        client,
        ControlMessage::EnrolChallengeRequest(EnrolChallengeRequest {
            request_id: "c".into(),
        }),
    )
    .await
}

async fn nonce(client: &mut LoopbackTransport) -> [u8; 32] {
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

async fn enrol(
    client: &mut LoopbackTransport,
    key: &KeyPair,
    nonce: [u8; 32],
    lifetime_secs: Option<u64>,
    descriptor: Vec<u8>,
) -> ControlMessage {
    ask(
        client,
        ControlMessage::EnrolRequest(EnrolRequest {
            request_id: "e".into(),
            csr: CertificateRequest::build(key, &nonce).expect("csr"),
            lifetime_secs,
            descriptor,
        }),
    )
    .await
}

fn refused(reason: EnrolRefusal, request_id: &str) -> ControlMessage {
    ControlMessage::EnrolRefused(EnrolRefused {
        request_id: request_id.into(),
        reason,
    })
}

fn device_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key")
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
    store.revoke(KeyId::of_public_key(&key.subject_public_key_info()));
    let mut client = session(
        &fixture,
        Some("alice"),
        Some(DeviceCertConfig::new(issuer().1)),
        &store,
    )
    .await;
    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &key, handed, None, Vec::new()).await;
    assert_eq!(reply, refused(EnrolRefusal::Revoked, "e"));
    assert_eq!(store.records(), Vec::new());
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
        }),
    )
    .await;
    assert_eq!(reply, refused(EnrolRefusal::InvalidRequest, "e"));

    let handed = nonce(&mut client).await;
    let reply = enrol(&mut client, &device_key(), handed, None, vec![0; 4097]).await;
    assert_eq!(reply, refused(EnrolRefusal::InvalidRequest, "e"));
    assert_eq!(store.records(), Vec::new());
}
