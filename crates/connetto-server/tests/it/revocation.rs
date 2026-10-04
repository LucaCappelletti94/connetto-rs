//! Revoking a device and publishing the lists that say so (R74 step 5).

use std::sync::Arc;
use std::time::Duration;

use connetto_core::device_cert::{DeviceCertificate, KeyId, RevocationList};
use connetto_core::messages::{
    ControlMessage, DeviceRevokedAck, DevicesList, DevicesRequest, EnrolGrant, EnrolRefusal,
    FatalErrorReason, RevocationUpdate, RevokeDeviceRequest, SignedList,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::LoopbackTransport;
use connetto_server::device_cert::{DeviceCertConfig, DeviceEnrolment, MemoryEnrolments};
use connetto_test_harness::Fixture;
use parking_lot::Mutex;
use rcgen::{KeyPair, PublicKeyData as _};

use super::enrolment::{
    ask, connect, device_key, enrol, enrolling_manager, nonce, refused, rooted_issuer,
};

const BOUND: Duration = Duration::from_secs(20);

/// The next pushed revocation lists, within the bound.
async fn next_lists(client: &mut LoopbackTransport) -> Vec<SignedList> {
    tokio::time::timeout(BOUND, async {
        loop {
            match client.recv().await.expect("recv") {
                Some(IncomingFrame::Control(ControlMessage::RevocationUpdate(
                    RevocationUpdate { lists },
                ))) => return lists,
                Some(_) => {}
                None => panic!("the session closed before its lists came"),
            }
        }
    })
    .await
    .expect("the lists arrive within the bound")
}

/// The one list in `lists`, verified against `root`.
fn verified(lists: &[SignedList], root: &[u8]) -> RevocationList {
    let [list] = lists else {
        panic!("one issuer, one list, got {}", lists.len());
    };
    RevocationList::verify(&list.list, &list.signer, &[root.to_vec()]).expect("the list verifies")
}

/// Enrol `key` on `client` and return its certificate.
async fn enrolled(client: &mut LoopbackTransport, key: &KeyPair) -> DeviceCertificate {
    let nonce = nonce(client).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain, .. }) =
        enrol(client, key, nonce, None, vec![0xc0]).await
    else {
        panic!("expected a grant");
    };
    DeviceCertificate::parse(&chain[0]).expect("profile")
}

fn key_id(key: &KeyPair) -> KeyId {
    KeyId::of_public_key(&key.subject_public_key_info())
}

/// A manager enrolling into `store` and recording each revoked session.
async fn revoking_manager(
    fixture: &Fixture,
    store: &Arc<MemoryEnrolments<String>>,
    issuer: connetto_core::device_cert::DeviceIssuer,
) -> (
    Arc<super::ticket_shared::TicketManager<super::ticket_shared::OkSigner>>,
    Arc<Mutex<Vec<connetto_core::SessionId>>>,
) {
    let revoked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&revoked);
    let enrolment = DeviceEnrolment::new(DeviceCertConfig::new(issuer), Arc::clone(store) as _)
        .with_session_revoker(Arc::new(move |session| {
            seen.lock().push(session);
            Box::pin(core::future::ready(()))
        }));
    (enrolling_manager(fixture, Some(enrolment)).await, revoked)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handshake_and_a_grant_carry_the_current_list() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (root, _, issuer) = rooted_issuer();
    let (manager, _) = revoking_manager(&fixture, &store, issuer).await;
    let mut client = connect(&manager, Some("alice")).await;
    let list = verified(&next_lists(&mut client).await, &root);
    assert!(list.number() >= 1);
    let nonce = nonce(&mut client).await;
    let ControlMessage::EnrolGrant(grant) =
        enrol(&mut client, &device_key(), nonce, None, Vec::new()).await
    else {
        panic!("expected a grant");
    };
    assert_eq!(
        verified(&grant.revocation_lists, &root).number(),
        list.number()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_session_gets_no_list() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (_, _, issuer) = rooted_issuer();
    let (manager, _) = revoking_manager(&fixture, &store, issuer).await;
    let mut client = connect(&manager, None).await;
    let reply = ask(
        &mut client,
        ControlMessage::DevicesRequest(DevicesRequest {
            request_id: "d".into(),
        }),
    )
    .await;
    assert_eq!(reply, refused(EnrolRefusal::Unidentified, "d"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reporting_a_device_lost_closes_it_lists_it_and_revokes_its_session() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (root, _, issuer) = rooted_issuer();
    let (manager, revoked_sessions) = revoking_manager(&fixture, &store, issuer).await;
    let mut phone = connect(&manager, Some("alice")).await;
    let mut laptop = connect(&manager, Some("alice")).await;
    let phone_key = device_key();
    let laptop_key = device_key();
    let phone_cert = enrolled(&mut phone, &phone_key).await;
    let laptop_cert = enrolled(&mut laptop, &laptop_key).await;
    let before = verified(&manager_lists(&manager).await, &root);
    assert!(!before.revokes(phone_cert.serial()));

    let reply = ask(
        &mut laptop,
        ControlMessage::RevokeDeviceRequest(RevokeDeviceRequest {
            request_id: "r".into(),
            key_id: *key_id(&phone_key).as_bytes(),
        }),
    )
    .await;
    assert_eq!(
        reply,
        ControlMessage::DeviceRevokedAck(DeviceRevokedAck {
            request_id: "r".into()
        })
    );
    let after = verified(&next_lists(&mut laptop).await, &root);
    assert!(
        after.number() > before.number(),
        "a new list takes the next number"
    );
    assert!(after.revokes(phone_cert.serial()));
    assert!(!after.revokes(laptop_cert.serial()));

    let closed = tokio::time::timeout(BOUND, async {
        loop {
            match phone.recv().await.expect("recv") {
                Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => {
                    return fatal.reason;
                }
                Some(_) => {}
                None => panic!("closed without a reason"),
            }
        }
    })
    .await
    .expect("the reported device is closed within the bound");
    assert_eq!(closed, FatalErrorReason::DeviceRevoked);
    assert_eq!(
        revoked_sessions.lock().len(),
        1,
        "its auth-store session is revoked"
    );

    let ControlMessage::DevicesList(DevicesList { devices, .. }) = ask(
        &mut laptop,
        ControlMessage::DevicesRequest(DevicesRequest {
            request_id: "d".into(),
        }),
    )
    .await
    else {
        panic!("expected the device list");
    };
    assert_eq!(devices.len(), 2);
    let phone_entry = devices
        .iter()
        .find(|device| device.key_id == *key_id(&phone_key).as_bytes())
        .expect("the phone is listed");
    assert!(phone_entry.revoked_at_secs.is_some());
    assert_eq!(phone_entry.descriptor, vec![0xc0]);
    let laptop_entry = devices
        .iter()
        .find(|device| device.key_id == *key_id(&laptop_key).as_bytes())
        .expect("the laptop is listed");
    assert!(laptop_entry.revoked_at_secs.is_none());

    let mut thief = connect(&manager, Some("alice")).await;
    let nonce = nonce(&mut thief).await;
    assert_eq!(
        enrol(&mut thief, &phone_key, nonce, None, Vec::new()).await,
        refused(EnrolRefusal::Revoked, "e"),
        "the revoked key cannot renew"
    );
}

/// The lists the manager publishes now, read through a fresh session.
async fn manager_lists(
    manager: &Arc<super::ticket_shared::TicketManager<super::ticket_shared::OkSigner>>,
) -> Vec<SignedList> {
    let mut reader = connect(manager, Some("alice")).await;
    next_lists(&mut reader).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_owner_revokes_and_an_unknown_key_is_refused() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (_, _, issuer) = rooted_issuer();
    let (manager, revoked_sessions) = revoking_manager(&fixture, &store, issuer).await;
    let mut alice = connect(&manager, Some("alice")).await;
    let mut bob = connect(&manager, Some("bob")).await;
    let alice_key = device_key();
    enrolled(&mut alice, &alice_key).await;
    for (key, what) in [
        (key_id(&alice_key), "another account's key"),
        (KeyId::from_bytes([7; 32]), "an unknown key"),
    ] {
        let reply = ask(
            &mut bob,
            ControlMessage::RevokeDeviceRequest(RevokeDeviceRequest {
                request_id: "r".into(),
                key_id: *key.as_bytes(),
            }),
        )
        .await;
        assert_eq!(reply, refused(EnrolRefusal::InvalidRequest, "r"), "{what}");
    }
    assert!(revoked_sessions.lock().is_empty());
    let nonce = nonce(&mut bob).await;
    assert_eq!(
        enrol(&mut bob, &alice_key, nonce, None, Vec::new()).await,
        refused(EnrolRefusal::InvalidRequest, "e"),
        "a key enrolled under one account is refused to another"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operator_revokes_any_key_once() {
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (root, _, issuer) = rooted_issuer();
    let (manager, revoked_sessions) = revoking_manager(&fixture, &store, issuer).await;
    let mut alice = connect(&manager, Some("alice")).await;
    let mut watcher = connect(&manager, Some("bob")).await;
    let _ = next_lists(&mut watcher).await;
    let key = device_key();
    let cert = enrolled(&mut alice, &key).await;
    assert!(manager.revoke_device(key_id(&key)).await.expect("revoke"));
    let pushed = verified(&next_lists(&mut watcher).await, &root);
    assert!(
        pushed.revokes(cert.serial()),
        "every identified session hears of it"
    );
    assert!(
        !manager.revoke_device(key_id(&key)).await.expect("again"),
        "a second revoke changes nothing"
    );
    assert_eq!(revoked_sessions.lock().len(), 1);
    assert!(
        manager
            .revoke_device(KeyId::from_bytes([1; 32]))
            .await
            .is_err()
    );
}

/// An issuer as its certificate and its PKCS #8 key.
type IssuerBytes = (Vec<u8>, Vec<u8>);

/// A root and two issuers it signed, each as its certificate and PKCS #8 key,
/// so a test loads one issuer into two configurations.
fn root_and_two_issuers() -> (connetto_core::device_cert::RootCa, IssuerBytes, IssuerBytes) {
    use connetto_core::device_cert::{DeploymentId, RootCa};
    let now = std::time::SystemTime::now();
    let day = Duration::from_hours(24);
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(0x0f0f)),
        now - day,
        3650 * day,
    )
    .expect("root");
    let issuer = |serial: u8| {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("issuer key");
        let cert = root
            .sign_issuer(
                &key.subject_public_key_info(),
                now - day,
                395 * day,
                [serial; 16],
            )
            .expect("issuer");
        (cert, key.serialize_der())
    };
    let (old, new) = (issuer(1), issuer(2));
    (root, old, new)
}

fn load(
    root: &connetto_core::device_cert::RootCa,
    (cert, key): &IssuerBytes,
) -> connetto_core::device_cert::DeviceIssuer {
    connetto_core::device_cert::DeviceIssuer::from_pkcs8(cert.clone(), key, root.certificate())
        .expect("load the issuer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_issuer_keeps_listing_its_certificates_beside_the_roots_list() {
    use connetto_core::device_cert::Revoked;
    let fixture = Fixture::acquire().await;
    let store = Arc::new(MemoryEnrolments::default());
    let (root, old, new) = root_and_two_issuers();
    let roots = [root.certificate().to_vec()];

    let before = enrolling_manager(
        &fixture,
        Some(DeviceEnrolment::new(
            DeviceCertConfig::new(load(&root, &old)),
            Arc::clone(&store) as _,
        )),
    )
    .await;
    let mut device = connect(&before, Some("alice")).await;
    let key = device_key();
    let cert = enrolled(&mut device, &key).await;

    // The root revokes some third issuer offline, and the operator rotates.
    let now = std::time::SystemTime::now();
    let root_list = SignedList {
        list: root
            .sign_list(
                1,
                &[Revoked {
                    serial: vec![9; 16],
                    at: now,
                }],
                now,
                now + Duration::from_hours(24 * 400),
            )
            .expect("the root signs"),
        signer: root.certificate().to_vec(),
    };
    let after = enrolling_manager(
        &fixture,
        Some(DeviceEnrolment::new(
            DeviceCertConfig::new(load(&root, &new))
                .with_retired_issuer(load(&root, &old))
                .with_root_list(root_list),
            Arc::clone(&store) as _,
        )),
    )
    .await;
    assert!(after.revoke_device(key_id(&key)).await.expect("revoke"));
    let lists = manager_lists(&after).await;
    assert_eq!(
        lists.len(),
        3,
        "the current issuer, the retired one, the root"
    );
    let by_signer = |signer: &[u8]| {
        let list = lists
            .iter()
            .find(|list| list.signer == signer)
            .expect("a list from that signer");
        RevocationList::verify(&list.list, &list.signer, &roots).expect("verifies")
    };
    assert!(
        by_signer(&old.0).revokes(cert.serial()),
        "the retired issuer lists its own"
    );
    assert!(
        !by_signer(&new.0).revokes(cert.serial()),
        "the new issuer signed none of it"
    );
    assert!(by_signer(root.certificate()).revokes(&[9; 16]));
}
