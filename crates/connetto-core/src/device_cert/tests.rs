use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, PKCS_ED25519, PublicKeyData, SanType,
};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use super::*;

const DAY: Duration = Duration::from_hours(24);
const YEAR: Duration = Duration::from_hours(365 * 24);

fn deployment() -> DeploymentId {
    DeploymentId::from_uuid(uuid::Uuid::from_u128(
        0x4ea7_9187_635b_41c1_a6e9_c46f_30c4_91dc,
    ))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// A root, an issuer it signed, and the issuer ready to issue, all starting at `start`.
fn authorities(start: SystemTime) -> (RootCa, DeviceIssuer) {
    let root = RootCa::create(deployment(), start, 10 * YEAR).expect("create the root");
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let issuer_cert = root
        .sign_issuer(
            &issuer_key.subject_public_key_info(),
            start,
            YEAR + 30 * DAY,
            [2; 16],
        )
        .expect("sign the issuer");
    let issuer =
        DeviceIssuer::new(issuer_cert, issuer_key, root.certificate()).expect("load the issuer");
    (root, issuer)
}

/// A P-256 device key and its certificate request carrying `nonce`.
fn device_request(nonce: &[u8; 32]) -> (KeyPair, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key");
    let csr = CertificateRequest::build(&key, nonce).expect("build the request");
    (key, csr)
}

fn verify_chain(
    root: &RootCa,
    issuer: &DeviceIssuer,
    leaf: &[u8],
    now: SystemTime,
    usage: KeyUsage,
) {
    let root_der = rustls_pki_types::CertificateDer::from(root.certificate().to_vec());
    let anchor = anchor_from_trusted_cert(&root_der).expect("root as anchor");
    let leaf_der = rustls_pki_types::CertificateDer::from(leaf.to_vec());
    let end_entity = EndEntityCert::try_from(&leaf_der).expect("parse the leaf");
    let intermediates = [rustls_pki_types::CertificateDer::from(
        issuer.certificate().to_vec(),
    )];
    let secs = now
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &intermediates,
            rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs)),
            usage,
            None,
            None,
        )
        .expect("the chain verifies");
}

#[test]
fn an_identity_round_trips_through_its_uri() {
    let key = KeyId::from_bytes([0xab; 32]);
    let identity = DeviceIdentity::new(deployment(), "c0ffee-42", key).expect("valid identity");
    let uri = identity.uri();
    assert_eq!(
        uri,
        format!(
            "connetto://4ea79187-635b-41c1-a6e9-c46f30c491dc/account/c0ffee-42/device/{}",
            "ab".repeat(32)
        )
    );
    assert_eq!(DeviceIdentity::from_uri(&uri), Ok(identity));
}

#[test]
fn a_uri_outside_the_identity_form_is_refused() {
    let key = "ab".repeat(32);
    let dep = "4ea79187-635b-41c1-a6e9-c46f30c491dc";
    for uri in [
        format!("spiffe://{dep}/account/a/device/{key}"),
        format!("connetto://{}/account/a/device/{key}", dep.to_uppercase()),
        format!("connetto://not-a-uuid/account/a/device/{key}"),
        format!("connetto://{dep}/account/a/device/{}", "AB".repeat(32)),
        format!("connetto://{dep}/account/a/device/{}", "ab".repeat(31)),
        format!("connetto://{dep}/account/a/device"),
        format!("connetto://{dep}/account/a/device/{key}/extra"),
        format!("connetto://{dep}/user/a/device/{key}"),
        format!("connetto://{dep}/account//device/{key}"),
        format!("connetto://{dep}/account/../device/{key}"),
        format!("connetto://{dep}/account/a%2Fb/device/{key}"),
        format!("connetto://{dep}:443/account/a/device/{key}"),
    ] {
        assert!(DeviceIdentity::from_uri(&uri).is_err(), "accepted {uri}");
    }
}

#[test]
fn an_account_the_uri_cannot_carry_is_refused() {
    for account in ["", ".", "..", "a/b", "a b", "é"] {
        assert!(
            DeviceIdentity::new(deployment(), account, KeyId::from_bytes([1; 32])).is_err(),
            "accepted {account:?}"
        );
    }
}

#[test]
fn the_root_names_its_deployment() {
    let root = RootCa::create(deployment(), at(1_800_000_000), 10 * YEAR).expect("create the root");
    assert_eq!(deployment_of_root(root.certificate()), Ok(deployment()));
}

#[test]
fn an_issued_certificate_carries_exactly_the_profile() {
    let start = at(1_800_000_000);
    let (root, issuer) = authorities(start);
    let (key, csr) = device_request(&[7; 32]);
    let request = CertificateRequest::parse(&csr).expect("parse the request");
    assert_eq!(request.challenge(), &[7; 32]);
    let leaf = issuer
        .issue(&request, "c0ffee-42", start, DAY, [9; 16])
        .expect("issue");

    let cert = DeviceCertificate::parse(&leaf).expect("the leaf meets the profile");
    let expected_key = KeyId::of_public_key(&key.subject_public_key_info());
    assert_eq!(
        cert.identity(),
        &DeviceIdentity::new(deployment(), "c0ffee-42", expected_key).expect("identity")
    );
    assert_eq!(cert.not_before(), start);
    assert_eq!(cert.not_after(), start + DAY);
    assert_eq!(cert.serial(), &[9; 16]);

    verify_chain(
        &root,
        &issuer,
        &leaf,
        start + DAY / 2,
        KeyUsage::client_auth(),
    );
    verify_chain(
        &root,
        &issuer,
        &leaf,
        start + DAY / 2,
        KeyUsage::server_auth(),
    );
}

#[test]
fn fields_the_request_asks_for_are_ignored() {
    let start = at(1_800_000_000);
    let (_, issuer) = authorities(start);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key");
    let mut params = CertificateParams::new(vec!["evil.example".to_owned()]).expect("params");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request_with_attributes(&key, vec![challenge_attribute(&[1; 32])])
        .expect("serialize")
        .der()
        .to_vec();
    let request = CertificateRequest::parse(&csr).expect("parse the request");
    let leaf = issuer
        .issue(&request, "acct", start, DAY, [3; 16])
        .expect("issue");
    assert!(DeviceCertificate::parse(&leaf).is_ok());
}

#[test]
fn a_request_with_a_broken_signature_is_refused() {
    let (_, mut csr) = device_request(&[7; 32]);
    let last = csr.len() - 1;
    csr[last] ^= 0x01;
    assert_eq!(
        CertificateRequest::parse(&csr).err(),
        Some(RequestError::BadSignature)
    );
}

#[test]
fn a_request_for_a_key_other_than_p256_is_refused() {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
    let csr = CertificateRequest::build(&key, &[7; 32]).expect("build");
    assert_eq!(
        CertificateRequest::parse(&csr).err(),
        Some(RequestError::NotP256)
    );
}

#[test]
fn a_request_without_the_server_challenge_is_refused() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("serialize")
        .der()
        .to_vec();
    assert_eq!(
        CertificateRequest::parse(&csr).err(),
        Some(RequestError::NoChallenge)
    );
}

#[test]
fn a_certificate_outliving_its_issuer_is_not_issued() {
    let start = at(1_800_000_000);
    let (_, issuer) = authorities(start);
    let (_, csr) = device_request(&[7; 32]);
    let request = CertificateRequest::parse(&csr).expect("parse");
    assert_eq!(
        issuer
            .issue(&request, "acct", start + YEAR, 31 * DAY, [3; 16])
            .err(),
        Some(IssueError::OutlivesIssuer)
    );
}

#[test]
fn an_issuer_the_root_did_not_sign_is_refused() {
    let start = at(1_800_000_000);
    let root = RootCa::create(deployment(), start, 10 * YEAR).expect("root");
    let other = RootCa::create(deployment(), start, 10 * YEAR).expect("other root");
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let issuer_cert = other
        .sign_issuer(&issuer_key.subject_public_key_info(), start, YEAR, [2; 16])
        .expect("sign");
    assert_eq!(
        DeviceIssuer::new(issuer_cert, issuer_key, root.certificate()).err(),
        Some(IssuerError::NotSignedByRoot)
    );
}

#[test]
fn a_certificate_outside_the_profile_is_refused() {
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let issuer_params = {
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        p
    };
    let signer = rcgen::Issuer::new(issuer_params, &issuer_key);
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let identity = DeviceIdentity::new(
        deployment(),
        "acct",
        KeyId::of_public_key(&leaf_key.subject_public_key_info()),
    )
    .expect("identity");
    let profile = || {
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        p.subject_alt_names = vec![SanType::URI(identity.uri().try_into().expect("uri"))];
        p
    };
    let sign = |p: CertificateParams| {
        p.signed_by(&leaf_key, &signer)
            .expect("sign")
            .der()
            .to_vec()
    };
    assert!(DeviceCertificate::parse(&sign(profile())).is_ok());

    let mut ca = profile();
    ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut signing = profile();
    signing.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let mut code = profile();
    code.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    let mut two_uris = profile();
    two_uris
        .subject_alt_names
        .push(SanType::URI(identity.uri().try_into().expect("uri")));
    let mut dns = profile();
    dns.subject_alt_names
        .push(SanType::DnsName("x.example".try_into().expect("dns")));
    let mut named = profile();
    named
        .distinguished_name
        .push(rcgen::DnType::CommonName, "someone");
    let mut other_key = profile();
    other_key.subject_alt_names = vec![SanType::URI(
        DeviceIdentity::new(deployment(), "acct", KeyId::from_bytes([5; 32]))
            .expect("identity")
            .uri()
            .try_into()
            .expect("uri"),
    )];
    for (params, refusal) in [
        (ca, ProfileError::CertificateAuthority),
        (signing, ProfileError::KeyUsage),
        (code, ProfileError::ExtendedKeyUsage),
        (two_uris, ProfileError::SubjectAltName),
        (dns, ProfileError::SubjectAltName),
        (named, ProfileError::Subject),
        (other_key, ProfileError::KeyMismatch),
    ] {
        assert_eq!(DeviceCertificate::parse(&sign(params)), Err(refusal));
    }
}

#[test]
fn a_root_reloaded_from_its_parts_signs_issuers_the_issuer_accepts() {
    let start = at(1_800_000_000);
    let created = RootCa::create(deployment(), start, 10 * YEAR).expect("create the root");
    let key = KeyPair::try_from(created.private_key_der().as_slice()).expect("key from PKCS #8");
    let root = RootCa::from_parts(created.certificate().to_vec(), key).expect("reload the root");
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let issuer_cert = root
        .sign_issuer(&issuer_key.subject_public_key_info(), start, YEAR, [2; 16])
        .expect("sign the issuer");
    assert!(DeviceIssuer::new(issuer_cert, issuer_key, created.certificate()).is_ok());
}

#[test]
fn a_root_reloaded_with_another_key_is_refused() {
    let start = at(1_800_000_000);
    let created = RootCa::create(deployment(), start, 10 * YEAR).expect("create the root");
    let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("other key");
    assert_eq!(
        RootCa::from_parts(created.certificate().to_vec(), other).err(),
        Some(RootError::KeyMismatch)
    );
}

#[test]
fn an_issuer_loads_from_its_stored_pkcs8_key() {
    let start = at(1_800_000_000);
    let root = RootCa::create(deployment(), start, 10 * YEAR).expect("root");
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let issuer_cert = root
        .sign_issuer(&issuer_key.subject_public_key_info(), start, YEAR, [2; 16])
        .expect("sign");
    assert!(
        DeviceIssuer::from_pkcs8(
            issuer_cert.clone(),
            &issuer_key.serialize_der(),
            root.certificate()
        )
        .is_ok()
    );
    assert!(matches!(
        DeviceIssuer::from_pkcs8(issuer_cert, b"not a key", root.certificate()),
        Err(IssuerError::Key(_))
    ));
}

/// A device key held in memory, standing in for a chip.
struct InMemory(KeyPair);

impl DeviceKey for InMemory {
    fn public_point(&self) -> [u8; 65] {
        self.0
            .der_bytes()
            .try_into()
            .expect("an uncompressed P-256 point")
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        rcgen::SigningKey::sign(&self.0, message)
            .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::Software
    }
}

#[test]
fn a_device_key_requests_a_certificate_naming_it() {
    let start = at(1_800_000_000);
    let (_, issuer) = authorities(start);
    let key = InMemory(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key"));
    let csr = CertificateRequest::build(&CertificateSigner::new(&key), &[4; 32]).expect("build");
    let request = CertificateRequest::parse(&csr).expect("the request verifies");
    let leaf = issuer
        .issue(&request, "acct", start, DAY, [5; 16])
        .expect("issue");
    let cert = DeviceCertificate::parse(&leaf).expect("profile");
    assert_eq!(cert.identity().key(), key_id(&key));
    assert_eq!(
        key_id(&key),
        KeyId::of_public_key(&key.0.subject_public_key_info())
    );
}

#[test]
fn a_device_key_that_cannot_sign_builds_no_request() {
    struct Refusing;
    impl DeviceKey for Refusing {
        fn public_point(&self) -> [u8; 65] {
            [4; 65]
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
            Err(DeviceKeyError::Unavailable)
        }
        fn home(&self) -> KeyHome {
            KeyHome::Software
        }
    }
    assert!(CertificateRequest::build(&CertificateSigner::new(&Refusing), &[4; 32]).is_err());
}

/// A certificate for a fresh device key, its serial and its DER.
fn issued(issuer: &DeviceIssuer, start: SystemTime, serial: u8) -> Vec<u8> {
    let (_, csr) = device_request(&[serial; 32]);
    let request = CertificateRequest::parse(&csr).expect("parse");
    issuer
        .issue(&request, "alice", start, DAY, [serial; 16])
        .expect("issue")
}

#[test]
fn a_signed_list_verifies_against_its_root_and_names_its_serials() {
    let start = at(1_800_000_000);
    let (root, issuer) = authorities(start);
    let leaf = issued(&issuer, start, 0x81);
    let revoked = [Revoked {
        serial: vec![0x81; 16],
        at: start + DAY / 2,
    }];
    let der = issuer
        .sign_list(7, &revoked, start + DAY / 2, start + 30 * DAY)
        .expect("sign");
    let roots = [root.certificate().to_vec()];
    let list = RevocationList::verify(&der, issuer.certificate(), &roots).expect("verifies");
    assert_eq!(list.number(), 7);
    assert_eq!(list.issuer(), issuer.key_id());
    assert!(
        list.revokes(&[0x81; 16]),
        "a high-bit serial matches despite its DER padding"
    );
    assert!(!list.revokes(&[0x01; 16]));
    assert_eq!(list.der(), der.as_slice());
    verify_chain_to(&leaf, &issuer, &roots);
}

fn verify_chain_to(leaf: &[u8], issuer: &DeviceIssuer, roots: &[Vec<u8>]) {
    super::verify_chain(leaf, issuer.certificate(), roots).expect("the leaf chains to the root");
}

#[test]
fn a_list_or_chain_from_outside_the_roots_is_refused() {
    let start = at(1_800_000_000);
    let (root, issuer) = authorities(start);
    let (other_root, other_issuer) = authorities(start);
    let der = other_issuer
        .sign_list(1, &[], start, start + DAY)
        .expect("sign");
    let roots = [root.certificate().to_vec()];
    assert_eq!(
        RevocationList::verify(&der, other_issuer.certificate(), &roots),
        Err(ListError::Untrusted)
    );
    assert_eq!(
        RevocationList::verify(&der, issuer.certificate(), &roots),
        Err(ListError::BadSignature),
        "a trusted issuer that did not sign it"
    );
    let leaf = issued(&other_issuer, start, 3);
    assert_eq!(
        super::verify_chain(&leaf, issuer.certificate(), &roots),
        Err(ListError::BadSignature)
    );
    assert_eq!(
        super::verify_chain(&leaf, other_issuer.certificate(), &roots),
        Err(ListError::Untrusted)
    );
    assert!(
        super::verify_chain(
            &leaf,
            other_issuer.certificate(),
            &[other_root.certificate().to_vec()]
        )
        .is_ok()
    );
}

#[test]
fn webpki_refuses_a_certificate_the_list_revokes() {
    let start = at(1_800_000_000);
    let (root, issuer) = authorities(start);
    let revoked_leaf = issued(&issuer, start, 0x11);
    let kept_leaf = issued(&issuer, start, 0x22);
    let der = issuer
        .sign_list(
            1,
            &[Revoked {
                serial: vec![0x11; 16],
                at: start + DAY / 4,
            }],
            start + DAY / 4,
            start + 30 * DAY,
        )
        .expect("sign");
    let crl = webpki::CertRevocationList::from(
        webpki::BorrowedCertRevocationList::from_der(&der).expect("webpki parses the list"),
    );
    let crls = [&crl];
    let check = |leaf: &[u8]| {
        let root_der = rustls_pki_types::CertificateDer::from(root.certificate().to_vec());
        let anchor = anchor_from_trusted_cert(&root_der).expect("anchor");
        let leaf_der = rustls_pki_types::CertificateDer::from(leaf.to_vec());
        let end_entity = EndEntityCert::try_from(&leaf_der).expect("leaf");
        let intermediates = [rustls_pki_types::CertificateDer::from(
            issuer.certificate().to_vec(),
        )];
        let options = webpki::RevocationOptionsBuilder::new(&crls)
            .expect("options")
            .with_status_policy(webpki::UnknownStatusPolicy::Allow)
            .build();
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &[anchor],
                &intermediates,
                rustls_pki_types::UnixTime::since_unix_epoch(
                    at(1_800_000_000)
                        .duration_since(UNIX_EPOCH)
                        .expect("after the epoch")
                        + DAY / 2,
                ),
                KeyUsage::client_auth(),
                Some(options),
                None,
            )
            .map(drop)
    };
    assert!(matches!(
        check(&revoked_leaf),
        Err(webpki::Error::CertRevoked)
    ));
    assert!(check(&kept_leaf).is_ok());
}

#[test]
fn a_root_signed_list_revokes_an_issuer_and_webpki_refuses_its_chain() {
    let start = at(1_800_000_000);
    let (root, issuer) = authorities(start);
    let leaf = issued(&issuer, start, 0x33);
    let issuer_serial = certificate_serial(issuer.certificate()).expect("the issuer's serial");
    let der = root
        .sign_list(
            1,
            &[Revoked {
                serial: issuer_serial.clone(),
                at: start + DAY / 4,
            }],
            start + DAY / 4,
            start + 30 * DAY,
        )
        .expect("the root signs");
    let roots = [root.certificate().to_vec()];
    let list = RevocationList::verify(&der, root.certificate(), &roots).expect("verifies");
    assert!(list.revokes(&issuer_serial));
    assert_eq!(
        list.issuer(),
        certificate_key_id(root.certificate()).expect("root key")
    );

    let crl = webpki::CertRevocationList::from(
        webpki::BorrowedCertRevocationList::from_der(&der).expect("webpki parses it"),
    );
    let crls = [&crl];
    let root_der = rustls_pki_types::CertificateDer::from(root.certificate().to_vec());
    let anchors = [anchor_from_trusted_cert(&root_der).expect("anchor")];
    let leaf_der = rustls_pki_types::CertificateDer::from(leaf);
    let end_entity = EndEntityCert::try_from(&leaf_der).expect("leaf");
    let intermediates = [rustls_pki_types::CertificateDer::from(
        issuer.certificate().to_vec(),
    )];
    let options = webpki::RevocationOptionsBuilder::new(&crls)
        .expect("options")
        .with_status_policy(webpki::UnknownStatusPolicy::Allow)
        .build();
    let verdict = end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        &intermediates,
        rustls_pki_types::UnixTime::since_unix_epoch(
            at(1_800_000_000)
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                + DAY / 2,
        ),
        KeyUsage::client_auth(),
        Some(options),
        None,
    );
    assert!(
        matches!(verdict, Err(webpki::Error::CertRevoked)),
        "a leaf under a revoked issuer is refused"
    );
}
