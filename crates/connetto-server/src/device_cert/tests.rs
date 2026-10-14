use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::device_cert::{CertificateSerial, DeploymentId, DeviceIssuer, RootCa};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _};

use super::*;

const DAY: Duration = Duration::from_hours(24);

fn start() -> SystemTime {
    UNIX_EPOCH + Duration::from_hours(500_000)
}

/// An issuer valid from [`start`] for `valid_for`.
fn issuer(valid_for: Duration) -> DeviceIssuer {
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        start(),
        3650 * DAY,
    )
    .expect("root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let cert = root
        .sign_issuer(
            &key.subject_public_key_info(),
            start(),
            valid_for,
            CertificateSerial::new([1; 16]).expect("the serial is positive"),
        )
        .expect("issuer");
    DeviceIssuer::new(cert, key, root.certificate()).expect("load")
}

#[test]
fn an_unrequested_lifetime_takes_the_default() {
    let config = DeviceCertConfig::new(issuer(395 * DAY));
    assert_eq!(config.lifetime_for(None), Ok(DAY));
}

#[test]
fn a_lifetime_over_the_ceiling_is_refused_never_shortened() {
    let config = DeviceCertConfig::new(issuer(395 * DAY)).with_lifetime_ceiling(7 * DAY);
    assert_eq!(config.lifetime_for(Some(7 * DAY)), Ok(7 * DAY));
    assert_eq!(
        config.lifetime_for(Some(7 * DAY + Duration::from_secs(1))),
        Err(LifetimeError::OverCeiling { ceiling: 7 * DAY })
    );
}

#[test]
fn a_default_above_the_ceiling_fails_the_startup_check() {
    let config = DeviceCertConfig::new(issuer(395 * DAY))
        .with_default_lifetime(10 * DAY)
        .with_lifetime_ceiling(7 * DAY);
    assert_eq!(
        config.check(start()),
        Err(ConfigError::DefaultOverCeiling {
            default: 10 * DAY,
            ceiling: 7 * DAY
        })
    );
}

#[test]
fn an_expired_issuer_fails_the_startup_check() {
    let config = DeviceCertConfig::new(issuer(30 * DAY));
    assert_eq!(
        config.check(start() + 30 * DAY),
        Err(ConfigError::IssuerExpired)
    );
}

#[test]
fn an_issuer_near_its_end_warns_sixty_days_ahead() {
    let config = DeviceCertConfig::new(issuer(395 * DAY));
    assert_eq!(config.check(start()), Ok(None));
    assert_eq!(config.check(start() + 335 * DAY), Ok(None));
    assert_eq!(
        config.check(start() + 335 * DAY + Duration::from_secs(1)),
        Ok(Some(IssuerExpiring {
            left: Duration::from_secs(60 * 86_400 - 1)
        }))
    );
}

/// An issuer and the PKCS #8 bytes of its key, so a render is checked
/// against the secret.
fn issuer_and_secret(valid_for: Duration) -> (DeviceIssuer, Vec<u8>) {
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        start(),
        3650 * DAY,
    )
    .expect("root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let secret = key.serialize_der();
    let cert = root
        .sign_issuer(
            &key.subject_public_key_info(),
            start(),
            valid_for,
            CertificateSerial::new([1; 16]).expect("the serial is positive"),
        )
        .expect("issuer");
    let issuer = DeviceIssuer::new(cert, key, root.certificate()).expect("load");
    (issuer, secret)
}

/// The issuer's key rides in logs through any `Debug` render, so the render
/// carries neither the PKCS #8 bytes nor their hex.
#[test]
fn a_debug_render_carries_no_private_key() {
    let (issuer, secret) = issuer_and_secret(395 * DAY);
    let (retired, retired_secret) = issuer_and_secret(395 * DAY);
    let config = DeviceCertConfig::new(issuer).with_retired_issuer(retired);
    let debug = format!("{config:?}");
    for secret in [secret, retired_secret] {
        let hex = format!("{secret:x?}");
        assert!(!debug.contains(&hex), "the render carries the key's hex");
        assert!(
            !debug
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret.as_slice()),
            "the render carries the key's bytes"
        );
    }
}

#[test]
fn a_thousand_random_serials_read_back_as_issued() {
    use connetto_core::device_cert::{AttestationLevel, CertificateRequest, DeviceCertificate};
    use ring::rand::{SecureRandom, SystemRandom};
    let issuer = issuer(30 * DAY);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("device key");
    let csr = CertificateRequest::build(&key, &[7; 32]).expect("the request builds");
    let request = CertificateRequest::parse(&csr).expect("the request parses");
    let random = SystemRandom::new();
    for _ in 0..1000 {
        let serial =
            CertificateSerial::random(|bytes| SecureRandom::fill(&random, bytes)).expect("a draw");
        let leaf = issuer
            .issue(
                &request,
                "alice",
                start(),
                DAY,
                serial,
                AttestationLevel::Unproven,
            )
            .expect("issued");
        let parsed = DeviceCertificate::parse(&leaf).expect("the profile");
        assert_eq!(parsed.serial(), serial.as_bytes().as_slice());
    }
}
