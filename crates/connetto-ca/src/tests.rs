use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::device_cert::{DeviceIssuer, deployment_of_root};
use rcgen::KeyPair;

use super::*;

const PASSPHRASE: &str = "correct horse battery staple";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_hours(500_000)
}

#[test]
fn a_new_root_signs_an_issuer_the_server_loads() {
    let ca = tempfile::tempdir().expect("ca dir");
    let out = tempfile::tempdir().expect("issuer dir");
    let deployment = init(ca.path(), PASSPHRASE, now()).expect("init");

    sign_issuer(ca.path(), PASSPHRASE, out.path(), now()).expect("sign the issuer");

    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("root certificate");
    assert_eq!(deployment_of_root(&root), Ok(deployment));
    let issuer = std::fs::read(out.path().join(ISSUER_CERTIFICATE)).expect("issuer certificate");
    let key = std::fs::read(out.path().join(ISSUER_KEY)).expect("issuer key");
    let key = KeyPair::try_from(key.as_slice()).expect("issuer key parses");
    let loaded = DeviceIssuer::new(issuer, key, &root).expect("the server loads the issuer");
    assert_eq!(loaded.deployment(), deployment);
}

#[test]
fn the_root_key_on_disk_is_encrypted() {
    let ca = tempfile::tempdir().expect("ca dir");
    init(ca.path(), PASSPHRASE, now()).expect("init");
    let stored = std::fs::read(ca.path().join(ROOT_KEY)).expect("root key");
    assert!(KeyPair::try_from(stored.as_slice()).is_err());
    assert!(pkcs8::EncryptedPrivateKeyInfo::try_from(stored.as_slice()).is_ok());
}

#[test]
fn a_wrong_passphrase_signs_nothing() {
    let ca = tempfile::tempdir().expect("ca dir");
    let out = tempfile::tempdir().expect("issuer dir");
    init(ca.path(), PASSPHRASE, now()).expect("init");
    assert!(matches!(
        sign_issuer(ca.path(), "wrong", out.path(), now()),
        Err(CaError::Passphrase)
    ));
    assert!(!out.path().join(ISSUER_CERTIFICATE).exists());
    assert!(!out.path().join(ISSUER_KEY).exists());
}

#[test]
fn an_existing_root_is_never_overwritten() {
    let ca = tempfile::tempdir().expect("ca dir");
    let first = init(ca.path(), PASSPHRASE, now()).expect("init");
    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("root");
    assert!(matches!(
        init(ca.path(), PASSPHRASE, now()),
        Err(CaError::Exists(_))
    ));
    assert_eq!(
        std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("root"),
        root
    );
    assert_eq!(deployment_of_root(&root), Ok(first));
}

#[test]
fn an_existing_issuer_is_never_overwritten() {
    let ca = tempfile::tempdir().expect("ca dir");
    let out = tempfile::tempdir().expect("issuer dir");
    init(ca.path(), PASSPHRASE, now()).expect("init");
    sign_issuer(ca.path(), PASSPHRASE, out.path(), now()).expect("first issuer");
    let key = std::fs::read(out.path().join(ISSUER_KEY)).expect("key");
    assert!(matches!(
        sign_issuer(ca.path(), PASSPHRASE, out.path(), now()),
        Err(CaError::Exists(_))
    ));
    assert_eq!(
        std::fs::read(out.path().join(ISSUER_KEY)).expect("key"),
        key
    );
}

#[cfg(unix)]
#[test]
fn private_keys_are_readable_by_their_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let ca = tempfile::tempdir().expect("ca dir");
    let out = tempfile::tempdir().expect("issuer dir");
    init(ca.path(), PASSPHRASE, now()).expect("init");
    sign_issuer(ca.path(), PASSPHRASE, out.path(), now()).expect("issuer");
    for key in [ca.path().join(ROOT_KEY), out.path().join(ISSUER_KEY)] {
        let mode = std::fs::metadata(&key)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{}", key.display());
    }
}

#[test]
fn the_issuer_lasts_a_year_and_the_ceiling() {
    let ca = tempfile::tempdir().expect("ca dir");
    let out = tempfile::tempdir().expect("issuer dir");
    init(ca.path(), PASSPHRASE, now()).expect("init");
    sign_issuer(ca.path(), PASSPHRASE, out.path(), now()).expect("issuer");
    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("root");
    let issuer = std::fs::read(out.path().join(ISSUER_CERTIFICATE)).expect("issuer");
    let key = std::fs::read(out.path().join(ISSUER_KEY)).expect("key");
    let loaded = DeviceIssuer::new(
        issuer,
        KeyPair::try_from(key.as_slice()).expect("key"),
        &root,
    )
    .expect("load");
    assert_eq!(loaded.not_after(), now() + ISSUER_VALIDITY);
}
