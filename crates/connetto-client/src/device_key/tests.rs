use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use connetto_core::device_cert::{
    CertificateRequest, CertificateSigner, DeviceKey, KeyHome, key_id, public_key_info,
};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

use super::*;

/// Records held in memory, standing in for the platform store.
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
}

const ALICE: &str = "\"alice\"";

#[tokio::test]
async fn a_software_key_is_created_once_and_reopened_after() {
    let records = Memory::default();
    let first = open_software_key(&records, ALICE).await.expect("create");
    assert!(first.created);
    let again = open_software_key(&records, ALICE).await.expect("reopen");
    assert!(!again.created);
    assert_eq!(first.key.public_point(), again.key.public_point());
    assert_eq!(first.key.home(), KeyHome::Software);
}

#[tokio::test]
async fn each_account_gets_its_own_key() {
    let records = Memory::default();
    let alice = open_software_key(&records, ALICE).await.expect("alice");
    let bob = open_software_key(&records, "\"bob\"").await.expect("bob");
    assert_ne!(alice.key.public_point(), bob.key.public_point());
}

#[tokio::test]
async fn an_unreadable_record_is_replaced_by_a_fresh_key() {
    let records = Memory::default();
    records
        .write(&crate::device_key_record(ALICE), "not a key")
        .await
        .expect("seed");
    let opened = open_software_key(&records, ALICE).await.expect("open");
    assert!(opened.created, "a key that cannot be read is a lost key");
    let again = open_software_key(&records, ALICE).await.expect("reopen");
    assert_eq!(opened.key.public_point(), again.key.public_point());
}

#[tokio::test]
async fn its_signatures_verify_under_its_public_key() {
    let records = Memory::default();
    let opened = open_software_key(&records, ALICE).await.expect("create");
    let signature = opened.key.sign(b"a hash-chain head").expect("sign");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, opened.key.public_point())
        .verify(b"a hash-chain head", &signature)
        .expect("the signature verifies");
}

#[tokio::test]
async fn it_requests_a_certificate_naming_itself() {
    let records = Memory::default();
    let opened = open_software_key(&records, ALICE).await.expect("create");
    let key: &dyn DeviceKey = &opened.key;
    let csr = CertificateRequest::build(&CertificateSigner::new(key), &[3; 32]).expect("build");
    let request = CertificateRequest::parse(&csr).expect("the request verifies");
    assert_eq!(request.public_key(), public_key_info(key).as_slice());
    assert_eq!(
        connetto_core::device_cert::KeyId::of_public_key(request.public_key()),
        key_id(key)
    );
}

/// A chip that holds keys in memory, or refuses to make one.
#[derive(Default)]
struct FakeChip {
    keys: Mutex<HashMap<String, [u8; 65]>>,
    refuses: bool,
    creations: Mutex<usize>,
}

struct FakeChipKey([u8; 65]);

impl DeviceKey for FakeChipKey {
    fn public_point(&self) -> [u8; 65] {
        self.0
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, connetto_core::device_cert::DeviceKeyError> {
        Ok(vec![0x30])
    }
    fn home(&self) -> KeyHome {
        KeyHome::SecureEnclave
    }
}

impl ChipKeys for FakeChip {
    type Key = FakeChipKey;

    fn find(&self, label: &str) -> Result<Option<FakeChipKey>, ChipError> {
        Ok(self.keys.lock().get(label).copied().map(FakeChipKey))
    }

    fn create(&self, label: &str) -> Result<FakeChipKey, ChipError> {
        *self.creations.lock() += 1;
        if self.refuses {
            return Err(ChipError::Unavailable("no secure enclave".into()));
        }
        let mut point = [4_u8; 65];
        point[1] = u8::try_from(self.keys.lock().len()).expect("few keys");
        self.keys.lock().insert(label.to_owned(), point);
        Ok(FakeChipKey(point))
    }
}

#[tokio::test]
async fn a_chip_key_is_made_once_and_preferred_after() {
    let (chip, records) = (Arc::new(FakeChip::default()), Memory::default());
    let first = open_device_key(Arc::clone(&chip), &records, "svc", ALICE)
        .await
        .expect("create");
    assert!(first.created);
    assert_eq!(first.key.home(), KeyHome::SecureEnclave);
    let again = open_device_key(Arc::clone(&chip), &records, "svc", ALICE)
        .await
        .expect("reopen");
    assert!(!again.created);
    assert_eq!(first.key.public_point(), again.key.public_point());
    assert_eq!(*chip.creations.lock(), 1);
    assert!(
        records.0.lock().is_empty(),
        "a chip key leaves no software record"
    );
}

#[tokio::test]
async fn a_device_without_a_chip_falls_back_to_software_and_stays_there() {
    let chip = Arc::new(FakeChip {
        refuses: true,
        ..FakeChip::default()
    });
    let records = Memory::default();
    let first = open_device_key(Arc::clone(&chip), &records, "svc", ALICE)
        .await
        .expect("fall back");
    assert!(first.created);
    assert_eq!(first.key.home(), KeyHome::Software);
    let again = open_device_key(Arc::clone(&chip), &records, "svc", ALICE)
        .await
        .expect("reopen");
    assert!(!again.created);
    assert_eq!(first.key.public_point(), again.key.public_point());
    assert_eq!(
        *chip.creations.lock(),
        1,
        "a stored software key is not traded for a chip"
    );
}

#[tokio::test]
async fn accounts_and_apps_get_distinct_chip_keys() {
    let (chip, records) = (Arc::new(FakeChip::default()), Memory::default());
    let alice = open_device_key(Arc::clone(&chip), &records, "svc", ALICE)
        .await
        .expect("alice");
    let bob = open_device_key(Arc::clone(&chip), &records, "svc", "\"bob\"")
        .await
        .expect("bob");
    let other_app = open_device_key(Arc::clone(&chip), &records, "other", ALICE)
        .await
        .expect("other app");
    assert_ne!(alice.key.public_point(), bob.key.public_point());
    assert_ne!(alice.key.public_point(), other_app.key.public_point());
}

/// Runs wherever an Apple build runs: an entitled build on enclave hardware
/// keeps the key in the enclave, any other build falls back to software.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tokio::test]
async fn the_enclave_or_its_fallback_signs_and_reopens() {
    let records = Memory::default();
    let account = format!("\"enclave-test-{}\"", std::process::id());
    let chip = Arc::new(apple::SecureEnclave);
    let first = open_device_key(Arc::clone(&chip), &records, "dev.connetto.test", &account)
        .await
        .expect("open");
    assert!(matches!(
        first.key.home(),
        KeyHome::SecureEnclave | KeyHome::Software
    ));
    let signature = first.key.sign(b"head").expect("sign");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, first.key.public_point())
        .verify(b"head", &signature)
        .expect("the signature verifies");
    let again = open_device_key(chip, &records, "dev.connetto.test", &account)
        .await
        .expect("reopen");
    assert_eq!(first.key.public_point(), again.key.public_point());
    eprintln!("device key home: {:?}", first.key.home());
}
