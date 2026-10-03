use parking_lot::Mutex;
use std::collections::HashMap;

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
