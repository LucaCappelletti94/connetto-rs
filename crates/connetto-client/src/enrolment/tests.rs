use core::time::Duration;
use std::collections::HashMap;
use std::time::SystemTime;

use base64::Engine as _;
use connetto_core::device_cert::{
    CertificateRequest, CertificateSigner, DeploymentId, DeviceCertificate, DeviceIssuer,
    DeviceKey, RootCa, public_key_info,
};
use diesel::Connection as _;
use diesel::connection::SimpleConnection as _;
use diesel::sqlite::SqliteConnection;
use parking_lot::Mutex;

use super::task::next_look;
use super::{CERTIFICATE_DDL, Held, Standing, TOLERANCE, delete, load, store};
use crate::ClientError;
use crate::device_key::{KeyRecords, open_software_key};

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
        .issue(&request, "alice", not_before, lifetime, [3; 16])
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
