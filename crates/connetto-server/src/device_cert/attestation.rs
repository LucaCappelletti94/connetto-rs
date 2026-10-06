//! Verifying the attestation a device offers at enrolment (R74 step 4):
//! the Android Keystore chain, Apple's App Attest object and Google's
//! attestation status list (decisions 7, 13, 31 to 34).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{ANDROID_ATTESTATION_CHALLENGE, AttestationLevel};
use connetto_core::messages::DeviceAttestation;
use serde::Deserialize;
use sha2::digest::Digest;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::X509Extension;
use x509_parser::prelude::FromDer;

/// The Android key attestation extension, under Google's enterprise number.
const KEY_DESCRIPTION: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
/// Apple's App Attest nonce extension.
const NONCE: &[u64] = &[1, 2, 840, 113_635, 100, 8, 2];
/// The `fmt` of an App Attest attestation object.
const APP_ATTEST: &str = "apple-appattest";
/// The attestation security levels that prove a key lives in a chip.
const TRUSTED_ENVIRONMENT: u8 = 1;
const STRONG_BOX: u8 = 2;
/// The attestation security level of a software key, never chip-proven.
const SOFTWARE: u8 = 0;
/// How long a copy of the status list stays usable (decision 34).
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the larger-unit `Duration` constructors are not yet stable"
)]
const LIST_AGE: Duration = Duration::from_secs(7 * 86_400);
/// The refresh period when a response names no `max-age`.
const REFRESH_DEFAULT: Duration = Duration::from_secs(3_600);
/// The shortest refresh period, so a source cannot hammer the list.
const REFRESH_FLOOR: Duration = Duration::from_secs(60);
/// The bound on one status list fetch.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Where the Android attestation status list comes from (decision 34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AndroidStatus {
    /// Fetched over HTTP(S), keeping the last good copy across failures.
    Url(String),
    /// Read from a local file, for air-gapped deployments and tests.
    File(PathBuf),
}

impl Default for AndroidStatus {
    /// Google's list, the source `CONNETTO_DEVICE_ANDROID_STATUS` replaces.
    fn default() -> Self {
        Self::Url("https://android.googleapis.com/attestation/status".to_owned())
    }
}

impl core::fmt::Display for AndroidStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Url(url) => f.write_str(url),
            Self::File(path) => path.display().fmt(f),
        }
    }
}

/// The environment the deployment's App IDs attest in (decision 32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestEnvironment {
    /// Attested after distribution, the `aaguid` `appattest` followed by seven
    /// zero bytes.
    Production,
    /// Attested in Apple's sandbox, the `aaguid` `appattestdevelop`.
    Development,
}

impl AppAttestEnvironment {
    /// The environment's `aaguid`, 16 bytes.
    #[must_use]
    pub const fn aaguid(self) -> [u8; 16] {
        match self {
            Self::Production => *b"appattest\0\0\0\0\0\0\0",
            Self::Development => *b"appattestdevelop",
        }
    }

    /// The environment `name` spells, the spelling
    /// `CONNETTO_DEVICE_APP_ATTEST_ENVIRONMENT` uses.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "production" => Some(Self::Production),
            "development" => Some(Self::Development),
            _ => None,
        }
    }
}

impl core::fmt::Display for AppAttestEnvironment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Production => "production",
            Self::Development => "development",
        })
    }
}

/// The App IDs App Attest vouches for, under one environment (decision 32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestSettings {
    /// The App IDs, each `TEAMID.bundle.id`.
    pub app_ids: Vec<String>,
    /// The environment their attestations come from.
    pub environment: AppAttestEnvironment,
}

/// What Google's status list says of a serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialStatus {
    /// The key is revoked, its certificate no longer valid.
    Revoked,
    /// The key is suspended, its certificate not to be trusted.
    Suspended,
}

impl core::fmt::Display for SerialStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
        })
    }
}

/// One serial's check against the copy usable at the moment of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialCheck {
    /// The copy is usable and does not name the serial.
    Clean,
    /// The copy is usable and names the serial.
    Bad(SerialStatus),
    /// No usable copy, so the serial is unchecked.
    NoCopy,
}

#[derive(Debug)]
struct StatusCache {
    /// The serials the list names, lowercase hex without leading zeros.
    entries: HashMap<String, SerialStatus>,
    /// When the copy was fetched, `None` before the first good fetch.
    fetched_at: Option<SystemTime>,
    /// The refresh period the last good response named.
    period: Duration,
}

/// Google's attestation status list, fetched at startup and when the
/// response's `Cache-Control` age runs out, keeping the last good copy
/// across failures (decision 34).
#[derive(Debug, Clone)]
pub struct StatusList {
    inner: Arc<StatusInner>,
}

#[derive(Debug)]
struct StatusInner {
    source: AndroidStatus,
    client: reqwest::Client,
    cache: parking_lot::Mutex<StatusCache>,
}

impl StatusList {
    /// The list at `source`, fetched by the task [`spawn`](Self::spawn) starts.
    ///
    /// # Panics
    ///
    /// When the `reqwest` client will not build.
    pub fn new(source: AndroidStatus) -> Self {
        let list = Self {
            inner: Arc::new(StatusInner {
                source,
                client: reqwest::Client::builder()
                    .timeout(REQUEST_TIMEOUT)
                    .build()
                    .expect("a reqwest client with a request timeout"),
                cache: parking_lot::Mutex::new(StatusCache {
                    entries: HashMap::new(),
                    fetched_at: None,
                    period: REFRESH_DEFAULT,
                }),
            }),
        };
        // A local file loads at construction, so the first enrolment never races the fetch.
        if let AndroidStatus::File(_) = &list.inner.source {
            list.load_file();
        }
        list
    }

    /// Reads the local file into the copy, keeping the empty one when it fails.
    fn load_file(&self) {
        let AndroidStatus::File(path) = &self.inner.source else {
            return;
        };
        let Ok(bytes) = std::fs::read(path) else {
            tracing::warn!("the attestation status list could not be read");
            return;
        };
        let Ok(entries) = StatusDocument::from_bytes(&bytes) else {
            tracing::warn!("the attestation status list could not be parsed");
            return;
        };
        let mut cache = self.inner.cache.lock();
        cache.entries = entries;
        cache.fetched_at = Some(SystemTime::now());
    }

    /// The startup fetch and the refetches, on a task the runtime ends with.
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let period = this.fetch().await;
                tokio::time::sleep(period).await;
            }
        })
    }

    /// A serial's check, a copy that is missing or older than seven days answering [`SerialCheck::NoCopy`].
    pub fn serial(&self, serial: &[u8]) -> SerialCheck {
        let cache = self.inner.cache.lock();
        let Some(fetched_at) = cache.fetched_at else {
            return SerialCheck::NoCopy;
        };
        let usable = fetched_at
            .checked_add(LIST_AGE)
            .is_some_and(|until| SystemTime::now() < until);
        if !usable {
            return SerialCheck::NoCopy;
        }
        match cache.entries.get(&serial_hex(serial)) {
            Some(status) => SerialCheck::Bad(*status),
            None => SerialCheck::Clean,
        }
    }

    /// Fetch once, answering the period to sleep for before the next fetch.
    async fn fetch(&self) -> Duration {
        let Some((entries, period)) = self.download().await else {
            return self.inner.cache.lock().period;
        };
        let mut cache = self.inner.cache.lock();
        cache.entries = entries;
        cache.fetched_at = Some(SystemTime::now());
        cache.period = period;
        period
    }

    /// The list at the source, and the `max-age` its response named.
    async fn download(&self) -> Option<(HashMap<String, SerialStatus>, Duration)> {
        let bytes = match &self.inner.source {
            AndroidStatus::Url(url) => {
                let Ok(response) = self.inner.client.get(url).send().await else {
                    tracing::warn!("the attestation status list could not be fetched");
                    return None;
                };
                let period = max_age(response.headers());
                let Ok(bytes) = response.bytes().await else {
                    tracing::warn!("the attestation status list could not be read");
                    return None;
                };
                Some((bytes.to_vec(), period))
            }
            AndroidStatus::File(path) => {
                let Ok(bytes) = tokio::fs::read(path).await else {
                    tracing::warn!("the attestation status list could not be read");
                    return None;
                };
                Some((bytes, REFRESH_DEFAULT))
            }
        };
        let (bytes, period) = bytes?;
        let Ok(entries) = StatusDocument::from_bytes(&bytes) else {
            tracing::warn!("the attestation status list could not be parsed");
            return None;
        };
        Some((entries, period))
    }
}

/// The serial the way Google's list keys it, lowercase hex without leading
/// zeros.
fn serial_hex(serial: &[u8]) -> String {
    let mut hex = String::with_capacity(serial.len() * 2);
    for byte in serial {
        hex.push(char::from(HEX[usize::from(*byte >> 4)]));
        hex.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    hex.trim_start_matches('0').to_owned()
}

/// `max-age` seconds in a `Cache-Control` header, the default when none,
/// floored at the refresh floor.
fn max_age(headers: &reqwest::header::HeaderMap) -> Duration {
    let period = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .find_map(|part| part.trim().strip_prefix("max-age="))
                .and_then(|age| age.parse::<u64>().ok())
        })
        .map_or(REFRESH_DEFAULT, Duration::from_secs);
    period.max(REFRESH_FLOOR)
}

/// The shape Google's status list takes.
#[derive(Deserialize)]
struct StatusDocument {
    entries: HashMap<String, StatusEntry>,
}

#[derive(Deserialize)]
struct StatusEntry {
    status: String,
}

impl StatusDocument {
    fn from_bytes(bytes: &[u8]) -> Result<HashMap<String, SerialStatus>, serde_json::Error> {
        let document: Self = serde_json::from_slice(bytes)?;
        Ok(document
            .entries
            .into_iter()
            .filter_map(|(serial, entry)| match entry.status.as_str() {
                "REVOKED" => Some((serial, SerialStatus::Revoked)),
                "SUSPENDED" => Some((serial, SerialStatus::Suspended)),
                _ => None,
            })
            .collect())
    }
}

/// The evidence is not for this request, so the enrolment is refused as
/// `InvalidRequest`, naming the first check that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AttestationMismatch {
    /// The chain's leaf, or the key the description attests, is not the request's key.
    #[error("the attestation is for a different key")]
    Key,
    /// The attestation's challenge is not the fixed one the request signs.
    #[error("the attestation names a different challenge")]
    Challenge,
    /// The App Attest object's CBOR, field layout or authenticator data does not parse.
    #[error("the App Attest object does not parse")]
    Object,
    /// The App Attest chain does not verify to the configured Apple root.
    #[error("the App Attest chain does not verify to its root")]
    Chain,
    /// The App Attest nonce does not match the authenticator data and the request.
    #[error("the App Attest nonce does not match")]
    Nonce,
    /// The App Attest key id, or the authenticator data's credential id, does not match the key.
    #[error("the App Attest key id does not match the key")]
    KeyId,
    /// The App Attest counter is not fresh, the assertion was replayed.
    #[error("the App Attest counter is not fresh")]
    Counter,
    /// The App Attest `aaguid` names an environment no deployment lists.
    #[error("the App Attest environment is not listed")]
    Environment,
}

/// The level the evidence proves, or a refusal when it is not for the
/// request.
pub(crate) fn verify(
    config: &super::DeviceCertConfig,
    status: Option<&StatusList>,
    evidence: Option<&DeviceAttestation>,
    csr: &[u8],
    spki: &[u8],
) -> Result<AttestationLevel, AttestationMismatch> {
    match evidence {
        None => Ok(AttestationLevel::Unproven),
        Some(DeviceAttestation::AndroidKeyChain(chain)) => android(config, status, chain, spki),
        Some(DeviceAttestation::AppleAppAttest {
            key_id,
            attestation,
        }) => apple(config, attestation, key_id, csr),
    }
}

/// The level an Android attestation chain proves (decisions 13 and 31).
fn android(
    config: &super::DeviceCertConfig,
    status: Option<&StatusList>,
    chain: &[serde_bytes::ByteBuf],
    spki: &[u8],
) -> Result<AttestationLevel, AttestationMismatch> {
    let Some(certs) = chain
        .iter()
        .map(|bytes| X509Certificate::from_der(bytes).ok().map(|(_, cert)| cert))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(record_unproven("the attestation chain does not parse"));
    };
    // A chain naming a different key is a refusal, not a lower level.
    if certs
        .first()
        .is_none_or(|leaf| leaf.public_key().raw != spki)
    {
        return Err(AttestationMismatch::Key);
    }
    // The description is trusted only where Google puts it, on the leaf the
    // device signs with. The one nearest the root says which key is attested,
    // so a description on any other certificate leaves the leaf's key unproven.
    let attesting = certs
        .iter()
        .enumerate()
        .rev()
        .find_map(|(position, cert)| find_extension(cert, KEY_DESCRIPTION).map(|_| position));
    let Some(position) = attesting else {
        return Ok(record_unproven(
            "the chain carries no usable key description",
        ));
    };
    if position != 0 {
        return Ok(record_unproven("the attested key is not the leaf"));
    }
    let description = find_extension(
        certs
            .first()
            .expect("a chain that named a key carries a leaf"),
        KEY_DESCRIPTION,
    )
    .and_then(|extension| key_description(extension.value));
    let Some((challenge, level, attested_key)) = description else {
        return Ok(record_unproven(
            "the chain carries no usable key description",
        ));
    };
    // A chain naming a different challenge or key is a refusal, not a lower level.
    if challenge != ANDROID_ATTESTATION_CHALLENGE {
        return Err(AttestationMismatch::Challenge);
    }
    if attested_key.is_some_and(|key| key != spki) {
        return Err(AttestationMismatch::Key);
    }
    // Every serial against the status list, the copy's age included.
    let Some(list) = status else {
        return Ok(record_unproven("no attestation status list is configured"));
    };
    for cert in &certs {
        match list.serial(cert.raw_serial()) {
            SerialCheck::Clean => {}
            SerialCheck::Bad(status) => {
                return Ok(record_unproven(&format!(
                    "the chain's serial {} is {status} in the status list",
                    serial_hex(cert.raw_serial())
                )));
            }
            SerialCheck::NoCopy => {
                return Ok(record_unproven(
                    "no usable copy of the attestation status list",
                ));
            }
        }
    }
    // The chain's signatures, up to a configured attestation root.
    if !chain_rooted(config, &certs) {
        return Ok(record_unproven(
            "the chain is not rooted in a configured attestation root",
        ));
    }
    match level {
        TRUSTED_ENVIRONMENT | STRONG_BOX => Ok(AttestationLevel::ChipProven),
        SOFTWARE => Ok(record_unproven("the chain attests a software key")),
        _ => Ok(record_unproven(
            "the chain names an unknown attestation security level",
        )),
    }
}

/// Whether `certs`, leaf first, verifies to one of `config`'s attestation
/// roots, matched by public key, the root's own signature included.
fn chain_rooted(config: &super::DeviceCertConfig, certs: &[X509Certificate<'_>]) -> bool {
    if certs.len() < 2 {
        return false;
    }
    for (cert, issuer) in certs.iter().zip(certs.iter().skip(1)) {
        if cert.verify_signature(Some(issuer.public_key())).is_err() {
            return false;
        }
    }
    let Some(top) = certs.last() else {
        return false;
    };
    config
        .android_roots()
        .iter()
        .filter_map(|root| X509Certificate::from_der(root).map(|(_, cert)| cert).ok())
        .any(|root| {
            top.public_key().raw == root.public_key().raw && top.verify_signature(None).is_ok()
        })
}

/// The extension with the arcs `oid`, the first one found.
fn find_extension<'c>(cert: &'c X509Certificate<'c>, oid: &[u64]) -> Option<&'c X509Extension<'c>> {
    cert.iter_extensions().find(|extension| {
        extension
            .oid
            .iter()
            .is_some_and(|arcs| arcs.eq(oid.iter().copied()))
    })
}

/// The first `KeyDescription` fields, `None` when the value does not parse:
/// the challenge, the security level, and the attested key's `SPKI` where
/// the format carries one.
fn key_description(value: &[u8]) -> Option<(Vec<u8>, u8, Option<Vec<u8>>)> {
    let children = der_children(value)?;
    let first = *children.first()?;
    match first.tag {
        // The keymint layout, versions 300 up: the version leads and the
        // challenge is fifth.
        0x02 => Some((
            children.get(4)?.as_octet_string()?.to_vec(),
            children.get(1)?.as_enumerated()?,
            None,
        )),
        // The keymaster layout: the challenge leads, the level is third, and
        // the attested key's `SPKI` rides in the key description's third field.
        0x04 => {
            let attested = children
                .get(3)
                .filter(|key| key.tag == 0x30)
                .and_then(|key| der_children(key.value))
                .and_then(|fields| {
                    fields
                        .get(2)
                        .filter(|field| field.tag == 0x04)
                        .map(|field| field.value.to_vec())
                });
            Some((
                first.value.to_vec(),
                children.get(2)?.as_enumerated()?,
                attested,
            ))
        }
        _ => None,
    }
}

/// The level a failure to prove takes, said why at `info`.
fn record_unproven(cause: &str) -> AttestationLevel {
    tracing::info!(%cause, "the device's attestation proves nothing, its level is unproven");
    AttestationLevel::Unproven
}

/// One parsed DER field.
#[derive(Debug, Clone, Copy)]
struct DerField<'a> {
    tag: u8,
    value: &'a [u8],
    /// The whole field's length, for walking a sequence's children.
    total: usize,
}

impl<'a> DerField<'a> {
    /// An `ENUMERATED` of one byte, the security levels take.
    fn as_enumerated(&self) -> Option<u8> {
        (self.tag == 0x0A && self.value.len() == 1).then_some(self.value[0])
    }

    /// An `OCTET STRING`'s content.
    fn as_octet_string(&self) -> Option<&'a [u8]> {
        (self.tag == 0x04).then_some(self.value)
    }
}

/// The children of a DER sequence that fills `data`, `None` when the prefix
/// does not parse as one.
fn der_children(data: &[u8]) -> Option<Vec<DerField<'_>>> {
    let sequence = der_tlv(data)?;
    if sequence.tag != 0x30 {
        return None;
    }
    let mut children = Vec::new();
    let mut rest = sequence.value;
    while !rest.is_empty() {
        let child = der_tlv(rest)?;
        children.push(child);
        rest = &rest[child.total..];
    }
    Some(children)
}

/// A DER field's tag, content and whole length, `None` when the prefix does
/// not parse.
fn der_tlv(data: &[u8]) -> Option<DerField<'_>> {
    let tag = *data.first()?;
    let (length, octets) = der_length(&data[1..])?;
    let total = 1usize.checked_add(octets)?.checked_add(length)?;
    data.get(..total).map(|_| DerField {
        tag,
        value: &data[1 + octets..total],
        total,
    })
}

/// A DER length, answering the byte count and how many leading octets it
/// took, `None` for the indefinite form DER forbids.
fn der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 8 || data.len() < 1 + count {
        return None;
    }
    let mut length = 0usize;
    for byte in &data[1..=count] {
        length = (length << 8) | usize::from(*byte);
    }
    Some((length, 1 + count))
}

/// The level an App Attest object proves (decision 32).
fn apple(
    config: &super::DeviceCertConfig,
    attestation: &[u8],
    key_id: &[u8],
    csr: &[u8],
) -> Result<AttestationLevel, AttestationMismatch> {
    let Ok(object) = ciborium::de::from_reader::<ciborium::Value, _>(attestation) else {
        return Err(AttestationMismatch::Object);
    };
    let Some(ciborium::Value::Text(fmt)) = object_field(&object, "fmt") else {
        return Err(AttestationMismatch::Object);
    };
    if fmt != APP_ATTEST {
        return Err(AttestationMismatch::Object);
    }
    let Some(statement) = object_field(&object, "attStmt") else {
        return Err(AttestationMismatch::Object);
    };
    let Some(ciborium::Value::Array(chain)) = object_field(statement, "x5c") else {
        return Err(AttestationMismatch::Object);
    };
    let certs: Vec<&[u8]> = chain
        .iter()
        .filter_map(|entry| match entry {
            ciborium::Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .collect();
    let Some(auth_data) = object_field(statement, "authData").and_then(|value| match value {
        ciborium::Value::Bytes(bytes) => Some(bytes.as_slice()),
        _ => None,
    }) else {
        return Err(AttestationMismatch::Object);
    };
    // The credential certificate leads the chain, up to Apple's root.
    if !app_attest_chain(config, &certs) {
        return Err(AttestationMismatch::Chain);
    }
    let Some((_, cred_cert)) = certs
        .first()
        .and_then(|bytes| X509Certificate::from_der(bytes).ok())
    else {
        return Err(AttestationMismatch::Chain);
    };
    // Apple's nonce is the SHA-256 of the authenticator data with the client data hash appended.
    let nonce = sha256_concat(auth_data, &sha256(csr));
    if nonce_extension(&cred_cert).is_none_or(|held| held != nonce) {
        return Err(AttestationMismatch::Nonce);
    }
    // The key id and the authenticator data's credential id both hash the
    // credential key's public part in X9.62 uncompressed point form.
    let Some(point) = x962_point(cred_cert.public_key().raw) else {
        return Err(AttestationMismatch::Key);
    };
    let key_hash = sha256(point);
    if key_hash != key_id {
        return Err(AttestationMismatch::KeyId);
    }
    let Some(fields) = auth_data_fields(auth_data) else {
        return Err(AttestationMismatch::Object);
    };
    if fields.credential_id != key_hash {
        return Err(AttestationMismatch::KeyId);
    }
    if fields.counter != 0 {
        return Err(AttestationMismatch::Counter);
    }
    // The `aaguid` says which environment attested, a third value fails.
    let environment = if fields.aaguid == AppAttestEnvironment::Production.aaguid() {
        AppAttestEnvironment::Production
    } else if fields.aaguid == AppAttestEnvironment::Development.aaguid() {
        AppAttestEnvironment::Development
    } else {
        return Err(AttestationMismatch::Environment);
    };
    // The `rpId` hash is the hash of the App ID the object attests.
    let Some(settings) = config.app_attest() else {
        return Ok(record_unproven("no App IDs are configured for App Attest"));
    };
    if !settings
        .app_ids
        .iter()
        .any(|app_id| sha256(app_id.as_bytes()) == fields.rp_id_hash)
    {
        return Ok(record_unproven(
            "the attestation vouches for an App ID the deployment does not list",
        ));
    }
    if settings.environment != environment {
        return Ok(record_unproven(&format!(
            "the attestation comes from the {environment} environment, the deployment lists the App ID under {}",
            settings.environment
        )));
    }
    Ok(AttestationLevel::AppAttested)
}

/// Whether the `x5c` chain, credential certificate first, verifies to the
/// configured Apple root.
fn app_attest_chain(config: &super::DeviceCertConfig, certs: &[&[u8]]) -> bool {
    let Some((_, root)) = X509Certificate::from_der(config.apple_root()).ok() else {
        return false;
    };
    let Ok(parsed) = certs
        .iter()
        .map(|bytes| X509Certificate::from_der(bytes).map(|(_, cert)| cert))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    if parsed.is_empty() {
        return false;
    }
    for (cert, issuer) in parsed.iter().zip(parsed.iter().skip(1)) {
        if cert.verify_signature(Some(issuer.public_key())).is_err() {
            return false;
        }
    }
    parsed
        .last()
        .is_some_and(|top| top.verify_signature(Some(root.public_key())).is_ok())
}

/// The nonce extension's octet string, `None` when absent or unparseable,
/// the extension holding a single octet string in a sequence.
fn nonce_extension(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
    let extension = find_extension(cert, NONCE)?;
    let children = der_children(extension.value)?;
    let [inner] = children.as_slice() else {
        return None;
    };
    inner.as_octet_string().map(<[u8]>::to_vec)
}

/// The App Attest authenticator data's checked fields, `None` when the
/// layout departs: a 32-byte `rpId` hash, a 4-byte counter, a 16-byte
/// `aaguid`, a 2-byte credential id length of 32, the 32-byte credential id
/// and the 77-byte encoded key.
fn auth_data_fields(auth_data: &[u8]) -> Option<AuthDataFields> {
    const MINIMUM: usize = 32 + 4 + 16 + 2 + 32 + 77;
    if auth_data.len() < MINIMUM {
        return None;
    }
    let counter = u32::from_be_bytes(auth_data[32..36].try_into().ok()?);
    let aaguid = auth_data[36..52].try_into().ok()?;
    let credential_length = u16::from_be_bytes(auth_data[52..54].try_into().ok()?);
    if credential_length != 32 {
        return None;
    }
    Some(AuthDataFields {
        rp_id_hash: auth_data[..32].to_vec(),
        counter,
        aaguid,
        credential_id: auth_data[54..86].to_vec(),
    })
}

/// The authenticator data's fields, checked against the layout.
#[derive(Debug)]
struct AuthDataFields {
    /// The `rpId` hash, the hash of the App ID.
    rp_id_hash: Vec<u8>,
    /// The key's assertion count, 0 at attestation.
    counter: u32,
    /// The environment marker.
    aaguid: [u8; 16],
    /// The credential id, the hash of the credential key's public part.
    credential_id: Vec<u8>,
}

/// A map's text-keyed field.
fn object_field<'a>(object: &'a ciborium::Value, key: &str) -> Option<&'a ciborium::Value> {
    let ciborium::Value::Map(entries) = object else {
        return None;
    };
    entries.iter().find_map(|(name, value)| {
        matches!(name, ciborium::Value::Text(text) if text == key).then_some(value)
    })
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn sha256_concat(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().to_vec()
}

/// The X9.62 uncompressed point a P-256 `SPKI` carries, `None` otherwise.
fn x962_point(spki: &[u8]) -> Option<&[u8]> {
    let offset = spki.len().checked_sub(65)?;
    let point = &spki[offset..];
    (point.first() == Some(&0x04)).then_some(point)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use connetto_core::device_cert::{
        ANDROID_ATTESTATION_CHALLENGE, AttestationLevel, DeploymentId, DeviceIssuer, RootCa,
    };
    use connetto_core::messages::DeviceAttestation;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256, PublicKeyData,
    };
    use x509_parser::{certificate::X509Certificate, prelude::FromDer};

    use super::{
        AndroidStatus, AppAttestEnvironment, SerialCheck, SerialStatus, StatusCache, StatusList,
        serial_hex, verify,
    };

    type Config = super::super::DeviceCertConfig;

    /// One test certificate authority and its certificate.
    struct Ca {
        key: KeyPair,
        cert: Vec<u8>,
    }

    fn ca(subject: &str, issuer: Option<&Ca>) -> Ca {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut params = CertificateParams::new(vec![subject.to_owned()]).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = match issuer {
            None => params.self_signed(&key).expect("ca"),
            Some(issuer) => {
                let issuer = Issuer::new(
                    CertificateParams::new(vec![subject.to_owned()]).expect("params"),
                    &issuer.key,
                );
                params.signed_by(&key, &issuer).expect("ca")
            }
        };
        Ca {
            key,
            cert: cert.der().to_vec(),
        }
    }

    /// A fixture's validity window, ten years.
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "the larger-unit `Duration` constructors are not yet stable"
    )]
    const TEN_YEARS: Duration = Duration::from_secs(86_400 * 3_650);
    /// How far back a fixture's clock sits, one thousand days.
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "the larger-unit `Duration` constructors are not yet stable"
    )]
    const PAST: Duration = Duration::from_secs(86_400 * 1_000);
    /// A status list copy too old to be usable, eight days.
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "the larger-unit `Duration` constructors are not yet stable"
    )]
    const EIGHT_DAYS: Duration = Duration::from_secs(8 * 86_400);

    /// A `DeviceIssuer` under a fresh test root, the config defaults to.
    fn issuer() -> DeviceIssuer {
        let now = UNIX_EPOCH + PAST;
        let root = RootCa::create(
            DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
            now,
            TEN_YEARS,
        )
        .expect("root");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
        let cert = root
            .sign_issuer(&key.subject_public_key_info(), now, TEN_YEARS, [1; 16])
            .expect("issuer");
        DeviceIssuer::new(cert, key, root.certificate()).expect("issuer")
    }

    /// One DER tag-length-value, short or long form.
    fn der_tl(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len if len < 0x80 => {
                out.push(u8::try_from(len).expect("the length is guarded below 0x80"));
            }
            len => {
                let bytes = len.to_be_bytes();
                let first = bytes
                    .iter()
                    .position(|byte| *byte != 0)
                    .expect("a non-zero length");
                out.push(0x80 | u8::try_from(8 - first).expect("at most eight leading octets"));
                out.extend_from_slice(&bytes[first..]);
            }
        }
        out.extend_from_slice(content);
        out
    }

    /// A keymint `KeyDescription`: the version leads, the level is second, the
    /// challenge is fifth.
    fn keymint(level: u8, challenge: &[u8]) -> Vec<u8> {
        let children = [
            der_tl(0x02, &[0x00, 0x01, 0xF4]),
            der_tl(0x0A, &[level]),
            der_tl(0x04, b""),
            der_tl(0x30, &[0x01, 0x01, 0xFF]),
            der_tl(0x04, challenge),
        ];
        der_tl(0x30, &children.concat())
    }

    /// A keymaster `KeyDescription`: the challenge leads, the level is third,
    /// the attested key's `SPKI` rides in the inner key description.
    fn keymaster(level: u8, challenge: &[u8], spki: &[u8]) -> Vec<u8> {
        let inner = der_tl(
            0x30,
            &[
                der_tl(
                    0x06,
                    &[
                        0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x0C, 0x80, 0x03, 0x01, 0x04,
                    ],
                ),
                der_tl(
                    0x06,
                    &[
                        0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x0C, 0x80, 0x03, 0x01, 0x05,
                    ],
                ),
                der_tl(0x04, spki),
            ]
            .concat(),
        );
        let children = [
            der_tl(0x04, challenge),
            der_tl(0x04, b""),
            der_tl(0x0A, &[level]),
            inner,
        ];
        der_tl(0x30, &children.concat())
    }

    /// An Android attestation chain under `root`, leaf first, for `leaf`'s key.
    fn android_chain(
        root: &Ca,
        level: u8,
        challenge: &[u8],
        layout: Layout,
        spki: &[u8],
        leaf: &KeyPair,
    ) -> Vec<Vec<u8>> {
        let intermediate = ca("intermediate", Some(root));
        let description = match layout {
            Layout::Keymint => keymint(level, challenge),
            Layout::Keymaster => keymaster(level, challenge, spki),
        };
        let mut params = CertificateParams::new(vec!["leaf".to_owned()]).expect("params");
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            description,
        )];
        let issuer = Issuer::new(
            CertificateParams::new(vec!["intermediate".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let leaf_cert = params.signed_by(leaf, &issuer).expect("leaf");
        vec![
            leaf_cert.der().to_vec(),
            intermediate.cert,
            root.cert.clone(),
        ]
    }

    /// Which `KeyDescription` layout a fixture takes.
    #[derive(Debug, Clone, Copy)]
    enum Layout {
        Keymint,
        Keymaster,
    }

    /// The `verify` input of one Android enrolment, the SPKI read from the
    /// parsed request as the production path reads it.
    fn android(
        config: &Config,
        status: Option<&StatusList>,
        chain: Vec<Vec<u8>>,
        csr: &[u8],
    ) -> AttestationLevel {
        let spki = connetto_core::device_cert::CertificateRequest::parse(csr)
            .expect("csr")
            .public_key()
            .to_vec();
        let evidence: Vec<serde_bytes::ByteBuf> = chain.into_iter().map(Into::into).collect();
        verify(
            config,
            status,
            Some(&DeviceAttestation::AndroidKeyChain(evidence)),
            csr,
            &spki,
        )
        .expect("a well-formed chain answers a level, not a refusal")
    }

    fn csr(leaf: &KeyPair) -> Vec<u8> {
        connetto_core::device_cert::CertificateRequest::build(leaf, &[9; 32]).expect("csr")
    }

    fn spki(leaf: &KeyPair) -> Vec<u8> {
        connetto_core::device_cert::CertificateRequest::parse(&csr(leaf))
            .expect("csr")
            .public_key()
            .to_vec()
    }

    fn clean() -> StatusList {
        seeded(HashMap::new(), Some(SystemTime::now()))
    }

    fn seeded(
        entries: std::collections::HashMap<String, SerialStatus>,
        fetched_at: Option<SystemTime>,
    ) -> StatusList {
        let list = StatusList::new(AndroidStatus::File(std::path::PathBuf::from("/dev/null")));
        *list.inner.cache.lock() = StatusCache {
            entries,
            fetched_at,
            period: super::REFRESH_DEFAULT,
        };
        list
    }

    fn android_setup(level: u8, layout: Layout) -> (Config, Vec<Vec<u8>>, KeyPair) {
        let root = ca("attestation root", None);
        let config = Config::new(issuer()).with_android_roots(vec![root.cert.clone()]);
        let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let chain = android_chain(
            &root,
            level,
            ANDROID_ATTESTATION_CHALLENGE,
            layout,
            &spki(&leaf),
            &leaf,
        );
        (config, chain, leaf)
    }

    #[test]
    fn a_tee_chain_proves_a_chip_key_in_both_layouts() {
        for layout in [Layout::Keymint, Layout::Keymaster] {
            let (config, chain, leaf) = android_setup(1, layout);
            let level = android(&config, Some(&clean()), chain, &csr(&leaf));
            assert_eq!(level, AttestationLevel::ChipProven, "the {layout:?} layout");
        }
    }

    #[test]
    fn a_strong_box_chain_proves_a_chip_key() {
        let (config, chain, leaf) = android_setup(2, Layout::Keymint);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::ChipProven);
    }

    #[test]
    fn a_software_chain_proves_nothing() {
        let (config, chain, leaf) = android_setup(0, Layout::Keymint);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn an_unrooted_chain_proves_nothing() {
        let (config, chain, leaf) = android_setup(1, Layout::Keymint);
        let other = ca("a different root", None);
        let foreign = vec![chain[0].clone(), chain[1].clone(), other.cert];
        let level = android(&config, Some(&clean()), foreign, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn a_chain_with_a_bad_serial_proves_nothing() {
        for status in [SerialStatus::Revoked, SerialStatus::Suspended] {
            let (config, chain, leaf) = android_setup(1, Layout::Keymint);
            let (_, leaf_cert) = X509Certificate::from_der(&chain[0]).expect("leaf");
            let entries =
                std::collections::HashMap::from([(serial_hex(leaf_cert.raw_serial()), status)]);
            let level = android(
                &config,
                Some(&seeded(entries, Some(SystemTime::now()))),
                chain,
                &csr(&leaf),
            );
            assert_eq!(level, AttestationLevel::Unproven, "a {status:?} serial");
        }
    }

    #[test]
    fn a_list_with_no_usable_copy_proves_nothing() {
        let (config, chain, leaf) = android_setup(1, Layout::Keymint);
        assert_eq!(
            android(&config, None, chain.clone(), &csr(&leaf)),
            AttestationLevel::Unproven,
            "no list at all"
        );
        assert_eq!(
            android(
                &config,
                Some(&seeded(std::collections::HashMap::new(), None)),
                chain.clone(),
                &csr(&leaf)
            ),
            AttestationLevel::Unproven,
            "a list that never fetched"
        );
        let stale = seeded(
            std::collections::HashMap::new(),
            Some(SystemTime::now() - EIGHT_DAYS),
        );
        assert_eq!(
            android(&config, Some(&stale), chain, &csr(&leaf)),
            AttestationLevel::Unproven,
            "a copy eight days old"
        );
    }

    #[test]
    fn a_chain_of_another_key_or_challenge_is_a_refusal() {
        let (config, chain, leaf) = android_setup(1, Layout::Keymint);
        let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("other key");
        let evidence: Vec<serde_bytes::ByteBuf> =
            chain.iter().map(|der| der.clone().into()).collect();
        let attestation = DeviceAttestation::AndroidKeyChain(evidence);
        assert!(
            verify(
                &config,
                Some(&clean()),
                Some(&attestation),
                &csr(&leaf),
                other.public_key_raw()
            )
            .is_err(),
            "the chain names a different key"
        );
        let root = ca("attestation root", None);
        let config = Config::new(issuer()).with_android_roots(vec![root.cert.clone()]);
        let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let chain = android_chain(
            &root,
            1,
            b"a different challenge",
            Layout::Keymint,
            &spki(&leaf),
            &leaf,
        );
        let attestation = DeviceAttestation::AndroidKeyChain(
            chain.iter().map(|der| der.clone().into()).collect(),
        );
        assert!(
            verify(
                &config,
                Some(&clean()),
                Some(&attestation),
                &csr(&leaf),
                &spki(&leaf)
            )
            .is_err(),
            "the challenge is not the fixed one"
        );
    }

    /// A chain with no key description at all, leaf first.
    fn chain_without_description(root: &Ca, leaf: &KeyPair) -> Vec<Vec<u8>> {
        let intermediate = ca("intermediate", Some(root));
        let params = CertificateParams::new(vec!["leaf".to_owned()]).expect("params");
        let issuer = Issuer::new(
            CertificateParams::new(vec!["intermediate".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let leaf_cert = params.signed_by(leaf, &issuer).expect("leaf");
        vec![
            leaf_cert.der().to_vec(),
            intermediate.cert,
            root.cert.clone(),
        ]
    }

    #[test]
    fn an_unparseable_chain_proves_nothing() {
        let (config, _chain, leaf) = android_setup(1, Layout::Keymint);
        let chain = vec![b"not a certificate".to_vec(), b"still not".to_vec()];
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn a_chain_without_a_key_description_proves_nothing() {
        let root = ca("attestation root", None);
        let config = Config::new(issuer()).with_android_roots(vec![root.cert.clone()]);
        let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let chain = chain_without_description(&root, &leaf);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn an_unknown_security_level_proves_nothing() {
        let (config, chain, leaf) = android_setup(3, Layout::Keymint);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn a_one_certificate_chain_proves_nothing() {
        let (config, mut chain, leaf) = android_setup(1, Layout::Keymint);
        chain.truncate(1);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    /// An Android chain whose attesting key, one level above the leaf, carries
    /// the genuine TEE description, and whose leaf for `leaf`'s key carries a
    /// forged level-1 description, so the attested key is not the leaf.
    fn forged_leaf_chain(root: &Ca, leaf: &KeyPair) -> Vec<Vec<u8>> {
        let intermediate = ca("intermediate", Some(root));
        let attesting_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("attesting key");
        let mut attesting_params =
            CertificateParams::new(vec!["attesting".to_owned()]).expect("params");
        attesting_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        attesting_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            keymint(1, ANDROID_ATTESTATION_CHALLENGE),
        )];
        let attesting_issuer = Issuer::new(
            CertificateParams::new(vec!["attesting".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let attesting_cert = attesting_params
            .signed_by(&attesting_key, &attesting_issuer)
            .expect("attesting");
        let mut leaf_params = CertificateParams::new(vec!["leaf".to_owned()]).expect("params");
        leaf_params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            keymint(1, ANDROID_ATTESTATION_CHALLENGE),
        )];
        let leaf_issuer = Issuer::new(
            CertificateParams::new(vec!["attesting".to_owned()]).expect("params"),
            &attesting_key,
        );
        let leaf_cert = leaf_params.signed_by(leaf, &leaf_issuer).expect("leaf");
        vec![
            leaf_cert.der().to_vec(),
            attesting_cert.der().to_vec(),
            intermediate.cert,
            root.cert.clone(),
        ]
    }

    #[test]
    fn a_forged_leaf_description_proves_nothing() {
        let root = ca("attestation root", None);
        let config = Config::new(issuer()).with_android_roots(vec![root.cert.clone()]);
        let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let chain = forged_leaf_chain(&root, &leaf);
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(
            level,
            AttestationLevel::Unproven,
            "a description on the attesting key leaves the leaf's key unproven"
        );
    }

    /// A long-form DER length of `0xffffffffffffffff`, whose whole-field
    /// length overflows a `usize`.
    const OVERFLOWING_LENGTH: [u8; 11] = [
        0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];

    #[test]
    fn an_overflowing_der_length_answers_no_field() {
        assert!(super::der_tlv(&OVERFLOWING_LENGTH).is_none());
        assert!(super::key_description(&OVERFLOWING_LENGTH).is_none());
    }

    #[test]
    fn an_overflowing_leaf_description_proves_nothing() {
        let root = ca("attestation root", None);
        let config = Config::new(issuer()).with_android_roots(vec![root.cert.clone()]);
        let leaf = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let intermediate = ca("intermediate", Some(&root));
        let mut params = CertificateParams::new(vec!["leaf".to_owned()]).expect("params");
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            OVERFLOWING_LENGTH.to_vec(),
        )];
        let issuer = Issuer::new(
            CertificateParams::new(vec!["intermediate".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let leaf_cert = params.signed_by(&leaf, &issuer).expect("leaf");
        let chain = vec![
            leaf_cert.der().to_vec(),
            intermediate.cert,
            root.cert.clone(),
        ];
        let level = android(&config, Some(&clean()), chain, &csr(&leaf));
        assert_eq!(level, AttestationLevel::Unproven);
    }

    /// One App Attest object and its key, over `root`.
    fn apple(
        root: &Ca,
        app_id: &str,
        counter: u32,
        aaguid: [u8; 16],
        nonce: Option<Vec<u8>>,
        key_id: Option<Vec<u8>>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let intermediate = ca("intermediate", Some(root));
        let cred = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("credential key");
        let csr = csr(&cred);
        let credential_id = super::sha256(cred.public_key_raw());
        let auth_data = [
            super::sha256(app_id.as_bytes()),
            counter.to_be_bytes().to_vec(),
            aaguid.to_vec(),
            32u16.to_be_bytes().to_vec(),
            credential_id.clone(),
            vec![7u8; 77],
        ]
        .concat();
        let nonce = nonce.unwrap_or(super::sha256_concat(&auth_data, &super::sha256(&csr)));
        let mut params = CertificateParams::new(vec!["credential".to_owned()]).expect("params");
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            super::NONCE,
            der_tl(0x30, &der_tl(0x04, &nonce)),
        )];
        let issuer = Issuer::new(
            CertificateParams::new(vec!["intermediate".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let cred_cert = params.signed_by(&cred, &issuer).expect("credential");
        let key_id = key_id.unwrap_or(credential_id);
        let object = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".to_owned()),
                ciborium::Value::Text("apple-appattest".to_owned()),
            ),
            (
                ciborium::Value::Text("attStmt".to_owned()),
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("x5c".to_owned()),
                        ciborium::Value::Array(vec![
                            ciborium::Value::Bytes(cred_cert.der().to_vec()),
                            ciborium::Value::Bytes(intermediate.cert),
                        ]),
                    ),
                    (
                        ciborium::Value::Text("authData".to_owned()),
                        ciborium::Value::Bytes(auth_data),
                    ),
                ]),
            ),
        ]);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&object, &mut cbor).expect("cbor");
        (cbor, key_id, csr)
    }

    fn apple_setup(app_ids: &[&str], environment: AppAttestEnvironment) -> (Config, Ca) {
        let root = ca("apple root", None);
        let config = Config::new(issuer())
            .with_apple_root(root.cert.clone())
            .with_app_attest(
                app_ids.iter().map(|app_id| (*app_id).to_owned()).collect(),
                environment,
            );
        (config, root)
    }

    /// An attestation object with the given `fmt`, `x5c` and `authData`, the
    /// field absent where its part is `None`.
    fn object(
        fmt: ciborium::Value,
        x5c: Option<ciborium::Value>,
        auth_data: Option<ciborium::Value>,
    ) -> ciborium::Value {
        let mut statement = Vec::new();
        if let Some(x5c) = x5c {
            statement.push((ciborium::Value::Text("x5c".to_owned()), x5c));
        }
        if let Some(auth_data) = auth_data {
            statement.push((ciborium::Value::Text("authData".to_owned()), auth_data));
        }
        ciborium::Value::Map(vec![
            (ciborium::Value::Text("fmt".to_owned()), fmt),
            (
                ciborium::Value::Text("attStmt".to_owned()),
                ciborium::Value::Map(statement),
            ),
        ])
    }

    /// The object's bytes, CBOR.
    fn encode(object: &ciborium::Value) -> Vec<u8> {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&object, &mut cbor).expect("cbor");
        cbor
    }

    /// A valid object's `x5c` and `authData`, decoded.
    fn parts(attestation: &[u8]) -> (ciborium::Value, ciborium::Value) {
        let decoded: ciborium::Value = ciborium::de::from_reader(attestation).expect("cbor");
        let statement = super::object_field(&decoded, "attStmt").expect("attStmt");
        (
            super::object_field(statement, "x5c").expect("x5c").clone(),
            super::object_field(statement, "authData")
                .expect("authData")
                .clone(),
        )
    }

    /// The `x5c` chain's certificates, credential first.
    fn certificates(x5c: &ciborium::Value) -> Vec<Vec<u8>> {
        let ciborium::Value::Array(entries) = x5c else {
            panic!("the fixture's x5c is an array")
        };
        entries
            .iter()
            .map(|entry| match entry {
                ciborium::Value::Bytes(bytes) => bytes.clone(),
                _ => panic!("the fixture's x5c is byte strings"),
            })
            .collect()
    }

    /// The authenticator data with `app_id`'s hash, `counter`, `aaguid` and
    /// `credential_id`, the key's own hash where the last is `None`.
    fn auth_data(
        app_id: &str,
        counter: u32,
        aaguid: [u8; 16],
        credential_id: Option<Vec<u8>>,
        key: &KeyPair,
    ) -> Vec<u8> {
        [
            super::sha256(app_id.as_bytes()),
            counter.to_be_bytes().to_vec(),
            aaguid.to_vec(),
            32u16.to_be_bytes().to_vec(),
            credential_id.unwrap_or_else(|| super::sha256(key.public_key_raw())),
            vec![7u8; 77],
        ]
        .concat()
    }

    /// One App Attest object over `root` carrying `auth_data` as-is, the
    /// credential certificate's nonce matching it.
    fn apple_auth_data(
        root: &Ca,
        auth_data: Vec<u8>,
        key: &KeyPair,
        key_id: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let intermediate = ca("intermediate", Some(root));
        let csr = csr(key);
        let nonce = super::sha256_concat(&auth_data, &super::sha256(&csr));
        let mut params = CertificateParams::new(vec!["credential".to_owned()]).expect("params");
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            super::NONCE,
            der_tl(0x30, &der_tl(0x04, &nonce)),
        )];
        let issuer = Issuer::new(
            CertificateParams::new(vec!["intermediate".to_owned()]).expect("params"),
            &intermediate.key,
        );
        let cred_cert = params.signed_by(key, &issuer).expect("credential");
        let object = object(
            ciborium::Value::Text("apple-appattest".to_owned()),
            Some(ciborium::Value::Array(vec![
                ciborium::Value::Bytes(cred_cert.der().to_vec()),
                ciborium::Value::Bytes(intermediate.cert),
            ])),
            Some(ciborium::Value::Bytes(auth_data)),
        );
        (encode(&object), key_id, csr)
    }

    #[test]
    fn a_listed_app_attestation_proves_app_attested() {
        let (config, root) = apple_setup(&["TEAMID.bundle.id"], AppAttestEnvironment::Production);
        let (attestation, key_id, csr) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        let level = verify(
            &config,
            None,
            Some(&DeviceAttestation::AppleAppAttest {
                key_id,
                attestation,
            }),
            &csr,
            &[],
        )
        .expect("a valid object answers a level");
        assert_eq!(level, AttestationLevel::AppAttested);
    }

    #[test]
    fn an_unlisted_app_id_proves_nothing() {
        let (config, root) = apple_setup(&["other.bundle.id"], AppAttestEnvironment::Production);
        let (attestation, key_id, csr) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        let level = verify(
            &config,
            None,
            Some(&DeviceAttestation::AppleAppAttest {
                key_id,
                attestation,
            }),
            &csr,
            &[],
        )
        .expect("a valid object answers a level");
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn a_mismatched_environment_proves_nothing() {
        let (config, root) = apple_setup(&["TEAMID.bundle.id"], AppAttestEnvironment::Production);
        let (attestation, key_id, csr) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Development.aaguid(),
            None,
            None,
        );
        let level = verify(
            &config,
            None,
            Some(&DeviceAttestation::AppleAppAttest {
                key_id,
                attestation,
            }),
            &csr,
            &[],
        )
        .expect("a valid object answers a level");
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    fn no_app_ids_proves_nothing() {
        let root = ca("apple root", None);
        let config = Config::new(issuer()).with_apple_root(root.cert.clone());
        let (attestation, key_id, csr) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        let level = verify(
            &config,
            None,
            Some(&DeviceAttestation::AppleAppAttest {
                key_id,
                attestation,
            }),
            &csr,
            &[],
        )
        .expect("a valid object answers a level");
        assert_eq!(level, AttestationLevel::Unproven);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one broken object per refusal reason, each asserted on its own"
    )]
    fn a_broken_app_attestation_is_a_refusal() {
        let (config, root) = apple_setup(&["TEAMID.bundle.id"], AppAttestEnvironment::Production);
        let object = |counter: u32| {
            apple(
                &root,
                "TEAMID.bundle.id",
                counter,
                AppAttestEnvironment::Production.aaguid(),
                None,
                None,
            )
        };
        // A nonce over a different request is not for this request.
        let (attestation, key_id, _) = object(0);
        let other_csr = csr(&KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("other key"));
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id,
                    attestation
                }),
                &other_csr,
                &[]
            )
            .is_err(),
            "a nonce of a different request"
        );
        // A key id that is not the credential's.
        let (attestation, _, req) = object(0);
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id: vec![3u8; 32],
                    attestation
                }),
                &req,
                &[]
            )
            .is_err(),
            "a different key id"
        );
        // A key that already asserted.
        let (attestation, key_id, req) = object(1);
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id,
                    attestation
                }),
                &req,
                &[]
            )
            .is_err(),
            "a non-zero counter"
        );
        // A chain that does not reach the configured root.
        let foreign = ca("a different apple root", None);
        let (attestation, key_id, req) = apple(
            &foreign,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id,
                    attestation
                }),
                &req,
                &[]
            )
            .is_err(),
            "a chain off a different root"
        );
        // Garbage and a wrong `fmt`.
        let (_, key_id, req) = object(0);
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id: key_id.clone(),
                    attestation: b"not cbor".to_vec()
                }),
                &req,
                &[]
            )
            .is_err(),
            "garbage"
        );
        let wrong_fmt = ciborium::Value::Map(vec![(
            ciborium::Value::Text("fmt".to_owned()),
            ciborium::Value::Text("other".to_owned()),
        )]);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&wrong_fmt, &mut cbor).expect("cbor");
        let (_, key_id, req) = object(0);
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id,
                    attestation: cbor
                }),
                &req,
                &[]
            )
            .is_err(),
            "a wrong fmt"
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one broken object per refusal reason, each asserted on its own"
    )]
    fn a_mangled_app_attestation_object_is_a_refusal() {
        let (config, root) = apple_setup(&["TEAMID.bundle.id"], AppAttestEnvironment::Production);
        let (valid, key_id, req) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        let (x5c, auth_data) = parts(&valid);
        let certs = certificates(&x5c);
        assert_eq!(certs.len(), 2, "the fixture's x5c carries two certificates");
        let (cred, intermediate) = (certs[0].clone(), certs[1].clone());
        let fmt = ciborium::Value::Text("apple-appattest".to_owned());
        let refuse = |name: &str, attestation: Vec<u8>| {
            assert!(
                verify(
                    &config,
                    None,
                    Some(&DeviceAttestation::AppleAppAttest {
                        key_id: key_id.clone(),
                        attestation
                    }),
                    &req,
                    &[]
                )
                .is_err(),
                "{name}"
            );
        };
        // A `fmt` that is not a text.
        refuse(
            "a fmt that is not a text",
            encode(&object(
                ciborium::Value::Integer(ciborium::value::Integer::from(1u64)),
                Some(x5c.clone()),
                Some(auth_data.clone()),
            )),
        );
        // No `attStmt` at all.
        refuse(
            "no attStmt",
            encode(&ciborium::Value::Map(vec![(
                ciborium::Value::Text("fmt".to_owned()),
                fmt.clone(),
            )])),
        );
        // No `x5c`.
        refuse(
            "no x5c",
            encode(&object(fmt.clone(), None, Some(auth_data.clone()))),
        );
        // No `authData`.
        refuse(
            "no authData",
            encode(&object(fmt.clone(), Some(x5c.clone()), None)),
        );
        // A credential certificate that does not parse.
        refuse(
            "an unparseable credential certificate",
            encode(&object(
                fmt.clone(),
                Some(ciborium::Value::Array(vec![
                    ciborium::Value::Bytes(b"not a certificate".to_vec()),
                    ciborium::Value::Bytes(intermediate.clone()),
                ])),
                Some(auth_data.clone()),
            )),
        );
        // An empty `x5c`.
        refuse(
            "an empty x5c",
            encode(&object(
                fmt.clone(),
                Some(ciborium::Value::Array(Vec::new())),
                Some(auth_data.clone()),
            )),
        );
        // An intermediate the next certificate did not sign.
        let foreign = ca("a different apple root", None);
        refuse(
            "an intermediate the next certificate did not sign",
            encode(&object(
                fmt,
                Some(ciborium::Value::Array(vec![
                    ciborium::Value::Bytes(cred),
                    ciborium::Value::Bytes(intermediate),
                    ciborium::Value::Bytes(foreign.cert),
                ])),
                Some(auth_data),
            )),
        );
        // A configured Apple root that does not parse.
        let (valid, key_id, req) = apple(
            &root,
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            None,
        );
        let config = Config::new(issuer()).with_apple_root(b"not a root".to_vec());
        assert!(
            verify(
                &config,
                None,
                Some(&DeviceAttestation::AppleAppAttest {
                    key_id,
                    attestation: valid
                }),
                &req,
                &[]
            )
            .is_err(),
            "a root that does not parse"
        );
    }

    #[test]
    fn a_mismatched_app_attest_auth_data_is_a_refusal() {
        let (config, root) = apple_setup(&["TEAMID.bundle.id"], AppAttestEnvironment::Production);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("credential key");
        let key_id = super::sha256(key.public_key_raw());
        let refuse = |name: &str, attestation: Vec<u8>, key_id: Vec<u8>, csr: Vec<u8>| {
            assert!(
                verify(
                    &config,
                    None,
                    Some(&DeviceAttestation::AppleAppAttest {
                        key_id,
                        attestation
                    }),
                    &csr,
                    &[]
                )
                .is_err(),
                "{name}"
            );
        };
        // An `authData` too short to carry its fields.
        let (attestation, attested_key_id, csr) =
            apple_auth_data(&root, vec![7u8; 100], &key, key_id.clone());
        refuse(
            "an authData too short to carry its fields",
            attestation,
            attested_key_id,
            csr,
        );
        // A credential id that is not the key's hash.
        let (attestation, attested_key_id, csr) = apple_auth_data(
            &root,
            auth_data(
                "TEAMID.bundle.id",
                0,
                AppAttestEnvironment::Production.aaguid(),
                Some(vec![3u8; 32]),
                &key,
            ),
            &key,
            key_id.clone(),
        );
        refuse(
            "a credential id that is not the key's hash",
            attestation,
            attested_key_id,
            csr,
        );

        // A credential id length the layout does not carry.
        let mut auth = auth_data(
            "TEAMID.bundle.id",
            0,
            AppAttestEnvironment::Production.aaguid(),
            None,
            &key,
        );
        auth[52..54].copy_from_slice(&16u16.to_be_bytes());
        let (attestation, attested_key_id, csr) =
            apple_auth_data(&root, auth, &key, key_id.clone());
        refuse(
            "a credential id length the layout does not carry",
            attestation,
            attested_key_id,
            csr,
        );
        // An `aaguid` no environment claims.
        let (attestation, attested_key_id, csr) = apple_auth_data(
            &root,
            auth_data("TEAMID.bundle.id", 0, [7u8; 16], None, &key),
            &key,
            key_id,
        );
        refuse(
            "an aaguid no environment claims",
            attestation,
            attested_key_id,
            csr,
        );
    }

    /// The header map one refresh-period case answers with.
    fn with_cache_control(value: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            value.parse().expect("a cache-control value"),
        );
        headers
    }

    /// The refresh period one status list source answers, fifteen minutes.
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "the larger-unit `Duration` constructors are not yet stable"
    )]
    const REFRESH_PERIOD: Duration = Duration::from_secs(900);
    /// The period Google's live header answers, one day.
    #[expect(
        clippy::duration_suboptimal_units,
        reason = "the larger-unit `Duration` constructors are not yet stable"
    )]
    const ONE_DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn the_refresh_period_reads_max_age_from_cache_control() {
        assert_eq!(
            super::max_age(&with_cache_control("max-age=900")),
            REFRESH_PERIOD
        );
        assert_eq!(
            super::max_age(&with_cache_control("public, max-age=86400")),
            ONE_DAY,
            "Google's live header"
        );
        assert_eq!(
            super::max_age(&with_cache_control("public,max-age=120")),
            Duration::from_secs(120),
            "a max-age after other directives"
        );
        assert_eq!(
            super::max_age(&with_cache_control("no-store")),
            super::REFRESH_DEFAULT,
            "directives without a max-age take the default"
        );
        assert_eq!(
            super::max_age(&with_cache_control("max-age=soon")),
            super::REFRESH_DEFAULT,
            "an unparsable age takes the default"
        );
        assert_eq!(
            super::max_age(&reqwest::header::HeaderMap::new()),
            super::REFRESH_DEFAULT,
            "no header takes the default"
        );
        assert_eq!(
            super::max_age(&with_cache_control("max-age=0")),
            super::REFRESH_FLOOR,
            "a zero age takes the floor"
        );
        assert_eq!(
            super::max_age(&with_cache_control("public, max-age=10")),
            super::REFRESH_FLOOR,
            "an age under the floor takes the floor"
        );
    }

    /// The answer one status list source case serves.
    async fn source_answer(
        axum::extract::State(body): axum::extract::State<
            std::sync::Arc<parking_lot::Mutex<Option<String>>>,
        >,
    ) -> axum::response::Response {
        match body.lock().clone() {
            Some(body) => axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header(axum::http::header::CACHE_CONTROL, "max-age=900")
                .body(axum::body::Body::from(body))
                .expect("a response"),
            None => axum::response::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("not a status list"))
                .expect("a response"),
        }
    }

    /// A local source for the status list, its good body swappable to a
    /// failure.
    struct Source {
        url: String,
        body: std::sync::Arc<parking_lot::Mutex<Option<String>>>,
        #[expect(
            dead_code,
            reason = "the handle is never read, and it is dropped last, keeping the source serving"
        )]
        serve: tokio::task::JoinHandle<()>,
    }

    /// The source on a local socket serving `body`, revoked serial `65`.
    async fn status_source(body: String) -> Source {
        let store = std::sync::Arc::new(parking_lot::Mutex::new(Some(body)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!(
            "http://{}/status",
            listener.local_addr().expect("an address")
        );
        let router = axum::Router::new()
            .route("/status", axum::routing::get(source_answer))
            .with_state(store.clone());
        let serve = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });
        Source {
            url,
            body: store,
            serve,
        }
    }

    const REVOKED: &str = r#"{"entries": {"65": {"status": "REVOKED"}}}"#;

    #[tokio::test]
    async fn a_fetched_status_list_answers_its_revoked_serials() {
        let source = status_source(REVOKED.to_owned()).await;
        let list = StatusList::new(AndroidStatus::Url(source.url));
        assert_eq!(
            list.fetch().await,
            REFRESH_PERIOD,
            "the next refresh waits the response's max-age"
        );
        assert_eq!(
            list.serial(&[0x65]),
            SerialCheck::Bad(SerialStatus::Revoked)
        );
        assert_eq!(list.serial(&[0x66]), SerialCheck::Clean);
    }

    #[tokio::test]
    async fn a_failed_refetch_keeps_the_last_good_copy() {
        let source = status_source(REVOKED.to_owned()).await;
        let list = StatusList::new(AndroidStatus::Url(source.url));
        assert_eq!(list.fetch().await, REFRESH_PERIOD);
        *source.body.lock() = None;
        assert_eq!(
            list.fetch().await,
            REFRESH_PERIOD,
            "a failed refetch keeps the last period"
        );
        assert_eq!(
            list.serial(&[0x65]),
            SerialCheck::Bad(SerialStatus::Revoked),
            "the last good copy still answers"
        );
        assert_eq!(list.serial(&[0x66]), SerialCheck::Clean);
    }

    #[test]
    fn a_missing_status_file_answers_no_copy() {
        let dir = tempfile::tempdir().expect("a directory");
        let list = StatusList::new(AndroidStatus::File(dir.path().join("status.json")));
        assert_eq!(list.serial(&[0x65]), SerialCheck::NoCopy);
    }

    #[test]
    fn a_local_status_file_answers_its_serials() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("status.json");
        std::fs::write(&path, REVOKED).expect("write the status file");
        let list = StatusList::new(AndroidStatus::File(path));
        assert_eq!(
            list.serial(&[0x65]),
            SerialCheck::Bad(SerialStatus::Revoked),
            "the file loads at construction, no fetch in flight"
        );
        assert_eq!(list.serial(&[0x66]), SerialCheck::Clean);
    }

    #[tokio::test]
    async fn the_spawned_fetcher_refetches_the_source_at_startup() {
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("status.json");
        std::fs::write(&path, REVOKED).expect("write the status file");
        let list = StatusList::new(AndroidStatus::File(path.clone()));
        assert_eq!(
            list.serial(&[0x65]),
            SerialCheck::Bad(SerialStatus::Revoked)
        );
        // The deployment's list revokes a different serial.
        std::fs::write(&path, r#"{"entries": {"66": {"status": "REVOKED"}}}"#)
            .expect("rewrite the status file");
        let handle = list.spawn();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if list.serial(&[0x66]) == SerialCheck::Bad(SerialStatus::Revoked) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the fetcher never refetched the source"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
    }
}
