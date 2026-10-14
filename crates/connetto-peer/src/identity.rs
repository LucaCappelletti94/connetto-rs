//! The presented identity, the trust, and the wall clock.

use std::sync::Arc;
use std::time::SystemTime;

use connetto_core::device_cert::{AttestationLevel, DeviceKey};

/// The identity a node presents and dials with, the leaf and the issuer
/// certificate beside the key that signs for the leaf.
#[derive(Clone)]
pub struct Identity {
    /// The leaf certificate, DER.
    pub certificate: Vec<u8>,
    /// The issuer certificate, DER.
    pub issuer: Vec<u8>,
    /// The key that signs for the leaf.
    pub key: Arc<dyn DeviceKey>,
}

/// What a node trusts: the deployment roots and the attestation levels it
/// accepts from its peers.
#[derive(Debug, Clone)]
pub struct Trust {
    /// The root certificates, DER.
    pub roots: Vec<Vec<u8>>,
    /// The attestation levels the node accepts.
    pub accepted: Vec<AttestationLevel>,
}

/// The wall clock a verifier reads time from.
///
/// A test or a device shim implements this to stand the clock somewhere the
/// wall clock does not.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> SystemTime;
}

/// The system wall clock.
#[derive(Default, Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
