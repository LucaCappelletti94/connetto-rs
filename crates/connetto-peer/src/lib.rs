//! The mutual TLS link between certified devices.
//!
//! A [`Node`] presents one device's certificate and key and dials or accepts
//! other certified devices over TLS 1.3, verifying every chain against the
//! roots the deployment ships, the attestation levels the device accepts,
//! and the revocation lists it keeps.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod error;
mod event;
mod frame;
mod identity;
mod link;
mod node;
mod signer;
mod verify;

#[cfg(feature = "discovery")]
mod discovery;
#[cfg(feature = "discovery")]
mod fingerprint;
#[cfg(feature = "discovery")]
mod policy;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "discovery"))]
mod discovery_proofs;

pub use error::{CloseReason, LinkError, Refusal, TrustError};
pub use event::PeerEvent;
pub use frame::PeerFrame;
pub use identity::{Clock, Identity, SystemClock, Trust};
pub use node::{Liveness, Node, SocketPrep};

#[cfg(feature = "discovery")]
pub use discovery::{Discovery, DiscoveryEvent};
#[cfg(feature = "discovery")]
pub use fingerprint::Fingerprint;
