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

#[cfg(test)]
mod tests;

pub use error::{CloseReason, LinkError, Refusal};
pub use event::PeerEvent;
pub use frame::PeerFrame;
pub use identity::{Clock, Identity, SystemClock, Trust};
pub use node::{Liveness, Node};
