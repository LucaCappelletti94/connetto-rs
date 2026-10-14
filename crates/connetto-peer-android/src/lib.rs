//! The Android permissions the connetto peer link asks for, and the bundled
//! Kotlin module behind the local-only hotspot the peer link dials through.
//!
//! See the crate's README for the two permissions the peer link needs and
//! where each of them is used.

#![doc = include_str!("../README.md")]

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::request_peer_permissions;

/// Ask the operating system for the permissions the peer link's discovery and
/// the hotspot need (R76), opening the prompt on the Activity when any is
/// missing. Run on the UI thread only.
///
/// Off Android the peer link's permissions do not exist, so the call does
/// nothing.
#[cfg(not(target_os = "android"))]
pub fn request_peer_permissions() {}
