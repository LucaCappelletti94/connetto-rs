//! The Android permissions the connetto peer link asks for, the bundled
//! Kotlin module behind its hotspot and beacon, and btleplug's virtual machine
//! and Java for the Bluetooth central.
//!
//! See the crate's README for the two permissions the peer link needs and
//! where each of them is used.

#![doc = include_str!("../README.md")]

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub use android::{
    VmError, java_vm, request_peer_permissions, start_bluetooth_prompt,
    use_application_class_loader,
};
/// The jni btleplug links, whose virtual machine [`java_vm`] answers.
#[cfg(target_os = "android")]
pub use jni;

/// Ask the operating system for the permissions the peer link's discovery and
/// the hotspot need (R76), opening the prompt on the Activity when any is
/// missing. Run on the UI thread only.
///
/// Off Android the peer link's permissions do not exist, so the call does
/// nothing.
#[cfg(not(target_os = "android"))]
pub fn request_peer_permissions() {}
