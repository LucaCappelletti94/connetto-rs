//! Integration tests for the native file client.
#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

mod archive;
mod negotiation;
mod offline_photo;
mod resolving;
mod retention;
mod staging;
mod store;
mod support;
