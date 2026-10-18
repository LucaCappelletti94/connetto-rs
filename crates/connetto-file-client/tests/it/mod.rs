//! Integration tests for the native file client.
#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

mod archive;
mod builder_content;
mod held;
mod held_files;
mod negotiation;
mod offline_photo;
mod resolving;
mod retention;
mod staging;
mod store;
mod support;
mod transport;
