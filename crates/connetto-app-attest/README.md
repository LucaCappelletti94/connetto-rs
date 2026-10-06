# connetto-app-attest

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)

Apple App Attest for connetto's device enrolment (R74 decision 35). `attest` asks Apple to vouch that a genuine copy of the app, signed under its App ID, made a request whose SHA-256 is the client data hash. It is the workspace's one crate allowed `unsafe` code.

`DCAppAttestService`'s instance methods lazily build a private controller on the shared service without a lock, so two concurrent first calls can release it under each other (objc2 #869). Every call here runs while one process-wide lock is held, from `isSupported` to the attestation's completion, so no two calls overlap. Other code in the same process that calls App Attest outside this crate is not covered by that lock and must not run while `attest` does.

On every target but iOS and iPadOS `attest` answers `Ok(None)`, and so does a Mac, since App Attest is unsupported on every Mac.

```rust
let hash = [0u8; 32];
if !cfg!(target_os = "ios") {
    assert_eq!(connetto_app_attest::attest(&hash), Ok(None));
}
```
