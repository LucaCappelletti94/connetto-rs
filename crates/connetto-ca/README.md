# connetto-ca

[![Tests](https://github.com/LucaCappelletti94/connetto-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/connetto-rs/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LucaCappelletti94/connetto-rs/blob/main/LICENSE)

The offline ceremonies of a connetto deployment's device certificate authority (R74). `init` creates the root, which names a fresh deployment UUID and whose key is stored encrypted under the operator's passphrase. `sign_issuer` signs the yearly issuer the server holds. `revoke_issuer` adds an issuer to the root's numbered list, which the server publishes beside its issuers' lists. The root never runs on the server, so this crate and its `connetto-ca` binary belong on the operator's offline machine.

```rust
use std::time::SystemTime;

let ca = tempfile::tempdir().unwrap();
let issuer = tempfile::tempdir().unwrap();
let deployment = connetto_ca::init(ca.path(), "correct horse", SystemTime::now()).unwrap();
connetto_ca::sign_issuer(ca.path(), "correct horse", issuer.path(), SystemTime::now()).unwrap();
assert!(issuer.path().join("issuer.der").exists());
assert!(!deployment.to_string().is_empty());
```
