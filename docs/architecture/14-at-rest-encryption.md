# 14: At-rest encryption

**Status**: normative. The encryption subsystem (phases E0 through E5) is shipped and its tests run in CI. Every normative statement below is marked **Built**, **Built, defective**, or **Decided (EN)** where EN names an E-phase in `docs/handoff-auth-at-rest-encryption.md`.

---

## What is encrypted

**Built.** Every durable replica on a device is ciphertext. The local tier that attaches to a replica shares its key and is ciphertext too. The refresh credential is stored separately and is also protected, though by a different key and by a different mechanism depending on the target.

| Store | Native | Browser |
|---|---|---|
| Replica | SQLCipher file, per-replica key | sqlite3mc file in OPFS, per-replica key |
| Local (never-syncing) tier | ATTACHed, inherits replica key | Separate connection, same per-replica key passed explicitly |
| Refresh token | OS keyring (`keyring` crate, no SQLite involved) | OPFS SQLite database encrypted under the device key |

The refresh store's device key is distinct from per-replica keys and is covered in the Key custody section below.

---

## The key

**Built.** `connetto_core::ReplicaKey` in `crates/connetto-core/src/replica_key.rs` is the shared value type: 32 raw bytes, lowercase hex on the wire, zeroized on drop (`zeroize::Zeroize`), and both `Debug` and `Display` redacted so the material cannot reach a log through a derived formatter.

The device mints the key, on first sight of a replica it is about to create. No key material crosses the wire and the server never holds any. Two devices for the same identity mint different keys and neither can read the other's file.

The consequence is stated in the module doc comment of `crates/connetto-core/src/replica_key.rs` and is worth repeating here: losing the cached key loses the replica. Synced tables recover by re-syncing from the server. Device-local tables do not recover at all.

The key survives logout deliberately. It is scoped per device rather than per session so a returning user resumes the replica instead of re-syncing, and is destroyed only by an explicit data wipe.

---

## Key custody

### Shared trait (native)

**Built.** `connetto_client::auth::ReplicaKeyStore` in `crates/connetto-client/src/auth.rs` is the native trait:

| Method | Purpose |
|---|---|
| `load(&self, name: &str)` | Return the cached key for `name`, or `None` |
| `store(&self, name: &str, key: &ReplicaKey)` | Persist `key` under `name` |
| `clear(&self, name: &str)` | Remove the record, which crypto-shreds the replica |

`name` is the same value `replica_db_name` produced for the replica file, so two identities on one device hold separate records and a wipe of one cannot reach the other.

The concrete implementation shipped for production is `connetto_client::auth::KeyringKeyStore` in `crates/connetto-client/src/auth.rs`, which uses OS secure storage: Keychain on macOS, Credential Manager on Windows, and the kernel keyutils keyring on Linux. On Linux the key lives in the session keyring. That keyring survives logout but not a reboot, so a rebooted Linux device reports `ClientError::ReplicaKeyMissing` and recovers by wiping and re-syncing.

The test implementation is `connetto_client::auth::MemoryKeyStore`, an in-memory `HashMap`.

### Browser key store

**Built.** `connetto_web::auth::ReplicaKeyStore` in `crates/connetto-web/src/auth.rs` wraps an `IndexedDB` database named `connetto-key-store`. It has two object stores:

| Store | Contents |
|---|---|
| `kek` | One non-extractable AES-GCM-256 key-encryption key (KEK), stored as a structured-cloneable `CryptoKey` |
| `wrapped` | Per-identity records, each keyed by the replica name, each holding a 12-byte AES-GCM IV followed by the AES-GCM ciphertext of the raw replica key |

The KEK is generated once per browser profile, marked non-extractable, and never exported. Script-level reads of the `wrapped` store yield opaque ciphertext because the KEK bytes are unreachable by script. The methods are `load`, `save`, and `clear` (named `save` rather than `store`, unlike the native trait).

The scope of protection is documented on the type: this defends against script-level exfiltration and an off-device copy of the `IndexedDB` contents. It does not defend against a resident attacker who can call `load` directly, and does not necessarily defend against an attacker holding the full browser profile directory, which includes both the IDB files and the backing storage for non-extractable keys.

### The gate on locally stored secrets

**Decided, and partly pending measurement.** Every locally stored secret sits behind a user-verification gate. Opening the app presents a fingerprint, a face check or a device passcode once, and both the replica and the stored refresh token become readable. This is the pattern a banking application uses, and it is worth being precise about what it is not: the server verifies nothing, sees nothing, and is not involved. The gate protects secrets at rest on the device. Session lifetime, revocation and the identity provider's authority are governed entirely by `11-authentication.md` and are untouched by it.

**Both secrets are covered, not one.** Gating either alone leaves a route to the same data, because whoever can use the refresh token can open a session and pull the data down again, and whoever can open the replica already has it. In the browser this costs nothing extra: the two are already wrapped by a single key-encryption key, since the refresh store's device key is itself a record in `ReplicaKeyStore`. On native they are independent keychain items and are gated separately.

**One unlock lasts as long as the process. Decided.** The derived key is held in memory while the application runs and a fresh start prompts again. No inactivity timeout and no per-operation prompt: the operating system's own screen lock is the right control for an unattended machine, and connetto has no notion of a sensitive operation to hang a second prompt on.

**Browser mechanism: a key derived from a passkey, replacing the stored one.** WebAuthn's `prf` extension derives 32 bytes from a credential given an input, the same bytes every time, and the specification forces user verification for it, overriding the request's own preference if necessary. So the gate arrives as a property of the mechanism rather than as separate work. The derived value goes through HKDF with a per-purpose label rather than being used as a key directly.

The input is **one fixed value, not per identity**, producing one key-encryption key that unwraps per-identity records. R23 originally proposed a per-identity input, which cannot work: the refresh store must open before any identity is known, so no identity-derived key could unwrap it. Nothing is lost, because per-identity keys exist for erasing one account without touching another, which the existing per-identity wrapped records already provide.

Storage becomes:

| Store | Contents |
|---|---|
| `wrapped` | keyed by (replica name, credential id), each holding an IV and the encrypted replica key |
| `credentials` | enrolled credential identifiers, in the clear, since they are not secret and are needed to scope the assertion |

The `kek` store disappears, because the key-encryption key is no longer stored anywhere. Keying `wrapped` by credential as well as replica costs nothing and avoids a stored-record migration if more than one holder is ever wanted. **Only one row is written**: multiple holders are rejected, because every copy lives in the same store and is lost together, so they protect only against losing an authenticator that sits on a different device from the replica, and only for a user who enrolled a backup in advance.

**A topology constraint, settled by the specification rather than by choice.** `PublicKeyCredential` is `[SecureContext, Exposed = Window]`, so it cannot be called from a worker, while connetto's database and its keys live in a dedicated worker per `09-wasm.md`. The assertion therefore happens in a tab and the key crosses into the worker.

**What crosses is a key object, not bytes. Decided.** Web Crypto defines serialization for `CryptoKey` and states that "applications may share a `CryptoKey` object across security boundaries, such as origins, through the use of the structured clone algorithm and APIs such as `postMessage`". So the page imports the derived bytes immediately with `extractable: false` and posts the resulting key object, keeping no reference of its own. The specification's guarantee is that "key material is not exposed to script, except through the use of the `exportKey` and `wrapKey` operations", which a non-extractable key forbids.

**The residual exposure, stated rather than softened.** The raw bytes exist in page script between the assertion resolving and the import, because the extension returns a buffer and there is no path from a PRF result directly to a key object. That window is irreducible. Script already resident at that instant obtains exportable material and therefore permanent, portable access to the local data. Script arriving after it finds a key it can ask the browser to use while the page lives, but cannot export, persist, or take off the device.

**No claim is made that the bytes are erased**, because the platform does not support one: "conforming user agents are not required to zeroize key material, and it may still be accessible on device storage or device memory, even after all references to the `CryptoKey` have gone away", and the material may be "persisted to disk, possibly unencrypted". The handoff is also final, since "once a key is shared with a destination origin, the source origin can not later restrict or revoke access to the key".

No published guidance for this combination was found. MDN documents the extension and `importKey` separately and says nothing about pairing them, and the community device-support material has no PRF content at all, so this is assembled from the two specifications rather than adopted from anyone.

**Native mechanism: an access-control attribute on the keychain item.** `keyring` cannot express this. Verified across versions: 3.6.3 which connetto pins, 4.1.6 which is current, and `keyring-core` 1.0.0 all have no access-control surface, and the Apple backends store secrets with a plain password call. One layer below, `security-framework-sys` already in the tree defines biometry-any, biometry-current-set, device passcode and their combinators. Apple items are stored with biometry-any combined with device passcode: biometry-any rather than biometry-current-set because the latter invalidates when the user changes their enrolled fingerprints, and the passcode combination gives a fallback without a second stored copy.

**The capability is added upstream rather than reached around. Decided.** Version 4 split the library into `keyring-core` plus per-platform store crates, so access control lands in the Apple store alone, which is the only platform that has it. That removes the objection to upstreaming, which was that an interface would have to express a capability most of its platforms lack. The project is active, outside contributions merge within days, and no such request exists yet, so this is a new proposal rather than a queue to join.

**Windows is in scope and is not symmetric with Apple.** Credential Manager has no user-verification attribute at all, so the gate cannot be a flag on the existing storage. Windows Hello sits behind a separate interface, reachable from Rust through the `windows` crate under its `Security_Credentials` features, and it offers two things that are easy to confuse. A consent check prompts and returns a result to the calling process, which is worth nothing against an attacker holding the files, for exactly the reason a PIN is worth nothing: our code never runs for them. A platform-held key gated by Hello is genuinely hardware-backed, but it signs rather than encrypts, so seeding a key from it depends on the signature being deterministic for a fixed challenge. **Pending**: whether it is. If not, Windows has no native gate and falls in with the unsupported surfaces.

**Declining is not a separate path. Decided.** The gate is offered, never forced, since the ceremony requires an explicit user gesture and user verification and dismissing it is always available. A user who declines lands on exactly the rung described below for platforms that cannot support it: a stored key, no user verification, and the application told so it can warn. No additional mechanism exists for this case because none is needed.

The reason the reporting surface carries must nonetheless distinguish the two, because only one is fixable. A platform that cannot do it is final. A user who declined can be offered it again, so an application can say so and enrol later, re-wrapping the replica key under the derived key at that point. That is the only place a re-wrap arises, and it is an ordinary operation rather than a migration, since nothing is deployed and there are no existing replicas to carry forward.

**Not uniform across platforms, and this is stated rather than smoothed over.** Apple has it. Android Keystore has it but `keyring` has no Android backend at all, and the third-party crates that provide one are unvetted. Windows Credential Manager has no such attribute, so gating there needs a different interface entirely. Linux Secret Service does define per-item locking, but it is a keyring-password prompt rather than a biometric one and `keyring` unlocks items transparently anyway, while `linux-keyutils`, which connetto actually uses, has no concept of it.

**Where no gate is possible, there is no gate, and the chapter says so. Decided.** Permanently unsupported surfaces get today's behaviour: a key stored locally with no user verification, which defends against script-level exfiltration and an off-device copy of the storage alone, and not against someone holding the whole profile. A PIN was considered and rejected. The threat is an offline, parallel attack on a copied profile, and a six-digit PIN is under twenty bits, which no key-derivation function rescues. WebAuthn's own PIN is meaningful only because the authenticator counts failed attempts in hardware and locks the credential, and that enforcement is the security rather than the digits. A PIN checked in our own code has none, because the attacker never runs our code. A passphrase with real entropy would work and is not offered, because the permanently affected population is small and a forgotten-passphrase path is its own design.

**Who that is, measured rather than guessed.** About 2.3% of tracked global usage is on browsers that will never support this, dominated by UC Browser at 0.62%, Firefox for Android at 0.37% and Android Browser at 0.14%, plus Android WebView, which has no WebAuthn at all and appears in no browser-share figure because nobody chooses it. A further 7.9% is version lag on browsers that do support it, mostly Chrome and Safari on iOS, and resolves as people upgrade. This holds only if a synced software passkey satisfies the extension, which is the probe's central question.

**The protection level is reported to the application, not merely documented. Decided.** A user cannot be expected to infer from their browser choice whether their local data is protected, so connetto exposes which custody applies to the open replica: derived from a user-verified credential, stored without verification, or no durable key at all because the replica is in memory. It carries a reason as well as a level, so an application can say why rather than only that. It is a property of the connection alongside the existing event stream, not a new channel, and it exists so an interface can warn plainly when protection is absent. Reporting a level connetto does not actually provide would be worse than reporting nothing, so this is a real surface rather than a label.

**Pending measurement.** Whether a real authenticator returns the derived bytes is not documented by any vendor and is not in the community device-support data. `docs/webauthn-prf-probe-spec.md` specifies what must be measured. Two things wait on it: how the native capability is reached, and whether the population above is right, because a synced passkey that declines the extension would make the unsupported case the common one and reopen the fallback decision entirely.

### Provisioning

**Built.** `provision_replica_key` is defined in two places, one per target, with the same provision-once semantics: a cached key always wins and is never overwritten, so a second login cannot silently re-key a replica and strand its contents. Only when nothing is cached is a fresh key minted from the device RNG and written through.

- Native: `connetto_client::auth::provision_replica_key(store: &dyn ReplicaKeyStore, name: &str)` in `crates/connetto-client/src/auth.rs`
- Browser: `connetto_web::auth::provision_replica_key(store: &ReplicaKeyStore, name: &str)` in `crates/connetto-web/src/auth.rs`

Call `provision_replica_key` only for a replica that does not yet exist. For one already on disk, call `ReplicaKeyStore::load` and pass the result to `Replica::encrypted_file`. Minting for an existing replica returns a key that decrypts nothing.

### The device key (browser only)

**Built.** The browser `RefreshStore` must be readable before any identity is known, because the identity is what the refresh token resolves to. A per-replica key cannot be used here because the replica name is derived from the identity. `connetto_web::storage::device_key` in `crates/connetto-web/src/storage.rs` provisions a separate record in the `ReplicaKeyStore` under the literal constant `"connetto-device-key"`, which a derived name can never collide with. The device key wraps the `RefreshStore`'s SQLite pages with the same AES-256-CBC codec the replica uses.

---

## The page codec

**Built.** connetto does not implement encryption. It states at each connect whether the database holds encrypted pages and hands the key to an off-the-shelf codec.

Natively the codec is SQLCipher, vendored by `libsqlite3-sys` under `bundled-sqlcipher`. In the browser it is SQLite3 Multiple Ciphers, vendored by `sqlite-wasm-rs` under `sqlite3mc`. The two are not the same codebase, which forces an explicit pin.

**The construction on both sides is SQLCipher version 4.** AES-256-CBC per page, with a fresh 16-byte random IV generated on every single page write, plus a 64-byte HMAC-SHA512 over the ciphertext, the IV, and the page number. Both live in 80 reserved bytes at the end of every page that SQLite itself accounts for through its page-reserve field. Page 1 carries a 16-byte random per-database salt in the clear. Rewriting a page in place never reuses an IV.

The key is supplied as 32 raw bytes through the `x'...'` form of `PRAGMA key`, documented in `crates/connetto-client/src/cipher.rs`, skipping the passphrase KDF because the key is already uniformly random.

**The pin is required in the browser.** SQLite3 Multiple Ciphers defaults to ChaCha20-Poly1305, not to the SQLCipher construction. Naming `sqlcipher` as the cipher is not enough: its own `sqlcipher` scheme defaults to a non-legacy variant that places different data in the first bytes of page 1 and cannot read a real SQLCipher file. The two pragmas that establish byte-for-byte compatibility are captured in `connetto_client::cipher::CIPHER_PRAGMAS` in `crates/connetto-client/src/cipher.rs`:

```
PRAGMA cipher = 'sqlcipher'; PRAGMA legacy = 4;
```

Phase E0 verified the pinning by having the browser codec read a file the native codec wrote, and confirmed that without `legacy = 4` it cannot. The native codec is SQLCipher itself and needs no pinning, so `cipher::unlock` applies these only on wasm.

**Decided (R21): the native side moves to SQLite3 Multiple Ciphers too**, so both backends run one codec on one SQLite version and the pin stops being load-bearing. The two-codebase arrangement is compatible today only because the pin forces agreement, which means correctness rests on a setting that nothing obliges a future version bump to preserve. If the two ever drift, a file written on one device stops opening on another, and the failure appears at a user's device rather than in a test. Phase E0 established that the switch works and recorded why the alternative, staying on `bundled-sqlcipher`, does not remove the split.

The browser codec intercepts as a VFS shim, so a database must be opened through a URI that names the codec layer. `connetto_client::cipher::cipher_url` in `crates/connetto-client/src/cipher.rs` composes `file:<name>?vfs=multipleciphers-<vfs>` over the installed VFS (`opfs-sahpool` for OPFS, `memvfs` for the in-memory fallback). Both backends are covered, so the OPFS-unavailable fallback stays encrypted rather than silently degrading.

---

## Ordering constraints

**Built.** `cipher::unlock` in `crates/connetto-client/src/cipher.rs` must be the first statement run against a connection. Anything that reads the database header, `PRAGMA journal_mode=WAL` included, fails on an encrypted file before the key is set. Diesel's `establish` only registers SQL functions and never reads the schema, so immediately after `establish` is both safe and the last safe moment. The code in `crates/connetto-client/src/lib.rs` (`connect_inner`) applies the unlock before `PRAGMA journal_mode=WAL` and that ordering is load-bearing.

**Built.** An attached database inherits the connection's derived key, not a key the `ATTACH` statement names. This was measured rather than assumed (see the comment in `crates/connetto-client/src/lib.rs` on `attach_local_tier_ddl`, and the tests in `crates/connetto-client/tests/encrypted_replica.rs`). Two consequences:

A local tier must be first-booted through the replica connection (via `attach_local_tier_ddl`) so both databases share the same key salt. A tier file created by any other connection carries its own salt and will fail to decrypt through the replica connection. Subsequent `attach_local_tier` calls work because the salt already matches from the first boot.

`PRAGMA key` in raw hex form cannot re-key an attached database to a different key. Only a passphrase form re-derives from the attached file's own salt, and the per-replica key is raw bytes, not a passphrase.

**Browser constraint (Built).** `sqlite-wasm-rs` allows one connection per database and the sahpool VFS keys its bookkeeping by name, so two live connections to one OPFS file trip a `debug_assert`. The browser local tier is therefore a separate connection carrying the same key explicitly rather than being attached.

---

## How a replica is named

**Built.** `connetto_client::replica::replica_db_name(prefix: &str, user_id: &Id)` in `crates/connetto-client/src/replica.rs` derives the replica filename before any transport opens. The derivation runs a SHA-256 over the identity's own serde encoding and encodes the first 128 bits as hex, producing `{prefix}-{32 hex chars}`. The derivation is deterministic: the same identity always selects the same file, and distinct identities produce distinct files.

The derivation deliberately does not go through `Display` or any textual representation of the identity. Serde encoding is the canonical byte source, and the result is fixed-length, filesystem-safe, and does not spell the user id in a directory listing.

Deriving the name before connecting is what makes resuming under the wrong identity unrepresentable rather than detected after the fact: an identity mismatch opens a different file and cannot adopt the wrong replica's rows or pending mutations.

The unauthenticated name (for a deployment with no authentication) is the bare prefix, which no derived name can collide with.

---

## Teardown

**Built.** Teardown is two orthogonal axes. connetto ships mechanisms and the application decides policy.

**Credential teardown**: `NativeAuthenticator::logout` in `crates/connetto-client/src/auth.rs` revokes the session server-side and clears the stored refresh token. In the browser, `BrowserAuthenticator::logout` in `crates/connetto-web/src/auth.rs` does the same, then `connetto_web::storage::clear_device_key` crypto-shreds the `RefreshStore` by destroying the device key.

**Data teardown**: `connetto_client::teardown::wipe_replica` in `crates/connetto-client/src/teardown.rs` destroys the replica's key-store record and then deletes the replica file and its WAL and SHM sidecars. The key goes first: if the delete then fails, what remains is inert ciphertext, and the wipe's promise still holds. The reverse order would leave a readable file whenever the delete failed. The browser mirror is `connetto_web::storage::wipe_replica` in `crates/connetto-web/src/storage.rs`.

Every destructive primitive blocks on unsynced writes unless `force` is set. That guard is meaningful at exactly one moment, logout, when the user's credential still works and queued writes could still be uploaded. `purge_replica` in `crates/connetto-client/src/teardown.rs` deletes the file without destroying the key and also carries the same guard.

`forget_device` in `crates/connetto-client/src/teardown.rs` runs both destructive axes under one guard and exists for the ordering guarantee: the unsynced check runs before the credential is destroyed, because once the refresh token is gone the queued writes can no longer be uploaded and the check would be protecting nothing. A revoke that never reached the server does not abort the data wipe.

**A purge that clears the key is unrecoverable.** A `wipe_replica` call destroys the key before the file. If the file delete then fails, `ReplicaUndecryptable` is reported on the next connect. The recovery is `purge_replica` with `force`, which deletes the now-unreadable file so the next connect can first-boot a fresh one. There is no unsynced guard on that recovery: the pending mutations lived inside the file the key will not open, so they are already lost.

**Browser wipe timing (Built).** The browser's replica connection lives inside the relay hub's pump for the worker's whole lifetime. A wipe cannot run while the connection is live, so it is deferred: `connetto_web::storage::mark_wipe_pending` in `crates/connetto-web/src/storage.rs` records the request in a separate `IndexedDB` database named `connetto-pending-wipes`, and `boot_db_worker` drains pending wipes at the very start of each boot before any connection opens. The unsynced guard lives at the marking step, not the boot step, because at boot the replica is closed and pending mutations are unreadable.

---

## Threat model boundary

Chapter 12 section "What at-rest encryption does not cover" in `docs/architecture/12-identity-session-capability.md` is the canonical statement and this chapter does not repeat it. The short version:

The replica filename is `prefix-sha256(canonical(user_id))` truncated to 128 bits, unsalted and deterministic across devices. Anyone with live filesystem access can confirm whether a suspected account used a device by hashing a guessed id and testing for the file. Encryption under a device-stored key does not defend against this attacker, who reads the key too. Hiding which identities used a device requires a user-supplied secret the device never stores, and nothing in the current design aims there.

**What it defends, without overclaiming.**

**Crypto-shredding on logout is the primary job and it works.** Deleting a database file does not erase its contents: the write-ahead log, the journal, free pages, wear-levelling, filesystem snapshots and every backup already taken keep readable copies. Destroying the 32-byte key invalidates all of them at once, including copies nobody controls any more. That is what makes logging out mean something on a device the deployment does not own afterwards, and there is no cheaper mechanism for it.

**Copies of the file that leave the device.** Backups are the case that matters most and the one full-disk encryption does not reach, because a backup is decrypted before it is uploaded. A recovered disk or a discarded drive is the same class.

**Not a stolen powered-off device, in practice.** Current iOS, Android, macOS and Windows encrypt the whole disk by default, so the marginal protection over the platform is small and claiming it here would overstate the mechanism.

**Not separation between accounts on one device**, per the threat model in chapter 12: several accounts belong to one person, and separation between different people is the operating system's user boundary.

**Not an attacker already resident in the process**, who can drive the open connection and read decrypted pages regardless of how they were stored.

**The stolen-profile case is what the gate exists to close, and the claim is still not made until it is measured.** As built today the ciphertext in OPFS and the key-encryption key in IndexedDB live in the same browser profile directory, so an attacker holding the profile plausibly holds both, and whether the browser protects IndexedDB contents with an operating-system secret has never been established. The gate above changes the shape rather than merely improving it: a key derived from a passkey is not in the profile at all, so a copied profile is insufficient by construction rather than by degree. That is the property to demonstrate, and `docs/webauthn-prf-probe-spec.md` asks for it directly by clearing site data and re-deriving. Until that report exists this chapter makes no stolen-profile claim for the browser. Where the gate is unavailable the old position stands unchanged, and what those users get is itself pending. Crypto-shredding is unaffected throughout, because it destroys the key wherever the key lived.

---

## No open decisions

Everything this chapter covers is built and decided. The anonymous-access and adoption work in phase E6 introduces no new encryption decisions: decision 1 of that set (the unauthenticated replica is encrypted under a device-scoped key) was built in E5 and the `boot_db_worker` path that provisions it is already in place.

---

## Where the handoff contradicted the source

One function name in this document's raw material was wrong. Earlier drafts of `docs/handoff-auth-at-rest-encryption.md` called the key provisioning function `resolve_replica_key` and described a `wire` parameter carrying a server-provisioned key. Neither that name nor that parameter exists in the shipped code: the function is `provision_replica_key` in both `crates/connetto-client/src/auth.rs` and `crates/connetto-web/src/auth.rs`, and it takes no wire key. Phase E3 moved key minting to the device and removed the wire field from `TokenPair`, `TokenResponse`, and `IssuedAuthCode`, as the handoff itself records.

One acceptance criterion in the handoff was retired rather than met: phase E2 listed "the baked-template first boot works on an encrypted replica" as a done criterion. It was resolved by retiring the requirement: `sqlcipher_export` exists in the SQLCipher amalgamation and not in the sqlite3mc amalgamation, so no plaintext-to-encrypted transform works on both backends, and the baked-template path was removed in E5. The variant `Replica::PlaintextFile` and the constructor `connect_with_plaintext_template` do not exist in the shipped code.
