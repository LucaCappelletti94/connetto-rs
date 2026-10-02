# 14: At-rest encryption

**Status**: normative. The encryption subsystem (phases E0 through E5) is shipped and its tests run in CI. Every normative statement below is marked **Built**, **Built, defective**, or **Decided**, naming either an E-phase from `docs/handoff-auth-at-rest-encryption.md` or an R-phase from `plans/master-implementation-plan.md`.

---

## What is encrypted

**Built.** Every durable replica on a device is ciphertext. The local tier that attaches to a replica shares its key and is ciphertext too. Natively the refresh credential is stored separately in the OS keyring. In the browser it is an `HttpOnly` cookie the browser keeps, outside every store this chapter protects (`11-authentication.md`, **Decided (R90, 2026-09-22)**).

| Store | Native | Browser |
|---|---|---|
| Replica | SQLCipher file, per-replica key | sqlite3mc file in OPFS, per-replica key |
| Local (never-syncing) tier | ATTACHed, inherits replica key | Separate connection, same per-replica key passed explicitly |
| Refresh token | OS keyring (`keyring` crate, no SQLite involved) | none, an `HttpOnly` cookie the browser keeps (R90) |
| Account index and last-used marker | OS keyring index record | plain OPFS SQLite database, never secret (R90) |

The browser's account index is plain by design, since an account key is an identifier and not a secret. A file an earlier build left under its name reads as not a database, and the boot discards it and asks for a login, while any other failure to open it propagates rather than costing the remembered accounts (**Decided (R90, 2026-09-23)**).

---

## The key

**Built.** `connetto_core::ReplicaKey` in `crates/connetto-core/src/replica_key.rs` is the shared value type: 32 raw bytes, lowercase hex on the wire, zeroized on drop (`zeroize::Zeroize`), and both `Debug` and `Display` redacted so the material cannot reach a log through a derived formatter.

The device mints the key, on first sight of a replica it is about to create. No key material crosses the wire and the server never holds any. Two devices for the same identity mint different keys and neither can read the other's file.

The consequence is stated in the module doc comment of `crates/connetto-core/src/replica_key.rs` and is worth repeating here: losing the cached key loses the replica. Synced tables recover by re-syncing from the server. Device-local tables do not recover at all.

The key survives logout deliberately. It is scoped per device rather than per session so a returning user resumes the replica instead of re-syncing, and is destroyed only by an explicit data wipe.

**Decided (2026-09-14, before R69), built 2026-09-14: an anonymous boot touches no key record.** A replica key exists to open a durable file, and an anonymous boot has none: its replica is in memory under the bare prefix, its tier is in memory, and its content store is worker-lifetime memory. The browser worker therefore provisions or loads a key only when the boot is identified. The anonymous content store still runs behind the encrypting decorator, because the archive is built over it on every platform, and its root key is minted for that worker and never stored, since encrypting memory the worker also holds the key for buys nothing and a constant would only look like a key. Until this decision the worker minted and stored a record under the bare prefix on every anonymous boot, which nothing could ever remove because a wipe is requested by an authenticated logout, so an anonymous boot now clears that record if it finds one, an idempotent read and delete that leaves no deployment carrying the leftover.

---

## Key custody

### One trait per secret

**Built (R41), 2026-08-07.** Each of the two secrets has one trait in `connetto-core`, implemented by every native and browser store, and every method names the account it addresses. Nothing is called `ReplicaKeyStore` in two crates any more, so a citation of that symbol is unambiguous. R90 deletes the browser's `RefreshTokenStore` implementation, the browser holding no refresh credential at rest once the token moves to an `HttpOnly` cookie (`11-authentication.md`, **Decided (R90, 2026-09-22)**), so that trait stands for the native targets.

| Secret | Trait | Native | Browser |
|---|---|---|---|
| refresh token | `connetto_core::traits::RefreshTokenStore`, awaiting through boxed futures | `KeyringStore`, `MemoryRefreshStore` | none after R90, the credential is an `HttpOnly` cookie (`11-authentication.md`) |
| replica keys | `connetto_core::traits::ReplicaKeyStore`, awaiting | `KeyringKeyStore`, `MemoryKeyStore` | `IdbKeyStore` |

Each trait carries an associated `Error`, following `connetto_core::traits::Transport::Error`, so neither target's error type had to move and no shared error was invented.

**Why the account is an argument rather than a field on the store.** One store instance serves every account on both targets, so the account is data the caller supplies rather than identity the constructor bakes. `KeyringStore` in `crates/connetto-client/src/auth.rs` used to carry `(service, user)` and now carries the service alone, composing its entry the way `KeyringKeyStore` beside it always did. The R41 form also served the browser's per-account refresh rows and the `connetto-device-key` record, and R90 deletes both (**Decided (R90, 2026-09-22)**), leaving the parameter standing on the native shape alone. Which account a caller attempts on boot is read from the last-used marker (`connetto_web::auth::remembered_account` in the browser, `connetto_client::auth::remembered_account` on native), from an explicit switch target when the user picks an account, or is `None` on a first run, which goes straight to an interactive login.

**Why both stores await.** The browser reaches `IndexedDB` and `SubtleCrypto` through promises that have no synchronous form in a worker, and the Linux desktop reaches the Secret Service only over D-Bus, where a synchronous call would hold a runtime worker for the round trip and for an unlock dialog (R71 decision 15). The key store's futures carry `MaybeSend` exactly as `Transport`'s do. The refresh-token trait returns boxed `Send` futures instead, so the native authenticator can hold it as `dyn RefreshTokenStore`. The Apple, Windows and Android stores still answer from a call that returns immediately.

What the seam buys over the rename is one caller. `crates/connetto-client/tests/secret_stores.rs` and `crates/connetto-web/tests/secret_stores.rs` run the same two exercises from `connetto_core::test_support`, written against the traits alone, against the native and the browser stores. R90 retargets the browser half to the key store, its refresh exercise retiring with the store.

### The key store

**Built.**

| Method | Purpose |
|---|---|
| `load(&self, name: &str)` | Return the cached key for `name`, or `None` |
| `store(&self, name: &str, key: &ReplicaKey)` | Persist `key` under `name` |
| `clear(&self, name: &str)` | Remove the record, which crypto-shreds the replica |

`name` is the same value `replica_db_name` produced for the replica file, so two identities on one device hold separate records and a wipe of one cannot reach the other. A literal name is equally valid.

The concrete implementation shipped for production on native is `connetto_client::auth::KeyringKeyStore` in `crates/connetto-client/src/auth.rs`, which uses OS secure storage: Keychain on Apple platforms, the Keystore on Android, Credential Manager under Windows Hello on Windows, and on Linux the store below.

**Built (R71, decided 2026-09-22 and 2026-09-28).** Every durable Linux secret, the replica key, the refresh token and R74's device key, survives a reboot. A desktop session keeps them as base64 text in the Secret Service's default collection, which connetto unlocks or creates through the desktop's own dialog under a bound, as libsecret does. A Flatpak or Snap application keeps them in libsecret's sandbox keyring file, opened with the Secret portal's per-application secret. A headless host keeps them in files under a state directory, sealed under a wrap key the operator supplies as the `connetto.wrap-key` systemd credential, or, in a container without systemd, as a key file the application names. A rotated wrap key reseals every record once from the previous key. On KDE, `ksecretd` writes a wallet to disk 5 s after a change and not when it is stopped, so a secret stored in the 5 s before a logout or a reboot is lost and reads back empty. With none of these reachable the client refuses with a typed error unless the application explicitly chooses keyutils and accepts losing its keys at reboot, which `KeyringStore::backend` and `KeyringKeyStore::backend` then report, together with which store holds the keys and whether the previous wrap key is still needed.

The test implementation is `connetto_client::auth::MemoryKeyStore`, an in-memory `HashMap`.

### The refresh store

**Built (R42).** `connetto_core::traits::RefreshTokenStore` carries four methods.

| Method | Purpose |
|---|---|
| `load(&self, account: &str)` | Return the stored token for `account`, or `None` |
| `store(&self, account: &str, token: &str)` | Persist `token` under `account` |
| `clear(&self, account: &str)` | Remove the record for `account` |
| `accounts(&self)` | Return every account the store holds a token for, excluding connetto's own reserved records |

The account key is `connetto_client::encode_identity(&user_id)`, the serde JSON encoding of the deployment's user id type. For a `String` id `"alice"`, the key is the seven-character string `"alice"` including the quotes. `connetto_client::decode_identity` reverses it.

**Deleted by R90 (decided 2026-09-22).** The browser answered `accounts()` from the rows of the `connetto_refresh` SQLite table directly, the same table the tokens lived in. Its account index and last-used marker survive as plain records in an unencrypted store, since neither was ever a secret.

**The native store** cannot ask the OS keyring: `keyring` 3.6.3 exposes no enumeration surface on any of its three backends, verified in its source. The native implementation therefore maintains its own index record in the keyring alongside the token entries. An out-of-band keychain edit can leave that index stale. A stale entry that names an account whose token has since been removed falls through to an interactive login rather than selecting a wrong identity.

**The last-used marker. Built (R42).** After a successful login, both authenticators write `connetto_client::IDENTITY_RECORD` (the literal `"connetto-device-identity"`) with that same account key as its value, natively beside the credential and, after R90, in the browser as a plain record with no credential write beside it. The marker therefore points at a row: reading it with `remembered_account` yields the same string that addresses the account's row, and natively the token. A boot with no marker stored returns `None` and the authenticator goes straight to an interactive login.

### Browser key store

**Built.** `connetto_web::auth::IdbKeyStore` in `crates/connetto-web/src/auth.rs` wraps an `IndexedDB` database named `connetto-key-store`. It has two object stores:

| Store | Contents |
|---|---|
| `kek` | One non-extractable AES-GCM-256 key-encryption key (KEK), stored as a structured-cloneable `CryptoKey` |
| `wrapped` | Per-identity records, each keyed by the replica name, each holding a 12-byte AES-GCM IV followed by the AES-GCM ciphertext of the raw replica key |

The KEK is generated once per browser profile, marked non-extractable, and never exported. Script-level reads of the `wrapped` store yield opaque ciphertext because the KEK bytes are unreachable by script.

The scope of protection is documented on the type: this defends against script-level exfiltration and an off-device copy of the `IndexedDB` contents. It does not defend against a resident attacker who can call `load` directly, and does not necessarily defend against an attacker holding the full browser profile directory, which includes both the IDB files and the backing storage for non-extractable keys.

### The gate on locally stored secrets

**Built (R23) for the browser, and by R51 (Apple), R52 (Android) and R53 (Windows) natively.** Every locally stored secret sits behind a user-verification gate. Opening the app presents a fingerprint, a face check or a device passcode once, and on native both the replica and the stored refresh token become readable, while in the browser the replica becomes readable and nothing else can: R90 moved the browser's refresh credential into an `HttpOnly` cookie that needs no gate because it is not browser storage at all (**Decided (R90, 2026-09-22)**). This is the pattern a banking application uses, and it is worth being precise about what it is not: the server verifies nothing, sees nothing, and is not involved. The gate protects secrets at rest on the device. Session lifetime, revocation and the identity provider's authority are governed entirely by `11-authentication.md` and are untouched by it.

**Native covers both secrets, the browser one. Amended (R90, 2026-09-22).** Gating either native secret alone leaves a route to the same data, because whoever can use the refresh token can open a session and pull the data down again, and whoever can open the replica already has it. The two are independent keychain items and are gated separately. In the browser the second secret no longer exists client-side, its former wrapper having been a record in `IdbKeyStore`, so the gate covers the replica key alone.

**One unlock lasts as long as the process. Decided.** The derived key is held in memory while the application runs and a fresh start prompts again. No inactivity timeout and no per-operation prompt: the operating system's own screen lock is the right control for an unattended machine, and connetto has no notion of a sensitive operation to hang a second prompt on.

**An application may ask again after time away. Built (R94, 2026-09-28).** `Gate` carries one re-check grace, set on the durable stage of either client builder. Absent, a launch unlocks once as above, which stays the floor. Set, the gate asks again when the application returns after being away longer than the grace, and zero means every return. The full event-by-situation table is [The gate's states](#the-gates-states) below, and its rows are the tests in `crates/connetto-client/tests/it/gate_recheck.rs`, `crates/connetto-client/src/keyring/gate.rs` and `examples/wasm-smoke/tests/gate.rs`.

The client has one away input, `ConnettoClient::away` and `ConnettoClient::back`, each taking a `Moment`. `connetto-dioxus`'s `use_away_input` feeds it from tao's `Suspended` and `Resumed` on iOS and Android and from window focus on the desktop, the browser tabs report page visibility to the worker, which counts the application away when no tab is visible, and an application with neither calls the two methods itself. Time away is measured from the two moments and never with a timer, since a suspended iOS process runs none. It is the larger of a sleep-counting monotonic delta (`CLOCK_BOOTTIME` on Linux and Android, Darwin's `CLOCK_MONOTONIC` on Apple, `performance.now()` in the browser) and the wall-clock delta, so a phone asleep for an hour cannot read as minutes and a clock stepped back cannot shorten the time away. A clock stepped forward costs at most one extra prompt.

A re-check that fires pauses the application and keeps the session. The client refuses the application's reads, writes and new watches with `ClientError::Locked`, holds live-handle refreshes and emits `ClientEvent::Locked`, while the replica connection and sync keep running until one of them needs a secret the gate has locked. Approval emits `ClientEvent::Unlocked` and each held handle wakes once. A dismissal emits `ClientEvent::UnlockDismissed` and stays locked, and the next return or `ConnettoClient::unlock`, typically from a click, asks again. In the browser the prompt runs in the tab that spawned the worker, the only one holding the private port a non-extractable key may cross, and the worker's hub states the gate to every tab (`GateState`, `02-protocol.md`), so a tab attaching while locked starts locked.

**Browser mechanism: a key derived from a passkey, replacing the stored one.** WebAuthn's `prf` extension derives 32 bytes from a credential given an input, the same bytes every time, and the specification forces user verification for it, overriding the request's own preference if necessary. So the gate arrives as a property of the mechanism rather than as separate work. The derived value goes through HKDF with a per-purpose label rather than being used as a key directly.

The input is **one fixed value, not per identity**, producing one key-encryption key that unwraps per-identity records. R23's original argument for a fixed input was that the refresh store must open before any identity is known, and R90 deletes the store that needed it (**Decided (R90, 2026-09-22)**). The decision stands on the reason that outlives the store: erasing one account without touching another is the job per-identity keys actually have, the per-identity wrapped records already provide it, and one gesture on a shared profile must open every account's replica rather than the remembered one.

Storage becomes:

| Store | Contents |
|---|---|
| `kek` | the stored key-encryption key, held only while no credential is enrolled |
| `wrapped` | keyed by (replica name, credential id), each holding an IV and the encrypted replica key |
| `credentials` | enrolled credential identifiers, in the clear, since they are not secret and are needed to scope the assertion |

The `kek` store holds the key-encryption key exactly while nobody has enrolled. Enrolling re-wraps every `wrapped` record under the derived key and destroys the stored `kek` record. A profile snapshot taken before enrolment holds the stored key and therefore the replica key, which enrolment re-wraps but does not re-key, and deleting an `IndexedDB` record does not erase the bytes underneath. After R90 a first run holds no token in memory at all, the credential arriving in the `HttpOnly` cookie, and the deferred first-run dance is deleted with the refresh store (decided 2026-09-22). Keying `wrapped` by credential as well as replica costs nothing and avoids a stored-record migration if more than one holder is ever wanted. **Only one row is written**: multiple holders are rejected, because every copy lives in the same store and is lost together, so they protect only against losing an authenticator that sits on a different device from the replica, and only for a user who enrolled a backup in advance.

**A topology constraint, settled by the specification rather than by choice.** `PublicKeyCredential` is `[SecureContext, Exposed = Window]`, so it cannot be called from a worker, while connetto's database and its keys live in a dedicated worker per `09-wasm.md`. The assertion therefore happens in a tab and the key crosses into the worker.

**What crosses is a key object, not bytes. Decided.** Web Crypto defines serialization for `CryptoKey` and states that "applications may share a `CryptoKey` object across security boundaries, such as origins, through the use of the structured clone algorithm and APIs such as `postMessage`". So the page imports the derived bytes immediately with `extractable: false` and posts the resulting key object, keeping no reference of its own. The specification's guarantee is that "key material is not exposed to script, except through the use of the `exportKey` and `wrapKey` operations", which a non-extractable key forbids.

**The residual exposure, stated rather than softened.** The raw bytes exist in page script between the assertion resolving and the import, because the extension returns a buffer and there is no path from a PRF result directly to a key object. That window is irreducible. Script already resident at that instant obtains exportable material and therefore permanent, portable access to the local data. Script arriving after it finds a key it can ask the browser to use while the page lives, but cannot export, persist, or take off the device.

**No claim is made that the bytes are erased**, because the platform does not support one: "conforming user agents are not required to zeroize key material, and it may still be accessible on device storage or device memory, even after all references to the `CryptoKey` have gone away", and the material may be "persisted to disk, possibly unencrypted". The handoff is also final, since "once a key is shared with a destination origin, the source origin can not later restrict or revoke access to the key".

No published guidance for this combination was found. MDN documents the extension and `importKey` separately and says nothing about pairing them, and the community device-support material has no PRF content at all, so this is assembled from the two specifications rather than adopted from anyone.

**Native mechanisms. Built (R51, R52).** Only the two secrets are gated, the refresh tokens and the replica keys. The account index, the last-used identity and a pending login stay readable before any prompt, since they are not secret and the account choice reads them first. On Apple the secrets live in the data protection keychain through `apple-native-keyring-store`'s protected store, each carrying `RequireUserPresence`, measured equivalent to biometry-any combined with the device passcode on all three points (probe N3), including surviving a fingerprint-set change. The store is configured `shared-authentication`, so one `LAContext` evaluated at the first gated read serves every gated item for the life of the process (probe I5 on an iPhone), and the gate's lock resets it. That option (`apple-native-keyring-store` #26) and the typed context it rides on (`security-framework` #263 and #264) are built against pinned fork revisions until released. On Android the secrets live in a named store of `android-native-keyring-store` configured `user-auth-required` with a timeout of zero, which stays locked until the app approves the store's `Cipher` in a `BiometricPrompt` allowing a strong biometric or the device credential, and locks again on the gate's lock. The prompt is the application's, through `KeystorePrompt`, since the crate is pure JNI, and `connetto-auth-session` hosts one. The store options (#28, the unlock-once and expiry-refusal steps, and #27's lost-key report) are built against one pinned integration revision until released. Either way a launch shows one prompt, at the first gated access, and a gated durable build arms its gate open when that access already verified the user. A first sign-in only creates the secrets and verifies nothing, so its connect asks once and returns only after the approval, resetting the platform context first because iOS lets the context that created an item read it back without a sheet. A dismissed launch prompt fails the connect. Items written before a gate existed are not migrated.

**Windows, built by R53 (2026-10-02).** The secrets live in `windows-native-keyring-store`'s `HelloStore`, pinned to the revision that carries it, and the reserved records stay in the ordinary Credential Manager store. The store derives its sealing key from a Windows Hello passkey's PRF output through native WebAuthn API 9, the same primitive the browser gate uses, and seals each entry with AES-256-GCM. The first unlock enrolls with one approval, every later launch unlocks with one, and the key stays in memory until `lock`. The prompt needs a live owner window, which the application lends through `KeyringAuth::with_hello_owner`, and `connetto-dioxus`'s `use_hello_owner` lends the desktop window. Windows disables that window while the prompt is up, so the app cannot be closed under it. A build with no owner, or a machine without Windows Hello PRF, keeps the secrets ungated and reports `Unverified(Unsupported)`. A lost or corrupt Hello credential discards the store and reports the loss once, and the durable build then wipes the replica and signs in again, as on Android. `UserConsentVerifier` stays unused: a consent check our own code performs is worth nothing against an attacker holding the files.

**On by default wherever the platform supports it. Built (R94, 2026-09-28).** `Gate::default()` is on, and an application turns it off with `Gate::off()` on the durable stage of the client builder. The gate exists only on that stage, since an in-memory replica has nothing durable to protect, and a user can still dismiss the platform's prompt. In the browser the passkey unlock is therefore on unless the application says otherwise. Natively the keyring's own mechanism rides the same setting (R51, R52, R53), and `Gate::off()` writes the secrets without the platform's verification. A platform fixes an item's protection when it creates it, so the setting applies to secrets as they are written.

**The custody a client reports is derived. Built (R94, 2026-09-28).** The two secret-store traits each report the protection their items carry through `protection()`, and a builder-built client reports the weaker of the two stores' claims and what the build did, the build's reason winning a tie between two `Unverified` levels. No caller sets a level, since a settable level is the hazard `crates/connetto-core/src/custody.rs` warns about.

**Declining is not a separate path. Decided.** The gate is never forced on the user, since dismissing the platform's own prompt is always available. A user who declines lands on exactly the rung described below for platforms that cannot support it: a stored key, no user verification, and the application told so it can warn. No additional mechanism exists for this case because none is needed. One measured detail shapes the retry: Safari has required a user gesture for an assertion since Safari 14 and grants one gesture-free call per navigation, restored after each success and spent on a failure, while Chrome and Firefox do not gate a plain assertion. So a first attempt can be automatic everywhere and a retry after a dismissal needs a real click on Safari, which is why the unlock is a function a tab calls rather than something connetto initiates.

The reason the reporting surface carries must nonetheless distinguish the two, because only one is fixable. A platform that cannot do it is final. A user who declined can be offered it again, so an application can say so and enrol later, re-wrapping the replica key under the derived key at that point. That is the only place a re-wrap arises, and it is an ordinary operation.

**Not uniform across platforms, and this is stated rather than smoothed over.** Apple has it (R51). Android Keystore has it: `set_user_authentication_required(true)` gates correctly, measured (probe A6). `android-native-keyring-store` 1.0.0 creates its key with the flag off and offers no option, so R52 takes the store option from upstream that opens the store with one approval per launch. Android WebView has no WebAuthn at all (probe A5, measured on the physical device), so a WebView-hosted application's only gate is the native Keystore path. Windows Credential Manager has no user-verification attribute, so R53 seals the secrets under a Windows Hello PRF key. Linux Secret Service defines collection locking, but connetto unlocks the default collection through the desktop's keyring-password dialog (R71 decision 10), which is not a biometric gate, and keyutils has no concept of it.

**Android, built by R88 (2026-09-23), gated by R52.** The native client keeps the refresh token and the replica keys in `android-native-keyring-store`, whose Keystore-backed stores encrypt them in `SharedPreferences`, and the replica is SQLCipher over vendored OpenSSL. With a secure lock screen and a `KeystorePrompt` the secrets sit in the gated store and custody is `Verified`. A device with no secure lock screen cannot create a gated key, so the secrets stay in the ungated store and custody reports `Unverified(NoGate::Offerable)`, and a build with no prompt reports `Unverified(NoGate::Unsupported)`. Removing the screen lock deletes every gated key, and the store then reports the key lost rather than replacing it (#27), which a durable build answers by wiping the replica and starting a fresh one the server resyncs.

**iOS and macOS, built by R88 (2026-09-24), gated by R51.** The native client keeps the refresh token and the replica keys in the data protection keychain through `apple-native-keyring-store`'s protected store, and the replica is SQLCipher over CommonCrypto. The keychain answers only an app carrying the `keychain-access-groups` entitlement under a development or distribution profile, so the macOS demo ships as a provisioned `.app` too (`connetto-macos-app`). A macOS build without the entitlement keeps its secrets ungated in the login keychain and reports `Unverified(NoGate::Unsupported)`. Face ID is offered only with `NSFaceIDUsageDescription`, which the demo's `Dioxus.toml` writes. The simulator creates gated items without enforcing them, so the prompt itself is proven on a device.

**Where no gate is possible, there is no gate, and the chapter says so. Decided.** Permanently unsupported surfaces get today's behaviour: a key stored locally with no user verification, which defends against script-level exfiltration and an off-device copy of the storage alone, and not against someone holding the whole profile. A PIN was considered and rejected. The threat is an offline, parallel attack on a copied profile, and a six-digit PIN is under twenty bits, which no key-derivation function rescues. WebAuthn's own PIN is meaningful only because the authenticator counts failed attempts in hardware and locks the credential, and that enforcement is the security rather than the digits. A PIN checked in our own code has none, because the attacker never runs our code. A passphrase with real entropy would work and is not offered, because the permanently affected population is small and a forgotten-passphrase path is its own design.

**Who that is, measured.** Synced Google Password Manager passkeys carry the extension fully on both measured platforms (macOS Chrome and Android Chrome), both JavaScript and Rust legs, and iCloud Keychain is confirmed directly on Safari macOS and iOS 26. So the roughly 2.3 percent tail stands as the unsupported population: UC Browser at 0.62%, Firefox for Android at 0.37% and Android Browser at 0.14%, plus Android WebView which has no WebAuthn at all. A further 7.9% is version lag on browsers that do support it and resolves as people upgrade. The passphrase fallback stays closed.

**The protection level is reported to the application, not merely documented. Built (R23).** `connetto_core::custody::{Custody, NoGate}` carries three levels and three reasons. Read natively from `ConnettoConnection::custody`, and in the browser from `connetto_web::unlock::custody` in the worker or `connetto_web::workers::request_custody` from a tab. The browser answer does not come from a tab's own connection: a tab holds its own in-memory mirror, so that connection's honest answer is always no durable key, which would read as a warning about the real data.

**Measured 2026-08-19.** Sixteen rows in `webauth-spike` at `report/results.json`. Not measured, so silence is not a pass: Windows browsers, iPad, Chrome on iOS, hardware security keys, and Linux browser rows. On Android the emulator on hand cannot mint the configuration that carries the extension, so the physical device is that platform's only source of truth for the browser rows.

### The gate's states

**Decided (R94, 2026-09-28), native rows added by R51 and R52 (2026-09-30).** Each cell names what the client does and the situation it ends in. "Unchanged" means no event, no state change and no prompt.

| Situation | Replica | Custody reported | Reached by |
|---|---|---|---|
| anonymous | in memory, no key | `Ephemeral` | a builder that never called `.signed_in()`, or a signed-in builder that never chose a durable replica |
| signed in without a gate | durable, key stored ungated | `Unverified(Unsupported)` where the platform has no gate, `Unverified(Offerable)` where the application turned the gate off, the user has not enrolled, or the device has no passcode or secure lock screen, `Unverified(Declined)` after a declined browser enrolment | the durable replica step with the gate off, or on a platform or device that cannot gate |
| gated and open | durable, key opened through the gate | `Verified` | the gate's prompt approved |
| gated and locked | durable, key behind the gate | `Verified`, since only access is paused | a launch before approval, whether a browser boot or a native first sign-in that has verified nothing yet, or a re-check that fired |

The inputs. Went away and came back are moments, each a sleep-counting monotonic reading and a wall reading, and the client keeps at most one pending away moment. Time away is the larger of the two deltas, a negative one read as zero. The grace is `Gate`'s re-check setting. Absent means once per launch, zero means every return, and otherwise a return re-checks when time away exceeds it. The browser worker counts the application away when no tab of the origin is visible, and `connetto-dioxus` reports window focus on the desktop and tao's `Suspended` and `Resumed` on iOS and Android.

| Event | anonymous | signed in without a gate | gated and open | gated and locked |
|---|---|---|---|---|
| launch | open, no prompt, custody `Ephemeral` | open, no prompt | natively, the launch whose sign-in or key read already raised the platform's prompt starts here with no second one | ask the prompt once, and the native connect or the browser worker's boot waits on the answer, so the application never meets the lock at launch |
| went away | ignored | ignored | keep the away moment when a grace is set, replacing an older one | ignored, a pending prompt stays pending |
| came back | ignored | ignored | with no pending away moment, unchanged. With one, clear it and measure time away. Within the grace, unchanged. Beyond it, or with a zero grace, lock the mechanism, emit `Locked`, refuse application access, ask the prompt, and move to gated and locked | with no prompt pending, ask it again. With one pending, unchanged |
| prompt approved | a stray answer is dropped | late browser enrolment: adopt the derived key, custody `Verified`, move to gated and open | a stray answer is dropped | emit `Unlocked`, resume application access and held live-handle refreshes, move to gated and open |
| prompt dismissed | not reachable | a declined browser enrolment: custody `Unverified(Declined)` | not reachable | at launch the connect or the boot fails. After a re-check, emit `UnlockDismissed` and stay locked, and the next return or `ConnettoClient::unlock` asks again |
| clock stepped | nothing | nothing | a pending away moment is measured at return by the larger delta, so a step back cannot shorten time away and a step forward costs at most one extra prompt | nothing |
| gate off | nothing durable to gate | this situation | not reachable, the gate is fixed when the builder connects | not reachable |

A platform withdrawing the gate while the client runs, a deleted passkey or a removed screen lock, reaches the client as a prompt that fails, the "prompt dismissed" row. On Android the store then reports its key lost, and the next durable connect wipes the replica and starts a fresh one.

While locked, the application's reads and writes through the client, its new watches, pins and unpins are refused with `ClientError::Locked`. Live handles, row and aggregate alike, keep their last answer and wake once after `Unlocked`. The replica connection, the pump, inbound patches, reconnects and the upload of writes made before the lock keep running until one of them needs a locked secret, and then waits. The browser worker's hub states each lock to every tab (`GateState`), whose clients refuse and hold the same way, and after its handshake ack a tab also learns the worker's sync status and identity (`SyncStatus`, `TabIdentity`), so a tab attaching while locked starts locked. The browser's ceremony runs in the tab that spawned the worker, the only one holding the private port a non-extractable key may cross.

The native keyring keeps a state of its own per service, since the platform store is process-wide.

| Event | ungated (gate off, or the device cannot) | launch (gated, nothing approved yet) | open | locked (a re-check fired) |
|---|---|---|---|---|
| reserved record read or written | ungated access | ungated access, no prompt | ungated access | ungated access |
| first gated access | ungated access | Apple: a read raises the sheet, a create raises none. Android: the unlock ceremony runs first. Approval moves to open, a dismissal returns the refusal and stays here | not reachable | not reachable |
| gated read or write | ungated access | as above | no prompt, through the shared context or the unlocked store | refused with `ClientError::Locked` and no prompt, so a background token refresh never raises one |
| gated create refused for no passcode or secure lock | not reachable | fall back to ungated, custody `Unverified(Offerable)` | the same | refused with `Locked` |
| gated access refused for a missing entitlement | not reachable | fall back to ungated, on macOS in the login keychain, custody `Unverified(Unsupported)` | not reachable | not reachable |
| mechanism lock | nothing | move to locked (Apple resets the shared context, Android locks the store) | the same | unchanged |
| mechanism ask | approved at once | the prompt, read against a gated secret this process touched, approval moves to open | approved at once, no prompt | the prompt again, approval moves to open, a dismissal stays locked |
| delete, for logout or forgetting the device | proceeds | proceeds, a delete raises no prompt | proceeds | proceeds, no prompt |

### Provisioning

**Built.** `provision_replica_key` is defined in two places, one per target, with the same provision-once semantics: a cached key always wins and is never overwritten, so a second login cannot silently re-key a replica and strand its contents. Only when nothing is cached is a fresh key minted from the device RNG and written through.

- Native: `connetto_client::auth::provision_replica_key<S: ReplicaKeyStore>(store: &S, name: &str)` in `crates/connetto-client/src/auth.rs`
- Browser: `connetto_web::auth::provision_replica_key<S: ReplicaKeyStore>(store: &S, name: &str)` in `crates/connetto-web/src/auth.rs`

Both are generic over the shared trait and each awaits. They stay one per target rather than moving to `connetto-core` beside the trait, because minting needs an entropy source and `ReplicaKey` deliberately carries none, which is what keeps the browser build free of one.

Call `provision_replica_key` only for a replica that does not yet exist. For one already on disk, call `ReplicaKeyStore::load` and pass the result to `Replica::encrypted_file`. Minting for an existing replica returns a key that decrypts nothing.

### The device key (browser only)

**Deleted by R90 (decided 2026-09-22).** The device key existed to wrap the browser `RefreshStore`'s SQLite pages under a name no identity-derived replica name could address, because the identity is what the refresh token resolves to. With the refresh credential in an `HttpOnly` cookie the store is gone, and `connetto_web::storage::device_key` and `clear_device_key` go with it, leaving `IdbKeyStore` holding per-identity wrapped replica keys and nothing else.

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

**Decided (R21): the native side moves to SQLite3 Multiple Ciphers too**, so both backends run one codec on one SQLite version and the pin stops being load-bearing. The two-codebase arrangement is compatible today only because the pin forces agreement, which means correctness rests on a setting that nothing obliges a future version bump to preserve. If the two ever drift, a file written on one device stops opening on another, and the failure appears at a user's device rather than in a test. Phase E0 measured the browser codec reading a file the native codec wrote under the pin, and recorded why the alternative, staying on `bundled-sqlcipher`, does not remove the split. Native running SQLite3MC is unmeasured until R21's step 0.

**Decided (R21, 2026-09-22): the format becomes ChaCha20-Poly1305.** Both backends declare SQLite3MC's `chacha20` scheme explicitly rather than relying on its default, keyed with the same raw 32 bytes. Files in the SQLCipher v4 layout stop opening, a break accepted before any deployment exists, and a device-local tier crosses it only through export and import. The SQLCipher v4 construction above holds until R21 lands.

The browser codec intercepts as a VFS shim, so a database must be opened through a URI that names the codec layer. `connetto_client::cipher::cipher_url` in `crates/connetto-client/src/cipher.rs` composes `file:<name>?vfs=multipleciphers-<vfs>` over the installed VFS (`opfs-sahpool` for OPFS, `memvfs` for the in-memory fallback). Both backends are covered, so the OPFS-unavailable fallback stays encrypted rather than silently degrading.

---

## Ordering constraints

**Built.** `cipher::unlock` in `crates/connetto-client/src/cipher.rs` must be the first statement run against a connection. Anything that reads the database header, `PRAGMA journal_mode=WAL` included, fails on an encrypted file before the key is set. Diesel's `establish` only registers SQL functions and never reads the schema, so immediately after `establish` is both safe and the last safe moment. The code in `crates/connetto-client/src/lib.rs` (`connect_inner`) applies the unlock before `PRAGMA journal_mode=WAL` and that ordering is load-bearing.

**Built (R15).** One further pragma follows `PRAGMA journal_mode=WAL` and precedes the first `CREATE TABLE`, on the create path only: `PRAGMA auto_vacuum = INCREMENTAL`, issued through `SqliteConnection::set_auto_vacuum` in `open_inner`. The mode lives in the file and is fixed at the first table, so it is set when the schema is created and never on a reconnect to an existing replica. `docs/architecture/15-replica-retention.md` is authoritative for why the mode is `INCREMENTAL` and what the trimming pass does with it.

**Built (2026-09-16).** `PRAGMA case_sensitive_like = 1` follows the journal mode on every open, reconnects included. pg2sqlite leads every script it emits with that pragma, as part of declaring that its schema is Postgres's dialect, where `LIKE` is case sensitive. A pragma is connection state, so the copy inside the DDL covers only the first boot that runs the DDL, and `connect_existing` and `open_existing` run none. The tier script carries the same pragma, and `with_tier` passes a `PRAGMA` through unqualified while still requalifying every `CREATE TABLE` into the tier schema.

**Built.** An attached database inherits the connection's derived key, not a key the `ATTACH` statement names. This was measured rather than assumed (see `Replica::with_tier` in `crates/connetto-client/src/replica.rs` and the tests in `crates/connetto-client/tests/encrypted_replica.rs`). Two consequences:

A local tier must be first-booted through the replica connection, which is what `Replica::with_tier` asks for, so both databases share the same key salt. A tier file created by any other connection carries its own salt and will fail to decrypt through the replica connection. A later run says `with_existing_tier` and it works because the salt already matches from the first boot. **Built (R3):** the tier is named on the replica rather than attached afterwards, which is what makes a durable tier beside an unkeyed replica unrepresentable.

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

**Credential teardown**: `NativeAuthenticator::logout` in `crates/connetto-client/src/auth.rs` revokes the session server-side and clears the stored refresh token. In the browser, `BrowserAuthenticator::logout` in `crates/connetto-web/src/auth.rs` revokes the session through the account's cookie, and the server deletes that cookie in the same response. After R90 nothing durable is left to shred, so the local half clears the account's rows from the plain (unencrypted, never-secret) account record store (decided 2026-09-22). **Decided (2026-09-14, before R69), built 2026-09-14:** the native keyring store's account index is a record only while it lists an account, so clearing the last account removes the record rather than writing an empty list, and a store whose accounts are all gone leaves nothing in the OS keyring. An absent index already read as empty, so nothing else changes.

**Data teardown**: `connetto_client::teardown::wipe_replica` in `crates/connetto-client/src/teardown.rs` destroys the replica's key-store record and then deletes everything that key opens, the replica file with its WAL and SHM sidecars, the device-private tier with its own, and the content directory, in the order the table below gives. The key goes first: if a delete then fails, what remains is inert ciphertext, and the wipe's promise still holds. The reverse order would leave a readable file whenever the delete failed. The browser mirror is `connetto_web::storage::wipe_replica` in `crates/connetto-web/src/storage.rs`.

**Decided (2026-09-14, before R69), built 2026-09-14: every data teardown primitive removes everything the replica key opens, on both platforms, and every one of those things is named by derivation from the replica so the primitive needs no second parameter to find it.** The tier and the content store are ciphertext under the replica key, so a wipe that left either behind would leave bytes only a destroyed key can open, holding quota that no sweep can reclaim because the manifests naming the chunks went with the replica. The one exception is the browser content namespace, which is derived from the replica name and the deployment's seed and so cannot be recomputed by the primitive, and the pending-wipe record already carries the resolved value. What a wipe removes:

| Removed | Native `purge_replica`, and through it `wipe_replica` and `forget_device` | Browser `wipe_replica`, run by the next boot from the pending record |
|---|---|---|
| Key-store record | `wipe_replica` and `forget_device` only, `purge_replica` keeps it | Yes, the record named by the replica |
| Replica | `db_path` | The pool entry named by the replica |
| WAL and SHM | `db_path-wal`, `db_path-shm` | Not applicable, the VFS pool holds one entry |
| Device-private tier | `db_path-tier` with its own WAL and SHM, named by `with_tier(ddl)` on an encrypted file replica and by `with_existing_tier()`, no longer a caller-chosen path | `tier_db_name(replica)`, as built |
| Content | The directory `db_path-content`, named by `connetto_client::teardown::content_dir(db_path)`, where R69 builds its `FsStore` | The namespace the pending record carries, passed as `Option<&str>`, `None` for a deployment without content |

Order is key, tier, replica, content, on both platforms, for the reason the tier already has: a failure after the key is gone leaves inert ciphertext and a retry, never a readable store. Every removal treats absence as success, so a retry after a partial failure is the same call again. Native stops at the first failing delete and reports it, and the caller's retry is `purge_replica` with `force`, which starts the list over. `purge_replica` removes the content directory too, although it keeps the key, because a fresh replica has empty manifest tables and every chunk under the old directory is an orphan the sweep would otherwise delete one file at a time. The browser namespace is per account by construction, `sha256(seed, replica_db_name)`, so a wipe of one identity can never reach chunks of another identity signed in on the same device, and an anonymous boot opens no namespace and records none. Rejected: a content path parameter on `wipe_replica` and `forget_device`, which is two places that must hold the same value, the mistake the tier derivation exists to prevent, and leaving native content teardown to the application, which turns the chapter 18 sentence that crypto-shredding covers content exactly as it covers rows into a statement about shredding alone.

Every destructive primitive blocks on pending local work unless `force` is set. In the browser that guard combines unsynced mutation sequence numbers with the content upload outbox, because acknowledged rows can still have bytes waiting to upload. `purge_replica` in `crates/connetto-client/src/teardown.rs` deletes the file without destroying the key and carries the mutation guard.

`forget_device` in `crates/connetto-client/src/teardown.rs` runs both destructive axes under one guard and exists for the ordering guarantee: the unsynced check runs before the credential is destroyed, because once the refresh token is gone the queued writes can no longer be uploaded and the check would be protecting nothing. A revoke that never reached the server does not abort the data wipe.

**A purge that clears the key is unrecoverable.** A `wipe_replica` call destroys the key before the file. If the file delete then fails, `ReplicaUndecryptable` is reported on the next connect. The recovery is `purge_replica` with `force`, which deletes the now-unreadable file so the next connect can first-boot a fresh one. There is no unsynced guard on that recovery: the pending mutations lived inside the file the key will not open, so they are already lost.

**Browser wipe timing (Built, order amended 2026-09-14).** The browser's replica connection lives inside the relay hub's pump for the worker's whole lifetime. A wipe cannot run while the connection is live, so `connetto_web::storage::mark_wipe_pending` records the replica and its exact persistent content namespace in `connetto-pending-wipes`. The next worker `boot()` runs `wipe_replica` with that namespace, which destroys the key, the tier and the replica and then removes the namespace. Environmental browser-storage failure does not brick future boots: replica destruction proceeds and the marker atomically becomes content-only, so later boots retry the orphaned encrypted namespace without deleting a replacement replica. An invalid namespace remains fatal because selecting fallback storage for malformed identity is unsafe. The acknowledgment and content-only transition compare the whole observed record inside one read-write transaction, so neither can overwrite or clear a replacement request for the same replica. Legacy records without a namespace retain their earlier replica-only behavior. The memory fallback does not lose the namespace: it is recorded whenever the boot is identified, whatever store the boot ended up with, so a wipe requested during a session whose `OPFS` was refused still finds the directory an earlier session filled.

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

**The stolen-profile case is what the gate exists to close, and for an enrolled profile the claim is now made.** The gate changes the shape: a key derived from a passkey is not in the profile at all, so a copied profile is insufficient by construction rather than by degree. Q13 of the probe established this in the strongest form, byte-identical PRF output from Firefox and Safari on one machine with two separate browser profiles, so the credential and its secret live outside any single browser profile. For an unenrolled profile the stored key is still in the profile, and the claim does not extend there. Crypto-shredding is unaffected throughout, because it destroys the key wherever the key lived.

---

## No open decisions

Everything this chapter covers is decided. R41, the single seam for the two secret stores, landed on 2026-08-07. R42, the multi-account credential store with enumeration, landed on 2026-08-19. The browser gate is built (R23) and after R90 it covers the replica key alone, the browser's refresh token having moved to an `HttpOnly` cookie with the device key deleted (decided 2026-09-22). One item remains decided rather than built: R21, which moves the native side onto the browser's page codec. Linux custody that survives a reboot is built (R71). R51, R52 and R53 built the native gates for Apple, Android and Windows, and R94 carries the gate's default and its re-check setting. An unidentified run introduces no encryption decision at all: its local copy is SQLite's own `:memory:` and carries no key (chapter 12, **Built (R3)**), so nothing of it is at rest. (Corrected 2026-09-12: this paragraph used to say the unauthenticated replica is encrypted under a device-scoped key built in phase E5, a discarded series and a shape R3 replaced with in-memory.)

---

## Where the handoff contradicted the source

One function name in this document's raw material was wrong. Earlier drafts of `docs/handoff-auth-at-rest-encryption.md` called the key provisioning function `resolve_replica_key` and described a `wire` parameter carrying a server-provisioned key. Neither that name nor that parameter exists in the shipped code: the function is `provision_replica_key` in both `crates/connetto-client/src/auth.rs` and `crates/connetto-web/src/auth.rs`, and it takes no wire key. Phase E3 moved key minting to the device and removed the wire field from `TokenPair`, `TokenResponse`, and `IssuedAuthCode`, as the handoff itself records.

One acceptance criterion in the handoff was retired rather than met: phase E2 listed "the baked-template first boot works on an encrypted replica" as a done criterion. It was resolved by retiring the requirement: `sqlcipher_export` exists in the SQLCipher amalgamation and not in the sqlite3mc amalgamation, so no plaintext-to-encrypted transform works on both backends, and the baked-template path was removed in E5. The variant `Replica::PlaintextFile` and the constructor `connect_with_plaintext_template` do not exist in the shipped code.
