//! The user-verification gate over a platform's secret store (R51, R52).
//!
//! The platform store answers one secret at a time, and the gate decides for
//! each whether it is gated, whether it may prompt, and what custody the store
//! reports. The states and their events are `plans/design-r51-r52-native-gates.md`'s
//! keyring table. Only the two secrets are gated, refresh tokens and replica
//! keys, and the reserved records stay readable before any prompt.

use std::sync::Mutex;

use connetto_core::custody::{Custody, NoGate};

use crate::ClientError;
use crate::away::{GateAskOutcome, GateMechanism};
use crate::keyring::SecretStoreError;

/// Why the platform refused a secret operation, as far as the gate cares.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The user dismissed the platform's prompt.
    Dismissed,
    /// The device has no passcode or secure lock screen, so no gated item can
    /// be created.
    #[cfg_attr(
        all(target_os = "windows", not(test)),
        expect(
            dead_code,
            reason = "the Hello store reports a machine without Hello as unsupported"
        )
    )]
    NoDeviceLock,
    /// The build or the platform lacks what the gated store needs, such as an
    /// entitlement on Apple, a prompt or Android 11 on Android, or Windows Hello.
    Unsupported,
    /// Anything else the store reported.
    Other(ClientError),
}

impl From<Refusal> for ClientError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Dismissed => Self::SecretStore(SecretStoreError::PromptDismissed),
            Refusal::NoDeviceLock => Self::SecretStore(SecretStoreError::Backend(
                "the device has no passcode or secure lock screen".to_owned(),
            )),
            Refusal::Unsupported => Self::SecretStore(SecretStoreError::Backend(
                "this build or platform cannot gate its secrets".to_owned(),
            )),
            Refusal::Other(err) => err,
        }
    }
}

/// Where one secret goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Storage {
    /// Behind the platform's user verification.
    Gated,
    /// With no user verification, for the stated reason.
    Ungated(NoGate),
}

/// The ungated storage, whose reason the platform stores never read.
const PLAIN: Storage = Storage::Ungated(NoGate::Offerable);

/// One platform's secret store, as the gate drives it.
pub(crate) trait Backend: Send + Sync {
    /// The secret under `name`, `None` when none was stored.
    fn read(&self, service: &str, name: &str, storage: Storage) -> Result<Option<String>, Refusal>;
    /// Store `secret` under `name`, replacing any prior one.
    fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
        storage: Storage,
    ) -> Result<(), Refusal>;
    /// Remove the entry under `name` from `storage` without a prompt, succeeding
    /// where that storage cannot exist on this device.
    fn clear(&self, service: &str, name: &str, storage: Storage) -> Result<(), ClientError>;
    /// The gated copy of `name` read while the secrets are ungated, prompting
    /// only when a copy exists, and `None` when its key is gone.
    fn read_stranded(&self, service: &str, name: &str) -> Result<Option<String>, Refusal>;
    /// Run the platform's prompt so the gated secrets open without another,
    /// `probe` naming a gated secret the prompt may read to raise it.
    fn open(&self, service: &str, probe: Option<&str>) -> Result<(), Refusal>;
    /// Drop what the platform holds from the last approval, so gated secrets
    /// stay shut until the next [`open`](Self::open).
    fn close(&self, service: &str);
    /// Whether the first gated access must [`open`](Self::open) first, as an
    /// unlock-once store does, rather than prompting by itself.
    fn opens_explicitly(&self) -> bool;
}

/// Where the gate stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// No verification, for the stated reason.
    Ungated(NoGate),
    /// Gated, nothing approved yet this launch. The first gated access prompts.
    Launch,
    /// Gated and approved.
    Open,
    /// Gated and shut by a re-check. Gated access is refused without a prompt.
    Locked,
}

#[derive(Debug)]
struct State {
    mode: Mode,
    /// A gated secret this process has touched, which a later prompt reads.
    probe: Option<String>,
}

/// The gate over one service's secrets in one platform store.
pub(crate) struct SecretGate<B> {
    service: String,
    backend: B,
    state: Mutex<State>,
}

impl<B: Backend> SecretGate<B> {
    /// A gate that starts gated, or ungated when the application opted out.
    pub(crate) fn new(service: impl Into<String>, backend: B, gated: bool) -> Self {
        let mode = if gated {
            Mode::Launch
        } else {
            Mode::Ungated(NoGate::Offerable)
        };
        Self {
            service: service.into(),
            backend,
            state: Mutex::new(State { mode, probe: None }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The platform store behind the gate.
    #[cfg(any(target_os = "android", target_os = "windows"))]
    pub(crate) fn backend(&self) -> &B {
        &self.backend
    }

    /// Apply the application's gate setting. Off keeps the secrets ungated,
    /// on gates them again unless the platform cannot.
    pub(crate) fn configure(&self, gated: bool) {
        let mut state = self.state();
        state.mode = match (gated, state.mode) {
            (false, Mode::Launch | Mode::Open | Mode::Locked) => Mode::Ungated(NoGate::Offerable),
            (true, Mode::Ungated(NoGate::Offerable)) => Mode::Launch,
            (_, mode) => mode,
        };
    }

    /// The custody these secrets carry.
    pub(crate) fn protection(&self) -> Custody {
        match self.state().mode {
            Mode::Ungated(reason) => Custody::Unverified(reason),
            Mode::Launch | Mode::Open | Mode::Locked => Custody::Verified,
        }
    }

    /// Whether the platform verified the user this launch and nothing locked
    /// the secrets since.
    pub(crate) fn is_open(&self) -> bool {
        self.state().mode == Mode::Open
    }

    /// Whether the secrets are behind the platform's verification.
    pub(crate) fn is_gated(&self) -> bool {
        !matches!(self.state().mode, Mode::Ungated(_))
    }

    /// The storage a secret goes to, opening the store first when it must be
    /// opened explicitly and nothing is approved yet.
    fn gated_storage(&self) -> Result<Storage, ClientError> {
        let mode = self.state().mode;
        match mode {
            Mode::Ungated(reason) => Ok(Storage::Ungated(reason)),
            Mode::Locked => Err(ClientError::Locked),
            Mode::Open => Ok(Storage::Gated),
            Mode::Launch => {
                if self.backend.opens_explicitly() {
                    match self.backend.open(&self.service, None) {
                        Ok(()) => self.state().mode = Mode::Open,
                        Err(Refusal::Unsupported) => {
                            self.fall_back(NoGate::Unsupported);
                            return Ok(Storage::Ungated(NoGate::Unsupported));
                        }
                        Err(Refusal::NoDeviceLock) => {
                            self.fall_back(NoGate::Offerable);
                            return Ok(Storage::Ungated(NoGate::Offerable));
                        }
                        Err(refusal) => return Err(refusal.into()),
                    }
                }
                Ok(Storage::Gated)
            }
        }
    }

    /// The secret under `name`, moving a copy an earlier launch stored under the
    /// other storage to the one this launch uses.
    pub(crate) fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        if crate::is_reserved_record(name) {
            return Ok(self.backend.read(&self.service, name, PLAIN)?);
        }
        let storage = self.gated_storage()?;
        let read = match self.backend.read(&self.service, name, storage) {
            Err(Refusal::Unsupported) if storage == Storage::Gated => {
                self.fall_back(NoGate::Unsupported);
                return self.read(name);
            }
            read => read?,
        };
        if let Some(secret) = read {
            if storage == Storage::Gated {
                let mut state = self.state();
                state.probe = Some(name.to_owned());
                if state.mode == Mode::Launch {
                    state.mode = Mode::Open;
                }
            }
            return Ok(Some(secret));
        }
        // A move verifies nothing, so it leaves the mode as it found it.
        let stranded = match storage {
            Storage::Gated => self.backend.read(&self.service, name, PLAIN)?,
            Storage::Ungated(_) => self.backend.read_stranded(&self.service, name)?,
        };
        if let Some(secret) = &stranded {
            self.write(name, secret)?;
        }
        Ok(stranded)
    }

    /// Store `secret` under `name`, removing any copy under the other storage.
    pub(crate) fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        if crate::is_reserved_record(name) {
            return Ok(self.backend.write(&self.service, name, secret, PLAIN)?);
        }
        let storage = self.gated_storage()?;
        match self.backend.write(&self.service, name, secret, storage) {
            Ok(()) => {
                let other = if storage == Storage::Gated {
                    self.state().probe = Some(name.to_owned());
                    PLAIN
                } else {
                    Storage::Gated
                };
                self.backend.clear(&self.service, name, other)
            }
            Err(Refusal::NoDeviceLock) if storage == Storage::Gated => {
                self.fall_back(NoGate::Offerable);
                self.write(name, secret)
            }
            Err(Refusal::Unsupported) if storage == Storage::Gated => {
                self.fall_back(NoGate::Unsupported);
                self.write(name, secret)
            }
            Err(refusal) => Err(refusal.into()),
        }
    }

    /// Remove the entry under `name` from both storages, never prompting.
    pub(crate) fn clear(&self, name: &str) -> Result<(), ClientError> {
        self.backend.clear(&self.service, name, PLAIN)?;
        if !crate::is_reserved_record(name) {
            self.backend.clear(&self.service, name, Storage::Gated)?;
        }
        let mut state = self.state();
        if state.probe.as_deref() == Some(name) {
            state.probe = None;
        }
        Ok(())
    }

    fn fall_back(&self, reason: NoGate) {
        self.state().mode = Mode::Ungated(reason);
    }

    /// Shut the gated secrets until the next approval.
    pub(crate) fn lock(&self) {
        let mut state = self.state();
        if matches!(state.mode, Mode::Ungated(_)) {
            return;
        }
        state.mode = Mode::Locked;
        drop(state);
        self.backend.close(&self.service);
    }

    /// Ask the platform's prompt when the gated secrets are shut, blocking
    /// until it answers.
    pub(crate) fn ask(&self) -> GateAskOutcome {
        let (mode, probe) = {
            let state = self.state();
            (state.mode, state.probe.clone())
        };
        match mode {
            Mode::Ungated(_) | Mode::Open => GateAskOutcome::Approved,
            Mode::Launch | Mode::Locked => {
                if mode == Mode::Launch {
                    // iOS lets the context that created an item read it back unasked.
                    self.backend.close(&self.service);
                }
                self.open_through_prompt(probe.as_deref())
            }
        }
    }

    fn open_through_prompt(&self, probe: Option<&str>) -> GateAskOutcome {
        match self.backend.open(&self.service, probe) {
            Ok(()) => {
                self.state().mode = Mode::Open;
                GateAskOutcome::Approved
            }
            Err(refusal) => {
                tracing::warn!(?refusal, "the platform prompt did not open the secrets");
                GateAskOutcome::Dismissed
            }
        }
    }
}

/// The client gate's mechanism over one [`SecretGate`].
pub(crate) struct KeyringMechanism<B> {
    gate: std::sync::Arc<SecretGate<B>>,
}

impl<B> KeyringMechanism<B> {
    pub(crate) fn new(gate: std::sync::Arc<SecretGate<B>>) -> Self {
        Self { gate }
    }
}

impl<B: Backend + 'static> GateMechanism for KeyringMechanism<B> {
    fn lock(&self) {
        self.gate.lock();
    }

    fn is_open(&self) -> bool {
        self.gate.is_open()
    }

    fn ask(&self) -> crate::away::GateAskFuture {
        let gate = std::sync::Arc::clone(&self.gate);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || gate.ask())
                .await
                .unwrap_or(GateAskOutcome::Dismissed)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use connetto_core::custody::{Custody, NoGate};

    use super::{Backend, Refusal, SecretGate, Storage};
    use crate::ClientError;
    use crate::away::GateAskOutcome;

    /// What the fake platform does on its next prompt or gated access.
    #[derive(Clone, Copy, Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "each flag scripts one independent platform behaviour"
    )]
    struct Script {
        dismiss: bool,
        /// The refusal every gated create meets, and every gated read too for
        /// a missing entitlement.
        cannot: Option<Cannot>,
        explicit_open: bool,
        /// A gated create leaves the shared context able to read the item
        /// back unasked, as the iOS data protection keychain does.
        creation_authorises: bool,
        /// The key behind the gated copies is gone, as after a screen lock or
        /// Windows Hello was removed.
        key_gone: bool,
    }

    /// Why the fake platform cannot hold a gated item.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Cannot {
        DeviceLock,
        Gate,
    }

    /// A platform store recording every call, prompting only where the real
    /// one would.
    #[derive(Default)]
    struct Fake {
        script: Mutex<Script>,
        gated: Mutex<HashMap<String, String>>,
        plain: Mutex<HashMap<String, (String, NoGate)>>,
        prompts: Mutex<usize>,
        closes: Mutex<usize>,
        /// Whether the platform holds an approval, the shared context or the
        /// unlocked data key.
        approved: Mutex<bool>,
    }

    impl Fake {
        fn prompts(&self) -> usize {
            *self.prompts.lock().expect("lock")
        }

        /// Where the one copy of `name` is, failing on a copy in each storage.
        fn storage_of(&self, name: &str) -> Option<Storage> {
            let gated = self.gated.lock().expect("lock").contains_key(name);
            let plain = self
                .plain
                .lock()
                .expect("lock")
                .get(name)
                .map(|item| item.1);
            match (gated, plain) {
                (true, Some(_)) => panic!("{name} has a copy in both storages"),
                (true, None) => Some(Storage::Gated),
                (false, reason) => reason.map(Storage::Ungated),
            }
        }

        /// A copy an earlier launch stored.
        fn seed(&self, name: &str, secret: &str, storage: Storage) {
            match storage {
                Storage::Gated => {
                    self.gated
                        .lock()
                        .expect("lock")
                        .insert(name.to_owned(), secret.to_owned());
                }
                Storage::Ungated(reason) => {
                    self.plain
                        .lock()
                        .expect("lock")
                        .insert(name.to_owned(), (secret.to_owned(), reason));
                }
            }
        }

        fn prompt(&self) -> Result<(), Refusal> {
            *self.prompts.lock().expect("lock") += 1;
            if self.script.lock().expect("lock").dismiss {
                return Err(Refusal::Dismissed);
            }
            *self.approved.lock().expect("lock") = true;
            Ok(())
        }
    }

    impl Backend for Arc<Fake> {
        fn read(
            &self,
            _service: &str,
            name: &str,
            storage: Storage,
        ) -> Result<Option<String>, Refusal> {
            let script = *self.script.lock().expect("lock");
            if storage != Storage::Gated {
                let plain = self.plain.lock().expect("lock");
                return Ok(plain.get(name).map(|item| item.0.clone()));
            }
            if script.cannot == Some(Cannot::Gate) {
                return Err(Refusal::Unsupported);
            }
            let Some(secret) = self.gated.lock().expect("lock").get(name).cloned() else {
                return Ok(None);
            };
            if !*self.approved.lock().expect("lock") {
                if script.explicit_open {
                    return Err(Refusal::Other(ClientError::Auth("store shut".into())));
                }
                self.prompt()?;
            }
            Ok(Some(secret))
        }

        fn write(
            &self,
            _service: &str,
            name: &str,
            secret: &str,
            storage: Storage,
        ) -> Result<(), Refusal> {
            let script = *self.script.lock().expect("lock");
            if storage == Storage::Gated {
                match script.cannot {
                    Some(Cannot::DeviceLock) => return Err(Refusal::NoDeviceLock),
                    Some(Cannot::Gate) => return Err(Refusal::Unsupported),
                    None => {}
                }
                if script.explicit_open && !*self.approved.lock().expect("lock") {
                    return Err(Refusal::Other(ClientError::Auth("store shut".into())));
                }
                if script.creation_authorises {
                    *self.approved.lock().expect("lock") = true;
                }
            }
            self.seed(name, secret, storage);
            Ok(())
        }

        fn clear(&self, _service: &str, name: &str, storage: Storage) -> Result<(), ClientError> {
            match storage {
                Storage::Gated => self.gated.lock().expect("lock").remove(name).map(drop),
                Storage::Ungated(_) => self.plain.lock().expect("lock").remove(name).map(drop),
            };
            Ok(())
        }

        fn read_stranded(&self, _service: &str, name: &str) -> Result<Option<String>, Refusal> {
            let Some(secret) = self.gated.lock().expect("lock").get(name).cloned() else {
                return Ok(None);
            };
            if self.script.lock().expect("lock").key_gone {
                self.gated.lock().expect("lock").clear();
                return Ok(None);
            }
            if !*self.approved.lock().expect("lock") {
                self.prompt()?;
            }
            Ok(Some(secret))
        }

        fn open(&self, _service: &str, probe: Option<&str>) -> Result<(), Refusal> {
            let script = *self.script.lock().expect("lock");
            if script.explicit_open {
                match script.cannot {
                    Some(Cannot::DeviceLock) => return Err(Refusal::NoDeviceLock),
                    Some(Cannot::Gate) => return Err(Refusal::Unsupported),
                    None => {}
                }
                return self.prompt();
            }
            match probe {
                Some(name) => self.read("svc", name, Storage::Gated).map(drop),
                None => Ok(()),
            }
        }

        fn close(&self, _service: &str) {
            *self.closes.lock().expect("lock") += 1;
            *self.approved.lock().expect("lock") = false;
        }

        fn opens_explicitly(&self) -> bool {
            self.script.lock().expect("lock").explicit_open
        }
    }

    fn gate(script: Script) -> (SecretGate<Arc<Fake>>, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        *fake.script.lock().expect("lock") = script;
        (SecretGate::new("svc", Arc::clone(&fake), true), fake)
    }

    const TOKEN: &str = "\"alice\"";
    const KEY: &str = "connetto-replica-0123";

    #[test]
    fn only_the_secrets_are_gated_and_the_reserved_records_never_prompt() {
        let (gate, fake) = gate(Script::default());
        gate.write(crate::IDENTITY_RECORD, TOKEN).expect("identity");
        gate.write(TOKEN, "refresh").expect("token");
        assert_eq!(fake.storage_of(TOKEN), Some(Storage::Gated));
        assert_eq!(
            fake.storage_of(crate::IDENTITY_RECORD),
            Some(Storage::Ungated(NoGate::Offerable))
        );
        gate.read(crate::IDENTITY_RECORD).expect("identity");
        assert_eq!(fake.prompts(), 0, "a reserved record never prompts");
        assert_eq!(gate.protection(), Custody::Verified);
    }

    #[test]
    fn a_launch_prompts_once_at_the_first_gated_read_and_the_ask_then_needs_none() {
        let (gate, fake) = gate(Script::default());
        gate.write(KEY, "key").expect("create raises no prompt");
        assert_eq!(fake.prompts(), 0);
        gate.read(KEY).expect("first read");
        gate.read(KEY).expect("second read");
        assert_eq!(fake.prompts(), 1, "one prompt per launch");
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(
            fake.prompts(),
            1,
            "the arming ask reuses the launch approval"
        );
    }

    #[test]
    fn a_first_launch_that_only_created_asks_once_through_the_probe() {
        let (gate, fake) = gate(Script::default());
        gate.write(KEY, "key").expect("create");
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 1, "the ask reads the created secret");
    }

    #[test]
    fn a_first_launch_asks_even_when_the_creation_authorised_the_context() {
        let (gate, fake) = gate(Script {
            creation_authorises: true,
            ..Script::default()
        });
        gate.write(KEY, "key").expect("create");
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 1, "the launch ask raises the sheet");
        gate.read(KEY).expect("read after the approval");
        assert_eq!(fake.prompts(), 1, "one prompt per launch");
    }

    #[test]
    fn a_dismissal_at_launch_fails_the_read_and_the_next_access_asks_again() {
        let (gate, fake) = gate(Script::default());
        gate.write(KEY, "key").expect("create");
        fake.script.lock().expect("lock").dismiss = true;
        assert!(matches!(
            gate.read(KEY),
            Err(ClientError::SecretStore(
                crate::keyring::SecretStoreError::PromptDismissed
            ))
        ));
        fake.script.lock().expect("lock").dismiss = false;
        gate.read(KEY).expect("the retry prompts and reads");
        assert_eq!(fake.prompts(), 2);
    }

    #[test]
    fn a_locked_gate_refuses_gated_access_without_prompting_and_the_ask_reopens_it() {
        let (gate, fake) = gate(Script::default());
        gate.write(KEY, "key").expect("create");
        gate.read(KEY).expect("launch read");
        gate.lock();
        assert_eq!(
            *fake.closes.lock().expect("lock"),
            1,
            "the lock drops the approval"
        );
        assert!(matches!(gate.read(KEY), Err(ClientError::Locked)));
        assert!(matches!(
            gate.write(TOKEN, "rotated"),
            Err(ClientError::Locked)
        ));
        assert_eq!(fake.prompts(), 1, "a locked read raises no prompt");
        gate.read(crate::replica::ACCOUNTS_RECORD)
            .expect("reserved records stay open");
        gate.clear(TOKEN).expect("a delete proceeds while locked");

        fake.script.lock().expect("lock").dismiss = true;
        assert_eq!(gate.ask(), GateAskOutcome::Dismissed);
        assert!(
            matches!(gate.read(KEY), Err(ClientError::Locked)),
            "a dismissal stays locked"
        );
        fake.script.lock().expect("lock").dismiss = false;
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(gate.read(KEY).expect("reopened").as_deref(), Some("key"));
        assert_eq!(fake.prompts(), 3);
    }

    #[test]
    fn a_device_with_no_lock_keeps_the_secrets_ungated_and_says_it_can_be_offered() {
        let (gate, fake) = gate(Script {
            cannot: Some(Cannot::DeviceLock),
            ..Script::default()
        });
        gate.write(KEY, "key").expect("falls back");
        assert_eq!(
            fake.storage_of(KEY),
            Some(Storage::Ungated(NoGate::Offerable))
        );
        assert_eq!(gate.protection(), Custody::Unverified(NoGate::Offerable));
        gate.lock();
        assert_eq!(gate.read(KEY).expect("never locks").as_deref(), Some("key"));
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn a_first_read_without_the_entitlement_falls_back_before_any_write() {
        let (gate, fake) = gate(Script {
            cannot: Some(Cannot::Gate),
            ..Script::default()
        });
        assert_eq!(gate.read(TOKEN).expect("falls back"), None);
        assert_eq!(gate.protection(), Custody::Unverified(NoGate::Unsupported));
        gate.write(TOKEN, "refresh").expect("write");
        assert_eq!(
            fake.storage_of(TOKEN),
            Some(Storage::Ungated(NoGate::Unsupported))
        );
    }

    #[test]
    fn a_build_without_the_entitlement_reports_the_gate_unsupported() {
        let (gate, fake) = gate(Script {
            cannot: Some(Cannot::Gate),
            ..Script::default()
        });
        gate.write(KEY, "key").expect("falls back");
        assert_eq!(
            fake.storage_of(KEY),
            Some(Storage::Ungated(NoGate::Unsupported))
        );
        assert_eq!(gate.protection(), Custody::Unverified(NoGate::Unsupported));
    }

    #[test]
    fn a_gate_the_application_turned_off_writes_ungated_and_reports_offerable() {
        let fake = Arc::new(Fake::default());
        let gate = SecretGate::new("svc", Arc::clone(&fake), false);
        gate.write(KEY, "key").expect("write");
        assert_eq!(
            fake.storage_of(KEY),
            Some(Storage::Ungated(NoGate::Offerable))
        );
        assert_eq!(gate.protection(), Custody::Unverified(NoGate::Offerable));
        assert!(!gate.is_gated());
    }

    #[test]
    fn the_application_setting_turns_the_gate_off_and_back_on_before_a_secret_is_written() {
        let (gate, fake) = gate(Script::default());
        gate.configure(false);
        gate.write(KEY, "key").expect("write");
        assert_eq!(
            fake.storage_of(KEY),
            Some(Storage::Ungated(NoGate::Offerable))
        );
        gate.configure(true);
        gate.write(TOKEN, "refresh").expect("write");
        assert_eq!(fake.storage_of(TOKEN), Some(Storage::Gated));
        assert_eq!(gate.protection(), Custody::Verified);

        let (unentitled, _) = super::tests::gate(Script {
            cannot: Some(Cannot::Gate),
            ..Script::default()
        });
        unentitled.write(KEY, "key").expect("falls back");
        unentitled.configure(true);
        assert_eq!(
            unentitled.protection(),
            Custody::Unverified(NoGate::Unsupported),
            "a platform that cannot gate stays unsupported"
        );
    }

    #[tokio::test]
    async fn the_client_gate_mechanism_locks_the_secrets_and_asks_off_the_runtime() {
        use crate::away::GateMechanism as _;

        let (gate, fake) = gate(Script::default());
        gate.write(KEY, "key").expect("create");
        let gate = Arc::new(gate);
        let mechanism = super::KeyringMechanism::new(Arc::clone(&gate));
        assert!(
            !mechanism.is_open(),
            "a launch that only created is not verified"
        );
        assert_eq!(mechanism.ask().await, GateAskOutcome::Approved);
        assert!(mechanism.is_open(), "the approval opens it");
        assert_eq!(
            fake.prompts(),
            1,
            "the launch ask prompts through the probe"
        );
        mechanism.lock();
        assert!(matches!(gate.read(KEY), Err(ClientError::Locked)));
        assert_eq!(mechanism.ask().await, GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 2);
        assert_eq!(gate.read(KEY).expect("open").as_deref(), Some("key"));
    }

    #[test]
    fn an_unlock_once_store_opens_before_its_first_gated_access_and_once_per_launch() {
        let (gate, fake) = gate(Script {
            explicit_open: true,
            ..Script::default()
        });
        gate.write(TOKEN, "refresh")
            .expect("the first write opens the store");
        gate.write(KEY, "key").expect("second write");
        gate.read(TOKEN).expect("read");
        assert_eq!(fake.prompts(), 1, "one ceremony per launch");
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 1);
        gate.lock();
        assert!(matches!(gate.read(TOKEN), Err(ClientError::Locked)));
        assert_eq!(gate.ask(), GateAskOutcome::Approved);
        assert_eq!(fake.prompts(), 2, "the re-check runs the ceremony again");
        gate.read(KEY).expect("reopened");
    }

    #[test]
    fn an_unlock_once_store_that_cannot_gate_falls_back_at_its_first_access() {
        for (cannot, reason) in [
            (Cannot::Gate, NoGate::Unsupported),
            (Cannot::DeviceLock, NoGate::Offerable),
        ] {
            let (gate, fake) = gate(Script {
                explicit_open: true,
                cannot: Some(cannot),
                ..Script::default()
            });
            gate.write(TOKEN, "refresh").expect("falls back");
            assert_eq!(fake.storage_of(TOKEN), Some(Storage::Ungated(reason)));
            assert_eq!(gate.protection(), Custody::Unverified(reason));
            assert_eq!(gate.read(TOKEN).expect("read").as_deref(), Some("refresh"));
            assert_eq!(gate.ask(), GateAskOutcome::Approved);
            assert_eq!(fake.prompts(), 0);
        }
    }

    /// Both kinds of platform store, the one prompting at a gated read and the
    /// one opened by a ceremony before it.
    const STORES: [Script; 2] = [
        Script {
            dismiss: false,
            cannot: None,
            explicit_open: false,
            creation_authorises: false,
            key_gone: false,
        },
        Script {
            dismiss: false,
            cannot: None,
            explicit_open: true,
            creation_authorises: false,
            key_gone: false,
        },
    ];

    const PLAIN: Storage = Storage::Ungated(NoGate::Offerable);

    #[test]
    fn a_secret_stored_ungated_moves_behind_the_gate_and_verifies_nothing() {
        for script in STORES {
            let (gate, fake) = gate(script);
            fake.seed(KEY, "key", PLAIN);
            assert_eq!(gate.read(KEY).expect("read").as_deref(), Some("key"));
            assert_eq!(fake.storage_of(KEY), Some(Storage::Gated));
            let ceremony = usize::from(script.explicit_open);
            assert_eq!(fake.prompts(), ceremony, "the move itself raises no prompt");
            assert_eq!(
                gate.is_open(),
                script.explicit_open,
                "only a ceremony that ran verifies the user"
            );
            assert_eq!(gate.ask(), GateAskOutcome::Approved);
            assert_eq!(fake.prompts(), 1, "one prompt per launch either way");
        }
    }

    #[test]
    fn a_gate_turned_off_moves_each_gated_secret_out_for_one_prompt() {
        for script in STORES {
            let (gate, fake) = gate(script);
            gate.configure(false);
            fake.seed(KEY, "key", Storage::Gated);
            fake.seed(TOKEN, "refresh", Storage::Gated);
            assert_eq!(gate.read(KEY).expect("read").as_deref(), Some("key"));
            assert_eq!(gate.read(TOKEN).expect("read").as_deref(), Some("refresh"));
            assert_eq!(fake.storage_of(KEY), Some(PLAIN));
            assert_eq!(fake.storage_of(TOKEN), Some(PLAIN));
            assert_eq!(fake.prompts(), 1, "one prompt moves every secret");
            assert_eq!(gate.protection(), Custody::Unverified(NoGate::Offerable));
        }
    }

    #[test]
    fn a_dismissed_move_out_refuses_the_read_and_keeps_the_secret_gated() {
        for script in STORES {
            let (gate, fake) = gate(Script {
                dismiss: true,
                ..script
            });
            gate.configure(false);
            fake.seed(KEY, "key", Storage::Gated);
            assert!(matches!(
                gate.read(KEY),
                Err(ClientError::SecretStore(
                    crate::keyring::SecretStoreError::PromptDismissed
                ))
            ));
            assert_eq!(fake.storage_of(KEY), Some(Storage::Gated));
        }
    }

    #[test]
    fn a_gated_secret_whose_key_is_gone_reads_as_none_once_ungated() {
        let (gate, fake) = gate(Script {
            key_gone: true,
            cannot: Some(Cannot::DeviceLock),
            ..STORES[1]
        });
        fake.seed(KEY, "key", Storage::Gated);
        assert_eq!(gate.read(KEY).expect("read"), None);
        assert_eq!(fake.storage_of(KEY), None, "the dead copy is discarded");
        assert_eq!(fake.prompts(), 0);
    }

    #[test]
    fn an_ungated_read_of_nothing_prompts_for_nothing() {
        for script in STORES {
            let (gate, fake) = gate(script);
            gate.configure(false);
            assert_eq!(gate.read(KEY).expect("read"), None);
            assert_eq!(fake.prompts(), 0);
        }
    }

    #[test]
    fn a_write_leaves_one_copy_whichever_storage_held_the_last() {
        for script in STORES {
            let (gate, fake) = gate(script);
            fake.seed(TOKEN, "old", PLAIN);
            gate.write(TOKEN, "rotated").expect("write");
            assert_eq!(fake.storage_of(TOKEN), Some(Storage::Gated));

            let (gate, fake) = super::tests::gate(script);
            gate.configure(false);
            fake.seed(TOKEN, "old", Storage::Gated);
            gate.write(TOKEN, "rotated").expect("write");
            assert_eq!(fake.storage_of(TOKEN), Some(PLAIN));
            assert_eq!(fake.prompts(), 0, "dropping the gated copy never prompts");
        }
    }

    #[test]
    fn an_interrupted_move_reads_the_current_copy_and_the_next_write_drops_the_other() {
        let (gate, fake) = gate(STORES[1]);
        fake.seed(KEY, "moved", Storage::Gated);
        fake.seed(KEY, "left behind", PLAIN);
        assert_eq!(gate.read(KEY).expect("read").as_deref(), Some("moved"));
        gate.write(KEY, "moved").expect("write");
        assert_eq!(fake.storage_of(KEY), Some(Storage::Gated));
    }

    #[test]
    fn a_delete_removes_both_copies_without_a_prompt_even_while_locked() {
        for script in STORES {
            let (gate, fake) = gate(script);
            fake.seed(TOKEN, "gated", Storage::Gated);
            fake.seed(TOKEN, "plain", PLAIN);
            gate.lock();
            gate.clear(TOKEN).expect("delete");
            assert_eq!(fake.storage_of(TOKEN), None);
            assert_eq!(fake.prompts(), 0);
        }
    }
}
