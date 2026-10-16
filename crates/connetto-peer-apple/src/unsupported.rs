//! The non-Apple platform: every framework call answers its own refusal.

/// The device side, absent off Apple.
pub(super) mod device {
    use super::super::Idiom;

    /// The device's user-set name, absent off Apple.
    pub(crate) fn device_name() -> Option<String> {
        None
    }

    /// The device's idiom, `Other` off Apple.
    pub(crate) fn device_idiom() -> Idiom {
        Idiom::Other
    }
}

/// The Bluetooth side, absent off Apple.
pub(super) mod peripheral {
    use super::super::{
        Error,
        bluetooth::{Event, PromptOutcome, State},
    };

    /// The radio's standing, unsupported off Apple.
    pub(crate) fn state() -> State {
        State::Unsupported
    }

    /// The strongest action, which has nothing to do off Apple.
    pub(crate) fn prompt() -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The last prompt's outcome, never settled off Apple.
    pub(crate) fn prompt_outcome() -> Option<PromptOutcome> {
        None
    }

    /// The GATT service, which stands nowhere off Apple.
    pub(crate) fn start() -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The GATT service's close, which stands ready off Apple.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "one signature on every target, and only iOS can fail"
    )]
    pub(crate) fn stop() -> Result<(), Error> {
        Ok(())
    }

    /// The service's events, never any off Apple.
    pub(crate) fn poll() -> Vec<Event> {
        Vec::new()
    }

    /// The service's send, which reaches no central off Apple.
    pub(crate) fn notify(_device: u64, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The central's close, which stands ready off Apple.
    pub(crate) fn disconnect(_device: u64) {}
}

/// The hotspot side, absent off Apple.
pub(super) mod hotspot {
    use super::super::{
        Error,
        hotspot::{Joined, Joining, Security},
    };

    /// The system's join, which stands nowhere off Apple.
    pub(crate) fn join(_ssid: &str, _passphrase: &str, _security: Security) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    /// The system's answer, never any off Apple.
    pub(crate) fn completion() -> Option<Result<Joining, Error>> {
        None
    }

    /// The system's release, which stands ready off Apple.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "one signature on every target, and only iOS can fail"
    )]
    pub(crate) fn leave(_ssid: &str) -> Result<(), Error> {
        Ok(())
    }

    /// The joined network, never any off Apple.
    pub(crate) fn joined() -> Option<Joined> {
        None
    }
}
