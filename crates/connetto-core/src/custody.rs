//! How the key protecting an open replica is held on this device.
//!
//! A user cannot infer from their browser or their operating system whether the
//! local copy of their data is behind a user-verified gate, so connetto reports
//! it rather than only documenting it. See the "Key custody" section of
//! `docs/architecture/14-at-rest-encryption.md`.
//!
//! The reason matters as much as the level, because only some reasons can be
//! acted on: a platform with no gate is final, while a gate nobody has set up
//! yet can be offered.

/// How the key protecting an open replica is held.
///
/// Read it from the connection that owns the durable replica. Never construct a
/// level a build does not actually provide: reporting protection that is not
/// there is worse than reporting nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Custody {
    /// Derived at unlock from a credential the user verified themselves with,
    /// and held only in memory. Nothing stored on the device opens the replica,
    /// so a copy of the stored data alone is inert.
    Verified,
    /// Held on the device with no user verification, for the stated reason. This
    /// defends a copy of the storage that leaves the device and it crypto-shreds
    /// on logout, but not somebody holding the whole profile or the unlocked
    /// machine.
    Unverified(NoGate),
    /// No durable key, because nothing durable is kept: the replica is in
    /// memory, which is what a run with nobody signed in gets.
    Ephemeral,
}

/// Why an open replica has no user-verified gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoGate {
    /// This platform has no gate connetto can use, so nothing can be offered.
    Unsupported,
    /// A gate is available here and nobody has set one up. An application may
    /// offer it.
    Offerable,
    /// A gate is available here and the user declined it. An application may
    /// offer it again, and enrolling re-wraps the replica key under the derived
    /// one.
    Declined,
}

impl Custody {
    /// Whether the replica is behind a user-verified gate.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(*self, Self::Verified)
    }

    /// Whether an application can usefully offer the gate. False both when the
    /// gate is already in place and when the platform cannot provide one.
    #[must_use]
    pub const fn offerable(&self) -> bool {
        matches!(
            *self,
            Self::Unverified(NoGate::Offerable | NoGate::Declined)
        )
    }
}

impl core::fmt::Display for Custody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Verified => f.write_str("derived from a user-verified credential"),
            Self::Unverified(NoGate::Unsupported) => {
                f.write_str("stored without user verification, unsupported on this platform")
            }
            Self::Unverified(NoGate::Offerable) => {
                f.write_str("stored without user verification, not set up yet")
            }
            Self::Unverified(NoGate::Declined) => {
                f.write_str("stored without user verification, declined by the user")
            }
            Self::Ephemeral => f.write_str("no durable key, nothing is kept"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Custody, NoGate};

    #[test]
    fn only_the_two_fixable_reasons_are_offerable() {
        assert!(Custody::Unverified(NoGate::Offerable).offerable());
        assert!(Custody::Unverified(NoGate::Declined).offerable());
        // A platform that cannot is final, and a gate already in place has
        // nothing left to offer. Both would be a pointless prompt.
        assert!(!Custody::Unverified(NoGate::Unsupported).offerable());
        assert!(!Custody::Verified.offerable());
        assert!(!Custody::Ephemeral.offerable());
    }

    #[test]
    fn verified_is_the_only_gated_level() {
        assert!(Custody::Verified.is_verified());
        assert!(!Custody::Unverified(NoGate::Declined).is_verified());
        assert!(!Custody::Ephemeral.is_verified());
    }
}
