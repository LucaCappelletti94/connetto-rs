//! The server's device certificate settings (R74): its issuer and the
//! lifetimes it grants.

use std::time::{Duration, SystemTime};

use connetto_core::device_cert::DeviceIssuer;

/// A certificate's lifetime when the application requests none (R74 decision 4).
const DEFAULT_LIFETIME: Duration = Duration::from_hours(24);
/// The longest lifetime granted by default (R74 decision 4).
const DEFAULT_CEILING: Duration = Duration::from_hours(24 * 30);
/// How long before its issuer expires the server starts warning (R74 decision 14).
const EXPIRY_WARNING: Duration = Duration::from_hours(24 * 60);
/// How long an enrolment nonce stays valid.
const CHALLENGE_WINDOW: Duration = Duration::from_secs(60);

mod enrolment;

pub(crate) use enrolment::PendingChallenge;
pub use enrolment::{
    Device, DeviceEnrolment, Enrolment, EnrolmentError, EnrolmentFuture, EnrolmentStore,
    MemoryEnrolments, Recorded, Revocation, RevokeError, SessionRevoker,
};

/// The issuer and the lifetimes it grants.
pub struct DeviceCertConfig {
    issuer: DeviceIssuer,
    default_lifetime: Duration,
    ceiling: Duration,
    challenge_window: Duration,
}

/// A requested lifetime over the ceiling, refused and never shortened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the lifetime is over the ceiling of {} s", .ceiling.as_secs())]
pub struct LifetimeRefused {
    /// The longest lifetime the server grants.
    pub ceiling: Duration,
}

/// Settings the server refuses to start with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The default lifetime is longer than the ceiling, so an unrequested lifetime would be refused.
    #[error(
        "the default certificate lifetime ({} s) is over the ceiling ({} s)",
        .default.as_secs(),
        .ceiling.as_secs()
    )]
    DefaultOverCeiling {
        /// The default lifetime.
        default: Duration,
        /// The ceiling.
        ceiling: Duration,
    },
    /// The issuer's certificate has expired, so it can issue nothing.
    #[error("the device certificate issuer has expired, sign a new one with connetto-ca")]
    IssuerExpired,
}

/// The issuer has less than sixty days left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerExpiring {
    /// The time left before it expires.
    pub left: Duration,
}

impl DeviceCertConfig {
    /// `issuer` with a 24-hour default lifetime under a 30-day ceiling.
    #[must_use]
    pub const fn new(issuer: DeviceIssuer) -> Self {
        Self {
            issuer,
            default_lifetime: DEFAULT_LIFETIME,
            ceiling: DEFAULT_CEILING,
            challenge_window: CHALLENGE_WINDOW,
        }
    }

    /// A certificate's lifetime when the application requests none.
    #[must_use]
    pub const fn with_default_lifetime(mut self, lifetime: Duration) -> Self {
        self.default_lifetime = lifetime;
        self
    }

    /// The longest lifetime granted.
    #[must_use]
    pub const fn with_lifetime_ceiling(mut self, ceiling: Duration) -> Self {
        self.ceiling = ceiling;
        self
    }

    /// How long an enrolment nonce stays valid, 60 seconds by default.
    #[must_use]
    pub const fn with_challenge_window(mut self, window: Duration) -> Self {
        self.challenge_window = window;
        self
    }

    /// The longest lifetime granted.
    #[must_use]
    pub const fn ceiling(&self) -> Duration {
        self.ceiling
    }

    /// How long an enrolment nonce stays valid.
    #[must_use]
    pub const fn challenge_window(&self) -> Duration {
        self.challenge_window
    }

    /// The issuer.
    #[must_use]
    pub const fn issuer(&self) -> &DeviceIssuer {
        &self.issuer
    }

    /// The lifetime to grant for `requested`, the default when none is requested.
    ///
    /// # Errors
    ///
    /// [`LifetimeRefused`] when the request is over the ceiling.
    pub fn lifetime_for(&self, requested: Option<Duration>) -> Result<Duration, LifetimeRefused> {
        match requested {
            Some(lifetime) if lifetime > self.ceiling => Err(LifetimeRefused {
                ceiling: self.ceiling,
            }),
            Some(lifetime) => Ok(lifetime),
            None => Ok(self.default_lifetime),
        }
    }

    /// The startup check at `now`, with a warning when the issuer has less than sixty days left.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for settings the server cannot serve with.
    pub fn check(&self, now: SystemTime) -> Result<Option<IssuerExpiring>, ConfigError> {
        if self.default_lifetime > self.ceiling {
            return Err(ConfigError::DefaultOverCeiling {
                default: self.default_lifetime,
                ceiling: self.ceiling,
            });
        }
        let left = self
            .issuer
            .not_after()
            .duration_since(now)
            .ok()
            .filter(|left| !left.is_zero())
            .ok_or(ConfigError::IssuerExpired)?;
        Ok((left < EXPIRY_WARNING).then_some(IssuerExpiring { left }))
    }
}

#[cfg(test)]
mod tests;
