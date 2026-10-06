//! The server's device certificate settings (R74): its issuer, the lifetimes
//! it grants, and the attestation levels it accepts.

use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{AttestationLevel, DeviceIssuer};
use connetto_core::messages::SignedList;

/// A certificate's lifetime when the application requests none (R74 decision 4).
const DEFAULT_LIFETIME: Duration = Duration::from_hours(24);
/// The longest lifetime granted by default (R74 decision 4).
const DEFAULT_CEILING: Duration = Duration::from_hours(24 * 30);
/// How long before its issuer expires the server starts warning (R74 decision 14).
const EXPIRY_WARNING: Duration = Duration::from_hours(24 * 60);
/// How long an enrolment nonce stays valid.
const CHALLENGE_WINDOW: Duration = Duration::from_secs(60);
/// Google's two current attestation roots (developer.android.com).
const GOOGLE_ROOTS: &str = include_str!("google_roots.pem");
/// Apple's App Attest root (www.apple.com/certificateauthority/private).
const APPLE_ROOT: &str = include_str!("apple_root.pem");

mod attestation;
mod enrolment;
mod schema;

pub(crate) use attestation::verify;
pub use attestation::{
    AndroidStatus, AppAttestEnvironment, AppAttestSettings, SerialCheck, SerialStatus, StatusList,
};
#[doc(hidden)]
pub use connetto_core::device_cert::{KeyId, Revoked};
pub(crate) use enrolment::PendingChallenge;
pub use enrolment::{
    Device, DeviceEnrolment, Enrolment, EnrolmentError, EnrolmentFuture, EnrolmentStore,
    MemoryEnrolments, Recorded, Revocation, RevokeError, SessionRevoker,
};
#[doc(hidden)]
pub use schema::__key_id;
pub use schema::{
    ConnettoEnrolmentSchema, DeviceRow, KeyFacts, NewCertificate, NewEnrolment, Renewal, Statement,
    pg_enrolment_store,
};

/// The issuer, the lifetimes it grants, and the attestation the server
/// verifies into a level (R74 step 4).
pub struct DeviceCertConfig {
    issuer: DeviceIssuer,
    default_lifetime: Duration,
    ceiling: Duration,
    challenge_window: Duration,
    retired: Vec<DeviceIssuer>,
    root_lists: Vec<SignedList>,
    android_roots: Vec<Vec<u8>>,
    android_status: AndroidStatus,
    apple_root: Vec<u8>,
    app_attest: Option<AppAttestSettings>,
    accepted: Vec<AttestationLevel>,
}

impl core::fmt::Debug for DeviceCertConfig {
    /// Names the issuers by key id, never their private keys.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceCertConfig")
            .field("issuer", &self.issuer.key_id())
            .field("default_lifetime", &self.default_lifetime)
            .field("ceiling", &self.ceiling)
            .field("challenge_window", &self.challenge_window)
            .field(
                "retired",
                &self
                    .retired
                    .iter()
                    .map(DeviceIssuer::key_id)
                    .collect::<Vec<_>>(),
            )
            .field("root_lists", &self.root_lists.len())
            .field("android_roots", &self.android_roots.len())
            .field("android_status", &self.android_status)
            .field("apple_root", &self.apple_root.len())
            .field("app_attest", &self.app_attest)
            .field("accepted", &self.accepted)
            .finish()
    }
}

/// A requested lifetime the server will not grant, refused and never shortened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LifetimeError {
    /// The request is over the ceiling, which the refusal names.
    #[error("the lifetime is over the ceiling of {} s", .ceiling.as_secs())]
    OverCeiling {
        /// The longest lifetime the server grants.
        ceiling: Duration,
    },
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
    /// `issuer` with a 24-hour default lifetime under a 30-day ceiling, both
    /// of Google's attestation roots as the Android roots, Apple's root, no
    /// App Attest App IDs and every attestation level accepted.
    #[must_use]
    pub fn new(issuer: DeviceIssuer) -> Self {
        Self {
            issuer,
            default_lifetime: DEFAULT_LIFETIME,
            ceiling: DEFAULT_CEILING,
            challenge_window: CHALLENGE_WINDOW,
            retired: Vec::new(),
            root_lists: Vec::new(),
            android_roots: pem_roots(GOOGLE_ROOTS),
            android_status: AndroidStatus::default(),
            apple_root: pem_root(APPLE_ROOT),
            app_attest: None,
            accepted: AttestationLevel::ALL.to_vec(),
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

    /// An issuer this one replaced, kept to sign the lists of its own
    /// certificates until it expires, after its last certificate (decision 14).
    #[must_use]
    pub fn with_retired_issuer(mut self, issuer: DeviceIssuer) -> Self {
        self.retired.push(issuer);
        self
    }

    /// A list the root signed offline with `connetto-ca revoke-issuer`,
    /// published beside the issuers' own lists.
    #[must_use]
    pub fn with_root_list(mut self, list: SignedList) -> Self {
        self.root_lists.push(list);
        self
    }

    /// The DER roots an Android attestation chain verifies to, matched by
    /// public key (decision 31), Google's two current roots by default.
    #[must_use]
    pub fn with_android_roots(mut self, roots: Vec<Vec<u8>>) -> Self {
        self.android_roots = roots;
        self
    }

    /// The source of the Android attestation status list (decision 34),
    /// Google's `https://android.googleapis.com/attestation/status` by default.
    #[must_use]
    pub fn with_android_status(mut self, source: AndroidStatus) -> Self {
        self.android_status = source;
        self
    }

    /// The App IDs App Attest vouches for and the environment they attest in
    /// (decision 32). An attestation that passes Apple's checks for a listed
    /// App ID under that environment records `app-attested`.
    #[must_use]
    pub fn with_app_attest(
        mut self,
        app_ids: Vec<String>,
        environment: AppAttestEnvironment,
    ) -> Self {
        self.app_attest = Some(AppAttestSettings {
            app_ids,
            environment,
        });
        self
    }

    /// The DER root an App Attest chain verifies to, Apple's root by default.
    #[must_use]
    pub fn with_apple_root(mut self, root: Vec<u8>) -> Self {
        self.apple_root = root;
        self
    }

    /// The attestation levels the deployment accepts, all three by default
    /// (decision 33). An enrolment, or a renewal of an enrolment, whose level
    /// is outside the set is refused with `AttestationRequired`.
    #[must_use]
    pub fn with_accepted_attestation(
        mut self,
        levels: impl IntoIterator<Item = AttestationLevel>,
    ) -> Self {
        self.accepted = levels.into_iter().collect();
        self
    }

    /// The issuers whose lists are published at `now`: the current one, and
    /// every retired one not yet expired.
    pub(crate) fn signing_issuers(&self, now: SystemTime) -> impl Iterator<Item = &DeviceIssuer> {
        core::iter::once(&self.issuer).chain(
            self.retired
                .iter()
                .filter(move |retired| retired.not_after() > now),
        )
    }

    /// The root-signed lists published as given.
    pub(crate) fn root_lists(&self) -> &[SignedList] {
        &self.root_lists
    }

    /// The attestation roots an Android chain verifies to.
    pub(crate) fn android_roots(&self) -> &[Vec<u8>] {
        &self.android_roots
    }

    /// The source of the Android attestation status list.
    pub(crate) fn android_status(&self) -> &AndroidStatus {
        &self.android_status
    }

    /// The root an App Attest chain verifies to.
    pub(crate) fn apple_root(&self) -> &[u8] {
        &self.apple_root
    }

    /// The App Attest settings, `None` when no App IDs are listed.
    pub(crate) fn app_attest(&self) -> Option<&AppAttestSettings> {
        self.app_attest.as_ref()
    }

    /// The attestation levels the deployment accepts.
    pub(crate) fn accepted_attestation(&self) -> &[AttestationLevel] {
        &self.accepted
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
    /// [`LifetimeError`] when the request is over the ceiling.
    pub fn lifetime_for(&self, requested: Option<Duration>) -> Result<Duration, LifetimeError> {
        match requested {
            Some(lifetime) if lifetime > self.ceiling => Err(LifetimeError::OverCeiling {
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

/// The DER certificates a PEM document holds.
fn pem_roots(pem: &str) -> Vec<Vec<u8>> {
    pem::parse_many(pem)
        .into_iter()
        .flatten()
        .map(|file| file.contents().to_vec())
        .collect()
}

/// The first DER certificate a PEM document holds.
fn pem_root(pem: &str) -> Vec<u8> {
    pem_roots(pem).into_iter().next().unwrap_or_default()
}

#[cfg(test)]
mod tests;
