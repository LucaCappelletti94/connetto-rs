//! connetto's own signed tokens: lifetimes, minting, and checking.
//!
//! Everything here is asymmetrically signed (Ed25519 through `jsonwebtoken`,
//! ring-backed, native backend only) under one key. Three things carry that
//! signature: a login grant naming a person and the run the auth store opened,
//! a capability grant naming a subject that is not a person, and the resume
//! blob naming the run of a caller with no identity. Checking pins the
//! algorithm (rejecting `none` and any symmetric algorithm), the issuer, the
//! audience, and the expiry. See `docs/architecture/11-authentication.md`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::SessionId;
pub use connetto_core::auth::VerifiedSession;
use connetto_core::auth::{AuthContext, CapabilitySubject, Subject};
use connetto_core::messages::Grant;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Default access-token lifetime. Short by design: a re-auth cadence, not the
/// revocation bound.
const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(15 * 60);
/// Default sliding refresh window, extended on each successful online refresh.
const DEFAULT_REFRESH_IDLE_WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// Default absolute refresh ceiling, a hard maximum regardless of use.
const DEFAULT_REFRESH_ABSOLUTE_CEILING: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// Default window in which a caller with no identity may keep resuming.
const DEFAULT_RESUME_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// Default share-key lifetime. A week is the ordinary span of a share link.
const DEFAULT_CAPABILITY_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Default ceiling on a share-key lifetime. It is what makes "a share key must
/// expire" something the server enforces rather than advice.
const DEFAULT_CAPABILITY_MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Server-side authentication configuration: token identity and lifetimes.
///
/// The architecture prescribes the shape (a short access token, a sliding
/// refresh window under an absolute ceiling) and leaves the exact numbers to
/// the deployment. These defaults are conservative and every field is
/// overridable.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// The `iss` connetto stamps on and pins in its own tokens.
    pub issuer: String,
    /// The `aud` connetto stamps on and pins in its own tokens.
    pub audience: String,
    /// Access-token lifetime.
    pub access_ttl: Duration,
    /// How long a caller with no identity may keep resuming the same run.
    ///
    /// It bounds a bearer blob that no login backs, so it cannot be endless,
    /// and it is the lifetime of the canonical case for an unidentified run,
    /// a shopping cart the visitor comes back to.
    pub resume_ttl: Duration,
    /// Default share-key lifetime, used when a mint names none.
    pub capability_ttl: Duration,
    /// Hard ceiling on a share-key lifetime. A mint asking for longer is
    /// refused rather than quietly shortened, so an application's own statement
    /// of when a link dies cannot be a lie.
    pub capability_max_ttl: Duration,
    /// Sliding refresh window, extended on each online refresh.
    pub refresh_idle_window: Duration,
    /// Absolute refresh ceiling, never extended.
    pub refresh_absolute_ceiling: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            issuer: "connetto".to_owned(),
            audience: "connetto".to_owned(),
            access_ttl: DEFAULT_ACCESS_TTL,
            resume_ttl: DEFAULT_RESUME_TTL,
            capability_ttl: DEFAULT_CAPABILITY_TTL,
            capability_max_ttl: DEFAULT_CAPABILITY_MAX_TTL,
            refresh_idle_window: DEFAULT_REFRESH_IDLE_WINDOW,
            refresh_absolute_ceiling: DEFAULT_REFRESH_ABSOLUTE_CEILING,
        }
    }
}

impl AuthConfig {
    /// The refresh-token lifetimes an auth store enforces.
    #[must_use]
    pub fn refresh_lifetimes(&self) -> RefreshLifetimes {
        RefreshLifetimes {
            idle_window: self.refresh_idle_window,
            absolute_ceiling: self.refresh_absolute_ceiling,
        }
    }
}

/// The refresh-token sliding window and absolute ceiling an auth store enforces.
#[derive(Debug, Clone, Copy)]
pub struct RefreshLifetimes {
    /// The session is refreshable only within this window since the last use.
    pub idle_window: Duration,
    /// The session is refreshable only within this window since creation.
    pub absolute_ceiling: Duration,
}

/// Failure minting or verifying a connetto access token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The supplied or generated key material was rejected.
    #[error("key material rejected: {0}")]
    Key(String),
    /// Signing the token failed.
    #[error("token minting failed: {0}")]
    Mint(String),
    /// The token failed signature, algorithm, issuer, audience, or expiry checks.
    #[error("token verification failed: {0}")]
    Verify(String),
    /// The system clock is before the unix epoch.
    #[error("system clock is before the unix epoch")]
    Clock,
}

/// What one signed grant claims, tagged by the kind of subject it names.
///
/// The tag is inside the signed payload, so choosing how to read a grant is
/// reading a checked claim rather than sniffing an opaque string, and one
/// `decode` handles both kinds with no order of attempts.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "knd")]
enum GrantClaims<Id, Key> {
    /// A login grant.
    #[serde(rename = "user")]
    User(AccessClaims<Id>),
    /// A capability grant.
    #[serde(rename = "key")]
    Key(CapabilityClaims<Key>),
}

/// The claims connetto signs into a login grant. `sub` is the `user_id`, `sid`
/// names the run for the liveness check, and the pair rebuilds the
/// [`AuthContext`] at the handshake with no store round-trip.
#[derive(Debug, Serialize, Deserialize)]
struct AccessClaims<Id> {
    iss: String,
    aud: String,
    sub: Id,
    iat: u64,
    exp: u64,
    sid: SessionId,
}

/// The claims connetto signs into a capability grant. `sub` is the subject the
/// authorization model relates permissions to, and there is deliberately
/// nothing else: a permission inside the token would split authorization
/// between the token and the model.
#[derive(Debug, Serialize, Deserialize)]
struct CapabilityClaims<Key> {
    iss: String,
    aud: String,
    sub: Key,
    iat: u64,
    exp: u64,
}

/// The claims connetto signs into the resume blob. `sub` is the run's handle.
#[derive(Debug, Serialize, Deserialize)]
struct ResumeClaims {
    iss: String,
    aud: String,
    sub: SessionId,
    iat: u64,
    exp: u64,
    knd: ResumeKind,
}

/// The resume blob's own tag, disjoint from every grant tag, so a grant cannot
/// be presented as a handle and a handle cannot be presented as a grant.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum ResumeKind {
    #[serde(rename = "run")]
    Run,
}

/// Mints and checks everything connetto signs under one key.
///
/// The algorithm is Ed25519 (`EdDSA`). Checking pins the algorithm, so a token
/// signed with any other algorithm (or the `none` algorithm, which
/// `jsonwebtoken` has no variant for) is refused, and it pins the issuer,
/// audience, and expiry.
pub struct TokenAuthority {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
    access_ttl: Duration,
    resume_ttl: Duration,
}

impl TokenAuthority {
    /// Build over a freshly generated ephemeral Ed25519 keypair.
    ///
    /// Suits the in-memory store, which is itself ephemeral, and local loops.
    /// A durable or multi-node deployment supplies a stable key through
    /// [`from_ed_pem`](Self::from_ed_pem).
    ///
    /// # Errors
    ///
    /// [`TokenError::Key`] if the platform RNG fails to produce a keypair.
    pub fn generate(config: &AuthConfig) -> Result<Self, TokenError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|err| TokenError::Key(err.to_string()))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|err| TokenError::Key(err.to_string()))?;
        let encoding = EncodingKey::from_ed_der(pkcs8.as_ref());
        let decoding = DecodingKey::from_ed_der(keypair.public_key().as_ref());
        Ok(Self::from_keys(encoding, decoding, config))
    }

    /// Build over an Ed25519 keypair supplied as PKCS#8 PEM (private) and the
    /// matching public-key PEM.
    ///
    /// A stable key is what lets a mesh verify tokens on any node with the
    /// shared public key, which is not a secret, so no secret crosses nodes.
    ///
    /// # Errors
    ///
    /// [`TokenError::Key`] if either PEM is malformed or not Ed25519.
    pub fn from_ed_pem(
        private_pem: &[u8],
        public_pem: &[u8],
        config: &AuthConfig,
    ) -> Result<Self, TokenError> {
        let encoding = EncodingKey::from_ed_pem(private_pem)
            .map_err(|err| TokenError::Key(err.to_string()))?;
        let decoding =
            DecodingKey::from_ed_pem(public_pem).map_err(|err| TokenError::Key(err.to_string()))?;
        Ok(Self::from_keys(encoding, decoding, config))
    }

    fn from_keys(encoding: EncodingKey, decoding: DecodingKey, config: &AuthConfig) -> Self {
        Self {
            encoding,
            decoding,
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            access_ttl: config.access_ttl,
            resume_ttl: config.resume_ttl,
        }
    }

    /// The access-token lifetime, echoed to the client as `expires_in`.
    #[must_use]
    pub fn access_ttl(&self) -> Duration {
        self.access_ttl
    }

    /// Mint an access token carrying `context`, naming `session_id`, issued at
    /// `issued_at`. Expiry is `issued_at + access_ttl`.
    ///
    /// # Errors
    ///
    /// [`TokenError::Clock`] if `issued_at` precedes the unix epoch, or
    /// [`TokenError::Mint`] if signing fails.
    pub fn mint_access<Id: Serialize + Clone>(
        &self,
        context: &AuthContext<Id>,
        session_id: SessionId,
        issued_at: SystemTime,
    ) -> Result<String, TokenError> {
        let iat = unix_secs(issued_at)?;
        let exp = iat.saturating_add(self.access_ttl.as_secs());
        let claims = GrantClaims::<Id, ()>::User(AccessClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: context.user_id.clone(),
            iat,
            exp,
            sid: session_id,
        });
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|err| TokenError::Mint(err.to_string()))
    }

    /// Mint a capability grant naming `subject`, expiring `ttl` after
    /// `issued_at`.
    ///
    /// The raw signing primitive, the counterpart of
    /// [`mint_access`](Self::mint_access). It carries no permission and checks
    /// nothing about whether the caller may share: the authorization model
    /// holds the permission as a relation on `subject`, and the check that a
    /// caller may not share what it cannot read wraps this call rather than
    /// living inside it.
    ///
    /// # Errors
    ///
    /// [`TokenError::Clock`] if `issued_at` precedes the unix epoch, or
    /// [`TokenError::Mint`] if signing fails.
    pub fn mint_capability<Key: Serialize + Clone>(
        &self,
        subject: &CapabilitySubject<Key>,
        issued_at: SystemTime,
        ttl: Duration,
    ) -> Result<String, TokenError> {
        let iat = unix_secs(issued_at)?;
        let claims = GrantClaims::<(), Key>::Key(CapabilityClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: subject.key().clone(),
            iat,
            exp: iat.saturating_add(ttl.as_secs()),
        });
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|err| TokenError::Mint(err.to_string()))
    }

    /// Check one grant's signature, algorithm, issuer, audience and expiry, and
    /// read the subject it names.
    ///
    /// Self-contained: it needs no store, because the signature is the proof.
    /// A login grant's liveness is checked separately, which is what makes
    /// revocation authoritative.
    ///
    /// # Errors
    ///
    /// [`TokenError::Verify`] if any check fails.
    pub fn check_grant<Id: DeserializeOwned, Key: DeserializeOwned>(
        &self,
        grant: &Grant,
    ) -> Result<Subject<Id, Key>, TokenError> {
        let data =
            decode::<GrantClaims<Id, Key>>(grant.as_str(), &self.decoding, &self.validation())
                .map_err(|err| TokenError::Verify(err.to_string()))?;
        Ok(match data.claims {
            GrantClaims::User(claims) => Subject::Identity(VerifiedSession {
                context: AuthContext {
                    user_id: claims.sub,
                },
                session_id: claims.sid,
            }),
            GrantClaims::Key(claims) => Subject::Capability(CapabilitySubject::new(claims.sub)),
        })
    }

    /// Mint the resume blob naming `session_id`, expiring `resume_ttl` after
    /// `issued_at`.
    ///
    /// # Errors
    ///
    /// [`TokenError::Clock`] if `issued_at` precedes the unix epoch, or
    /// [`TokenError::Mint`] if signing fails.
    pub fn mint_resume(
        &self,
        session_id: SessionId,
        issued_at: SystemTime,
    ) -> Result<String, TokenError> {
        let iat = unix_secs(issued_at)?;
        let claims = ResumeClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: session_id,
            iat,
            exp: iat.saturating_add(self.resume_ttl.as_secs()),
            knd: ResumeKind::Run,
        };
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|err| TokenError::Mint(err.to_string()))
    }

    /// Read the handle out of a resume blob this authority signed.
    ///
    /// # Errors
    ///
    /// [`TokenError::Verify`] if the blob is not one this authority signed, has
    /// expired, or is a grant rather than a handle.
    pub fn verify_resume(&self, blob: &str) -> Result<SessionId, TokenError> {
        let data = decode::<ResumeClaims>(blob, &self.decoding, &self.validation())
            .map_err(|err| TokenError::Verify(err.to_string()))?;
        Ok(data.claims.sub)
    }

    /// The shared check: pin the algorithm, issuer, audience and expiry.
    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation
    }
}

fn unix_secs(time: SystemTime) -> Result<u64, TokenError> {
    time.duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .map_err(|_| TokenError::Clock)
}
