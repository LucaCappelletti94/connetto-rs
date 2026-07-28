//! connetto's own session access token: lifetimes, minting, and verification.
//!
//! The access token is short-lived and asymmetrically signed (Ed25519 through
//! `jsonwebtoken`, ring-backed, native backend only). It carries the full
//! identity (`user_id`, `tenant_id`, `roles`, `claims`) plus the session id, so
//! the handshake trusts the identity from the signature alone and checks
//! liveness separately. Verification pins the algorithm (rejecting `none` and
//! any symmetric algorithm), the issuer, the audience, and the expiry. See
//! `docs/architecture/11-authentication.md`.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::auth::AuthContext;
pub use connetto_core::auth::VerifiedSession;
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

/// The claims connetto signs into its access token. `sub` is the `user_id`,
/// `sid` names the session for the liveness check, and the identity fields
/// rebuild the [`AuthContext`] at the handshake with no store round-trip.
#[derive(Debug, Serialize, Deserialize)]
struct AccessClaims<Id> {
    iss: String,
    aud: String,
    sub: Id,
    iat: u64,
    exp: u64,
    sid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    roles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    claims: BTreeMap<String, String>,
}

/// Mints and verifies connetto's own asymmetrically signed access token.
///
/// The algorithm is Ed25519 (`EdDSA`). Verification pins the algorithm, so a
/// token signed with any other algorithm (or the `none` algorithm, which
/// `jsonwebtoken` has no variant for) is refused, and it pins the issuer,
/// audience, and expiry.
pub struct TokenAuthority {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
    access_ttl: Duration,
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
        session_id: &str,
        issued_at: SystemTime,
    ) -> Result<String, TokenError> {
        let iat = unix_secs(issued_at)?;
        let exp = iat.saturating_add(self.access_ttl.as_secs());
        let claims = AccessClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: context.user_id.clone(),
            iat,
            exp,
            sid: session_id.to_owned(),
            tid: context.tenant_id.clone(),
            roles: context.roles.clone(),
            claims: context.claims.clone(),
        };
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding)
            .map_err(|err| TokenError::Mint(err.to_string()))
    }

    /// Verify an access token's signature, algorithm, issuer, audience, and
    /// expiry, and rebuild the identity it carries.
    ///
    /// This is self-contained: it needs no store, because the signature is the
    /// proof. The handshake still checks session liveness separately, which is
    /// what makes revocation authoritative.
    ///
    /// # Errors
    ///
    /// [`TokenError::Verify`] if any check fails.
    pub fn verify_access<Id: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<VerifiedSession<Id>, TokenError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let data = decode::<AccessClaims<Id>>(token, &self.decoding, &validation)
            .map_err(|err| TokenError::Verify(err.to_string()))?;
        let claims = data.claims;
        let context = AuthContext {
            user_id: claims.sub,
            tenant_id: claims.tid,
            roles: claims.roles,
            claims: claims.claims,
        };
        Ok(VerifiedSession {
            context,
            session_id: claims.sid,
        })
    }
}

fn unix_secs(time: SystemTime) -> Result<u64, TokenError> {
    time.duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .map_err(|_| TokenError::Clock)
}
