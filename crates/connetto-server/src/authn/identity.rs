//! The identity seam: mapping a verified credential's claims to the developer's
//! own typed distributed user id.
//!
//! connetto owns no identities table. A deployment supplies an [`IdentityResolver`]
//! that maps the [`VerifiedClaims`] connetto verified (issuer and subject, plus
//! optional email, name, `amr`, `acr`) to a typed `Id` in the developer's own
//! users table, so the developer can mint a new user row, link logins by verified
//! email, or gate on assurance. The resolver runs against the same Postgres as
//! the store, because `sessions.user_id` foreign-keys the row the resolver
//! produced. See `docs/architecture/11-authentication.md`.
//!
//! The in-memory store ships [`DefaultUuidResolver`], a deterministic UUID v5
//! mapping over `(issuer, subject)`, as the dev and test default.

use uuid::Uuid;

/// The verified claims a provider asserted, handed to the [`IdentityResolver`].
///
/// `issuer` and `subject` are always present (the only guaranteed unique
/// identifier per `OpenID Connect Core` 5.7). The rest are optional and let a
/// resolver link accounts or gate on assurance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    /// The `iss` claim: the identity provider that issued the credential.
    pub issuer: String,
    /// The `sub` claim: locally unique within the issuer.
    pub subject: String,
    /// The verified `email` claim, if the provider asserted one.
    pub email: Option<String>,
    /// The `name` claim, if present.
    pub name: Option<String>,
    /// The `amr` claim: the authentication methods used.
    pub amr: Vec<String>,
    /// The `acr` claim: the authentication context class reference.
    pub acr: Option<String>,
}

/// Failure resolving a verified identity to a typed user id.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The claims did not map to any user and the resolver does not mint one.
    #[error("no user for the presented identity")]
    NotFound,
    /// The resolver's backend (the developer's users table) failed.
    #[error("identity resolver backend error: {0}")]
    Backend(String),
}

/// The boxed future produced by [`IdentityResolver::resolve`].
///
/// A boxed `Send` future keeps the trait object-safe so the store can hold an
/// `Arc<dyn IdentityResolver<Id = _>>`, mirroring the session verifier. Identity
/// resolution fires once per login, off any hot path, so the box is irrelevant.
pub type ResolveFuture<'a, Id> =
    core::pin::Pin<Box<dyn Future<Output = Result<Id, ResolveError>> + Send + 'a>>;

/// Maps verified provider claims to the developer's typed distributed user id.
///
/// Held by the auth store as a runtime trait object so a deployment configures
/// identity without changing the store's type. The resolver owns account
/// creation and linking: creating a new user row (so the `sessions.user_id`
/// foreign-key target exists) is the resolver's job, run against the same
/// Postgres as the store.
pub trait IdentityResolver: Send + Sync {
    /// The developer-defined distributed user id.
    type Id;

    /// Resolve `claims` to a typed user id, minting or linking a user row as the
    /// deployment's policy requires.
    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, Self::Id>;
}

/// Namespace for the deterministic `(issuer, subject)` to `user_id` mapping. A
/// fixed random UUID, per `OpenID Connect Core` 5.7 which makes the issuer and
/// subject pair the only guaranteed unique identifier.
const CONNETTO_ID_NAMESPACE: Uuid = Uuid::from_u128(0x1d3f_9c8a_4b62_4f1e_9a7d_2c5e_8b0f_6a41);

/// Compute the deterministic UUID v5 over `(issuer, subject)`.
#[must_use]
pub fn deterministic_uuid(issuer: &str, subject: &str) -> Uuid {
    Uuid::new_v5(
        &CONNETTO_ID_NAMESPACE,
        format!("{issuer}|{subject}").as_bytes(),
    )
}

/// The default in-memory resolver: a deterministic UUID v5 over
/// `(issuer, subject)`, rendered as a string `user_id`. It needs no users table
/// and links nothing, suiting dev and test.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultUuidResolver;

impl IdentityResolver for DefaultUuidResolver {
    type Id = String;

    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, String> {
        let user_id = deterministic_uuid(&claims.issuer, &claims.subject).to_string();
        Box::pin(async move { Ok(user_id) })
    }
}
