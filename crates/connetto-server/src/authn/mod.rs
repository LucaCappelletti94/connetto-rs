//! Authentication: proving who a caller is, distinct from the authorization in
//! [`crate::auth`] which decides what a caller may see or write.
//!
//! connetto is the OAuth client (Backend-For-Frontend). It verifies a provider
//! token once at login (phase 3), maps the claims to a `user_id`, and mints its
//! own asymmetrically signed access token plus a stored rotating refresh token.
//! The handshake verifies connetto's own token and checks session liveness,
//! building the [`AuthContext`](connetto_core::auth::AuthContext) that RLS
//! consumes. See `docs/architecture/11-authentication.md`.
//!
//! This module holds the token authority ([`token`]), the pluggable auth store
//! ([`store`]), the login and refresh service plus the real session verifier
//! ([`service`]), and the HTTP endpoints ([`http`]).

pub mod http;
pub mod identity;
pub mod provider;
pub mod provider_oidc;
pub mod schema;
pub mod service;
pub mod store;
pub mod token;

pub use identity::{
    DefaultUuidResolver, IdentityResolver, ResolveError, ResolveFuture, VerifiedClaims,
};
pub use provider::{
    AssuranceRequirement, AuthCodes, IdentityProvider, IssuedAuthCode, LoginRedirect, PendingLogin,
    PendingLogins, PermissiveProvider, ProviderError, ProviderRegistry, RetainedProviderToken,
    VerifiedLogin,
};
pub use provider_oidc::{GenericOidcProvider, OidcProviderConfig};
pub use service::{AuthError, AuthService, ConnettoSessionVerifier, TokenPair};
pub use store::{
    AuthStore, AuthStoreError, InMemoryAuthStore, IssuedSession, RefreshOutcome, ResolvedIdentity,
};
pub use token::{AuthConfig, RefreshLifetimes, TokenAuthority, TokenError, VerifiedSession};

pub use schema::{ConnettoStoreSchema, StoreColumn};
pub use store::DbAuthStore;
