//! Concrete OIDC providers over `openidconnect`: a generic provider plus Google
//! and Microsoft presets.
//!
//! connetto is the confidential OAuth client. Each provider discovers its
//! metadata and JWKS at startup, then builds a client with a fixed endpoint
//! typestate (auth and token URLs set) so one concrete client type is stored.
//! The ID token is verified with pure-Rust crypto (RS256 by default), and the
//! `(iss, sub)` pair plus the standard claims map to a [`ResolvedIdentity`].
//! Microsoft embeds the tenant in the issuer and ends it in `/v2.0`, so exact
//! issuer matching is insufficient: the Microsoft preset accepts an any-tenant
//! issuer pattern and validates it after verification.

use std::time::SystemTime;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata};
use openidconnect::reqwest;
use openidconnect::{
    AccessToken, AuthenticationContextClass, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse,
};

use crate::authn::provider::{
    AssuranceRequirement, BoxFuture, IdentityProvider, LoginRedirect, ProviderError,
    RetainedProviderToken, VerifiedLogin,
};
use crate::authn::store::ResolvedIdentity;

/// Google's fixed OIDC issuer.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
/// Microsoft's multi-tenant discovery issuer (the common endpoint).
const MICROSOFT_COMMON_ISSUER: &str = "https://login.microsoftonline.com/common/v2.0";
/// Microsoft issuer prefix for the any-tenant match.
const MICROSOFT_ISSUER_PREFIX: &str = "https://login.microsoftonline.com/";
/// Microsoft issuer suffix for the any-tenant match.
const MICROSOFT_ISSUER_SUFFIX: &str = "/v2.0";

/// The stored client type after `CoreClient::new` plus the auth and token URL
/// setters: auth and token endpoints set, the rest unset.
type ConfiguredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointNotSet,
>;

/// How a provider decides whether it verifies a given issuer.
#[derive(Debug, Clone)]
enum IssuerMatch {
    /// Exactly this issuer (Google, generic).
    Exact(String),
    /// Any Microsoft tenant: `https://login.microsoftonline.com/<tenant>/v2.0`.
    MicrosoftAnyTenant,
}

impl IssuerMatch {
    fn index_key(&self) -> &str {
        match self {
            Self::Exact(issuer) => issuer,
            Self::MicrosoftAnyTenant => MICROSOFT_COMMON_ISSUER,
        }
    }

    fn matches(&self, issuer: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == issuer,
            Self::MicrosoftAnyTenant => {
                issuer.starts_with(MICROSOFT_ISSUER_PREFIX)
                    && issuer.ends_with(MICROSOFT_ISSUER_SUFFIX)
                    && issuer.len() > MICROSOFT_ISSUER_PREFIX.len() + MICROSOFT_ISSUER_SUFFIX.len()
            }
        }
    }

    fn is_pattern(&self) -> bool {
        matches!(self, Self::MicrosoftAnyTenant)
    }
}

/// Confidential-client configuration for one provider.
#[derive(Debug, Clone)]
pub struct OidcProviderConfig {
    /// The provider name, for the by-name registry lookup.
    pub name: String,
    /// The OAuth client id.
    pub client_id: String,
    /// The OAuth client secret, when the provider is confidential.
    pub client_secret: Option<String>,
    /// The OIDC issuer to discover (for the generic and Google providers).
    pub issuer: String,
    /// The redirect URL registered with the provider.
    pub redirect_url: String,
    /// The scopes to request beyond `openid`.
    pub scopes: Vec<String>,
    /// The MFA assurance bar to request and enforce.
    pub assurance: AssuranceRequirement,
}

/// An OIDC identity provider driven by `openidconnect`.
pub struct GenericOidcProvider {
    name: String,
    client: ConfiguredClient,
    http: reqwest::Client,
    scopes: Vec<Scope>,
    assurance: AssuranceRequirement,
    issuer_match: IssuerMatch,
}

impl GenericOidcProvider {
    /// Discover a provider's metadata and JWKS and build it, matching the
    /// discovered issuer exactly.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Config`] if discovery or client construction fails.
    pub async fn discover(
        config: OidcProviderConfig,
        http: reqwest::Client,
    ) -> Result<Self, ProviderError> {
        let issuer = config.issuer.clone();
        Self::discover_with_match(config, IssuerMatch::Exact(issuer), http).await
    }

    /// The Google preset: Google's fixed issuer, exact match.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Config`] if discovery fails.
    pub async fn google(
        mut config: OidcProviderConfig,
        http: reqwest::Client,
    ) -> Result<Self, ProviderError> {
        GOOGLE_ISSUER.clone_into(&mut config.issuer);
        Self::discover_with_match(config, IssuerMatch::Exact(GOOGLE_ISSUER.to_owned()), http).await
    }

    /// The Microsoft preset: the common (multi-tenant) endpoint, any-tenant
    /// issuer match.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Config`] if discovery fails.
    pub async fn microsoft(
        mut config: OidcProviderConfig,
        http: reqwest::Client,
    ) -> Result<Self, ProviderError> {
        MICROSOFT_COMMON_ISSUER.clone_into(&mut config.issuer);
        Self::discover_with_match(config, IssuerMatch::MicrosoftAnyTenant, http).await
    }

    async fn discover_with_match(
        config: OidcProviderConfig,
        issuer_match: IssuerMatch,
        http: reqwest::Client,
    ) -> Result<Self, ProviderError> {
        let issuer_url = IssuerUrl::new(config.issuer.clone())
            .map_err(|err| ProviderError::Config(err.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &http)
            .await
            .map_err(|err| ProviderError::Config(err.to_string()))?;
        let auth_url = metadata.authorization_endpoint().clone();
        let token_url = metadata
            .token_endpoint()
            .ok_or_else(|| ProviderError::Config("provider has no token endpoint".to_owned()))?
            .clone();
        let issuer = metadata.issuer().clone();
        let jwks = metadata.jwks().clone();
        let client = CoreClient::new(ClientId::new(config.client_id.clone()), issuer, jwks);
        let client = match &config.client_secret {
            Some(secret) => client.set_client_secret(ClientSecret::new(secret.clone())),
            None => client,
        };
        let client = client
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_url.clone())
                    .map_err(|err| ProviderError::Config(err.to_string()))?,
            );
        Ok(Self {
            name: config.name,
            client,
            http,
            scopes: config.scopes.into_iter().map(Scope::new).collect(),
            assurance: config.assurance,
            issuer_match,
        })
    }

    /// Build directly from endpoints and a JWKS, without discovery. For tests
    /// that verify a locally minted ID token with no network.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Config`] if a URL is malformed.
    pub fn from_parts(
        config: OidcProviderConfig,
        auth_url: &str,
        token_url: &str,
        jwks: openidconnect::core::CoreJsonWebKeySet,
        http: reqwest::Client,
    ) -> Result<Self, ProviderError> {
        let issuer = IssuerUrl::new(config.issuer.clone())
            .map_err(|err| ProviderError::Config(err.to_string()))?;
        let client = CoreClient::new(ClientId::new(config.client_id.clone()), issuer, jwks);
        let client = match &config.client_secret {
            Some(secret) => client.set_client_secret(ClientSecret::new(secret.clone())),
            None => client,
        };
        let client = client
            .set_auth_uri(
                openidconnect::AuthUrl::new(auth_url.to_owned())
                    .map_err(|err| ProviderError::Config(err.to_string()))?,
            )
            .set_token_uri(
                openidconnect::TokenUrl::new(token_url.to_owned())
                    .map_err(|err| ProviderError::Config(err.to_string()))?,
            )
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_url.clone())
                    .map_err(|err| ProviderError::Config(err.to_string()))?,
            );
        Ok(Self {
            name: config.name,
            client,
            http,
            scopes: config.scopes.into_iter().map(Scope::new).collect(),
            assurance: config.assurance,
            issuer_match: IssuerMatch::Exact(config.issuer),
        })
    }

    /// Verify an ID token's signature, issuer, audience, expiry, and nonce,
    /// enforce the assurance bar, and map its claims to a [`ResolvedIdentity`].
    /// No network. This is the security-critical core, exercised directly by
    /// tests with a locally minted token.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Verification`] or [`ProviderError::Assurance`] on failure.
    pub fn verify_claims(
        &self,
        id_token: &CoreIdToken,
        nonce: &str,
    ) -> Result<ResolvedIdentity, ProviderError> {
        let verifier = self.client.id_token_verifier();
        let verifier = if self.issuer_match.is_pattern() {
            // A pattern issuer cannot be pinned by exact string, so the verifier
            // skips the issuer check and we validate the pattern ourselves below.
            verifier.require_issuer_match(false)
        } else {
            verifier
        };
        let nonce = Nonce::new(nonce.to_owned());
        let claims = id_token
            .claims(&verifier, &nonce)
            .map_err(|err| ProviderError::Verification(err.to_string()))?;

        let issuer = claims.issuer().as_str().to_owned();
        if !self.issuer_match.matches(&issuer) {
            return Err(ProviderError::Verification(format!(
                "issuer {issuer} not accepted by provider {}",
                self.name
            )));
        }

        let acr = claims
            .auth_context_ref()
            .map(AuthenticationContextClass::as_ref);
        let amr_owned: Vec<String> = claims
            .auth_method_refs()
            .map(|refs| refs.iter().map(|method| (**method).clone()).collect())
            .unwrap_or_default();
        let amr: Vec<&str> = amr_owned.iter().map(String::as_str).collect();
        if !self.assurance.is_satisfied(acr, &amr) {
            return Err(ProviderError::Assurance(format!(
                "acr {acr:?} amr {amr:?} do not meet the bar"
            )));
        }

        let email = claims.email().map(|email| email.as_str().to_owned());
        let name = claims
            .name()
            .and_then(|localized| localized.get(None))
            .map(|name| name.as_str().to_owned());
        Ok(ResolvedIdentity {
            issuer,
            subject: claims.subject().as_str().to_owned(),
            email,
            name,
            amr: amr_owned,
            acr: acr.map(str::to_owned),
        })
    }
}

fn retained_from(
    issuer: String,
    access_token: &AccessToken,
    refresh_token: Option<&RefreshToken>,
    expires_in: Option<std::time::Duration>,
) -> RetainedProviderToken {
    RetainedProviderToken {
        issuer,
        access_token: access_token.secret().clone(),
        refresh_token: refresh_token.map(|token| token.secret().clone()),
        expires_at: expires_in.map(|delta| SystemTime::now() + delta),
    }
}

impl IdentityProvider for GenericOidcProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self) -> &str {
        self.issuer_match.index_key()
    }

    fn matches_issuer(&self, issuer: &str) -> bool {
        self.issuer_match.matches(issuer)
    }

    fn begin_login(&self) -> Result<LoginRedirect, ProviderError> {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.scopes {
            request = request.add_scope(scope.clone());
        }
        for acr in &self.assurance.acr_values {
            request = request.add_auth_context_value(AuthenticationContextClass::new(acr.clone()));
        }
        if let Some(max_age) = self.assurance.max_age {
            request = request.set_max_age(max_age);
        }
        let (url, csrf, nonce) = request.set_pkce_challenge(challenge).url();
        Ok(LoginRedirect {
            authorize_url: url.to_string(),
            state: csrf.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
        })
    }

    fn complete_login<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: &'a str,
        nonce: &'a str,
    ) -> BoxFuture<'a, Result<VerifiedLogin, ProviderError>> {
        Box::pin(async move {
            let token_response = self
                .client
                .exchange_code(AuthorizationCode::new(code.to_owned()))
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
                .request_async(&self.http)
                .await
                .map_err(|err| ProviderError::Exchange(err.to_string()))?;
            let id_token = token_response
                .id_token()
                .ok_or(ProviderError::MissingIdToken)?;
            let identity = self.verify_claims(id_token, nonce)?;
            let retained = retained_from(
                identity.issuer.clone(),
                token_response.access_token(),
                token_response.refresh_token(),
                token_response.expires_in(),
            );
            Ok(VerifiedLogin { identity, retained })
        })
    }

    fn refresh_provider_token<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<RetainedProviderToken, ProviderError>> {
        Box::pin(async move {
            let response = self
                .client
                .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
                .request_async(&self.http)
                .await
                .map_err(|err| ProviderError::Refresh(err.to_string()))?;
            // Reuse the presented token when the provider did not rotate.
            let rotated = response
                .refresh_token()
                .map_or_else(|| refresh_token.to_owned(), |token| token.secret().clone());
            Ok(RetainedProviderToken {
                issuer: self.issuer_match.index_key().to_owned(),
                access_token: response.access_token().secret().clone(),
                refresh_token: Some(rotated),
                expires_at: response.expires_in().map(|delta| SystemTime::now() + delta),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::IssuerMatch;

    #[test]
    fn exact_issuer_matches_only_itself() {
        let matcher = IssuerMatch::Exact("https://accounts.google.com".to_owned());
        assert!(matcher.matches("https://accounts.google.com"));
        assert!(!matcher.matches("https://evil.example"));
        assert!(!matcher.is_pattern());
    }

    #[test]
    fn microsoft_matches_any_tenant() {
        let matcher = IssuerMatch::MicrosoftAnyTenant;
        assert!(matcher.is_pattern());
        assert!(matcher.matches("https://login.microsoftonline.com/tenant-abc/v2.0"));
        // Wrong host, wrong suffix, and the empty-tenant degenerate case.
        assert!(!matcher.matches("https://login.example.com/tenant/v2.0"));
        assert!(!matcher.matches("https://login.microsoftonline.com/tenant/v1.0"));
        assert!(!matcher.matches("https://login.microsoftonline.com//v2.0"));
    }
}
