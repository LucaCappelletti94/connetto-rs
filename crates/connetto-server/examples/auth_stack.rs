//! A single-origin authentication stack for browser tests and local loops.
//!
//! Phase E4.b needs a login a real browser can complete, and a wasm test cannot
//! bind a listener, so the stack has to be an external process. This is it: one
//! axum app, on one port, serving three things.
//!
//! * A real OIDC provider, `oauth2-test-server`, whose authorize handler
//!   auto-grants consent, so no human and no login form is involved.
//! * connetto's own auth endpoints, `/auth/login`, `/auth/callback`,
//!   `/auth/token`, `/auth/refresh`, and `/auth/logout`.
//! * A landing route the client redirect points at, so the whole redirect chain
//!   stays on this one origin and a browser test can read the delivered code out
//!   of the final URL rather than navigating a tab away mid-test.
//!
//! One origin is the point. The OAuth dance itself needs no CORS, since every
//! step is a navigation or a server-to-server call, but connetto's own
//! `/auth/token`, `/auth/refresh`, and `/auth/logout` are `fetch` calls from the
//! DB worker, and a browser test page is served from a port of its own. So
//! connetto's routes carry a permissive [`CorsLayer`] here. That layer belongs to
//! this dev stack and not to the library: `auth_router` returns a plain
//! [`Router`], and a deployment that puts its app and its auth endpoints on
//! different origins is the one that has to decide how to bridge them.
//!
//! It verifies nothing about identity and holds an in-memory store, so it is a
//! test fixture and never a deployment. Run it with:
//!
//! ```text
//! cargo run --example auth_stack
//! ```
//!
//! It prints the base URL, the provider name, and the redirect URI a client needs.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::routing::get;
use connetto_server::{
    AssuranceRequirement, AuthConfig, AuthService, GenericOidcProvider, InMemoryAuthStore,
    OidcProviderConfig, ProviderRegistry, RedirectPolicy, TokenAuthority, auth_router,
};
use oauth2_test_server::{AppState, IssuerConfig};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};

/// The provider name a client names in its login request.
const PROVIDER: &str = "dev-idp";

/// Where the stack listens unless `CONNETTO_AUTH_STACK_BIND` says otherwise. It is
/// fixed rather than ephemeral because a browser test cannot be told a random port.
const DEFAULT_BIND: &str = "127.0.0.1:18099";
/// The path the client redirect points at. Serving it here keeps the redirect
/// chain single-origin.
const LANDING_PATH: &str = "/dev/landing";

#[tokio::main]
async fn main() -> Result<()> {
    let bind =
        std::env::var("CONNETTO_AUTH_STACK_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    let addr = listener.local_addr().context("reading the bound address")?;
    let base = format!("http://{addr}");

    // The provider is configured to publish this very origin, because
    // `openidconnect` refuses a discovery document whose `issuer` does not equal
    // the URL it was fetched from, and because the provider's routes are about to
    // be merged into this same app.
    let idp = AppState::new(IssuerConfig {
        scheme: "http".to_owned(),
        host: addr.ip().to_string(),
        port: addr.port(),
        ..IssuerConfig::default()
    });

    let callback = format!("{base}/auth/callback");
    let client = idp
        .register_client(json!({
            "redirect_uris": [callback.clone()],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid",
        }))
        .await
        .map_err(|err| anyhow::anyhow!("registering connetto as a client: {err:?}"))?;

    // Built from endpoints rather than by discovery, because the endpoints live in
    // the app that is not serving yet, and discovery would have nothing to talk
    // to. Discovery itself is covered by `tests/oidc_spine.rs`.
    let jwks = serde_json::from_value((*idp.jwks_json).clone())
        .context("reading the provider's JWKS into a key set")?;
    let provider = GenericOidcProvider::from_parts(
        OidcProviderConfig {
            name: PROVIDER.to_owned(),
            client_id: client.client_id.clone(),
            client_secret: client.client_secret.clone(),
            issuer: base.clone(),
            redirect_url: callback.clone(),
            scopes: Vec::new(),
            // The provider issues no `amr` or `acr`, so a bar it cannot express
            // would refuse every login. The bar itself is covered by
            // `tests/provider.rs`.
            assurance: AssuranceRequirement::none(),
            tenant_id: None,
        },
        &format!("{base}/authorize"),
        &format!("{base}/token"),
        jwks,
        openidconnect::reqwest::Client::new(),
    )
    .map_err(|err| anyhow::anyhow!("building the provider: {err}"))?;

    let config = AuthConfig::default();
    let authority =
        TokenAuthority::generate(&config).map_err(|err| anyhow::anyhow!("keypair: {err}"))?;
    let service = Arc::new(AuthService::new(
        Arc::new(authority),
        Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes())),
    ));
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(provider));

    // Permissive on purpose, and scoped to connetto's routes plus the landing:
    // the provider's own router already carries its own CORS layer, and stacking
    // two would emit duplicate headers that a browser rejects.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let connetto = auth_router(service, Arc::new(registry), RedirectPolicy::default())
        .route(
            LANDING_PATH,
            get(|| async { "connetto dev landing: the code is in this URL" }),
        )
        .layer(cors);

    let app = oauth2_test_server::router::build_router(idp).merge(connetto);

    println!("connetto auth stack on {base}");
    println!("  provider     {PROVIDER}");
    println!("  redirect_uri {base}{LANDING_PATH}");
    println!("  issuer       {base}");
    axum::serve(listener, app).await.context("serving")?;
    Ok(())
}
