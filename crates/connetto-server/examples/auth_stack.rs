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
//! It verifies nothing about identity, so it is a test fixture and never a
//! deployment. Its session store is in memory and its signing key is ephemeral
//! unless `DATABASE_URL` and `CONNETTO_JWT_*_KEY_FILE` point it at the ones a
//! sync server shares. Run it with:
//!
//! ```text
//! cargo run --example auth_stack
//! ```
//!
//! It prints the base URL, the provider name, and the redirect URI a client needs.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::routing::get;
use connetto_core::SessionId;
use connetto_server::{
    AssuranceRequirement, AuthConfig, AuthService, AuthStore, AuthStoreError, DbAuthStore,
    DefaultUuidResolver, GenericOidcProvider, InMemoryAuthStore, IssuedSession, OidcProviderConfig,
    ProviderRegistry, RedirectPolicy, RefreshOutcome, ResolvedIdentity, RetainedProviderToken,
    TokenAuthority, auth_router, connetto_auth_tables,
};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
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

// The same default auth tables the reference binary uses, so a shared database
// store reads and writes the rows the sync server expects.
connetto_auth_tables!(String, diesel::sql_types::Text);

/// The session store this stack runs on, mirroring the server binary's own
/// choice so the two can share one. A single concrete type keeps every awaited
/// store future `Send`.
enum ServerStore {
    /// Login-only loops: nothing else reads these sessions.
    InMemory(InMemoryAuthStore),
    /// Shared with the sync server, which checks liveness in the same rows.
    Db(DbAuthStore<ConnettoAuthSchema>),
}

impl AuthStore for ServerStore {
    type Id = String;

    async fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: std::time::SystemTime,
    ) -> Result<IssuedSession, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.create_session(identity, now).await,
            Self::Db(store) => store.create_session(identity, now).await,
        }
    }

    async fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: std::time::SystemTime,
    ) -> Result<RefreshOutcome, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.rotate_refresh(refresh_token, now).await,
            Self::Db(store) => store.rotate_refresh(refresh_token, now).await,
        }
    }

    async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthStoreError> {
        match self {
            Self::InMemory(store) => store.revoke_session(session_id).await,
            Self::Db(store) => store.revoke_session(session_id).await,
        }
    }

    async fn session_is_live(
        &self,
        session_id: SessionId,
        now: std::time::SystemTime,
    ) -> Result<bool, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.session_is_live(session_id, now).await,
            Self::Db(store) => store.session_is_live(session_id, now).await,
        }
    }

    async fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<SessionId>, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.session_for_refresh(refresh_token).await,
            Self::Db(store) => store.session_for_refresh(refresh_token).await,
        }
    }

    async fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &RetainedProviderToken,
        now: std::time::SystemTime,
    ) -> Result<(), AuthStoreError> {
        match self {
            Self::InMemory(store) => {
                store
                    .set_retained_provider_token(session_id, token, now)
                    .await
            }
            Self::Db(store) => {
                store
                    .set_retained_provider_token(session_id, token, now)
                    .await
            }
        }
    }

    async fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> Result<Option<RetainedProviderToken>, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.retained_provider_token(session_id).await,
            Self::Db(store) => store.retained_provider_token(session_id).await,
        }
    }
}

/// The token signing keypair, shared with a sync server when
/// `CONNETTO_JWT_PRIVATE_KEY_FILE` and `CONNETTO_JWT_PUBLIC_KEY_FILE` name one.
fn load_authority(config: &AuthConfig) -> Result<TokenAuthority> {
    let (Ok(private), Ok(public)) = (
        std::env::var("CONNETTO_JWT_PRIVATE_KEY_FILE"),
        std::env::var("CONNETTO_JWT_PUBLIC_KEY_FILE"),
    ) else {
        println!("  key          ephemeral (set CONNETTO_JWT_*_KEY_FILE to share one)");
        return TokenAuthority::generate(config).map_err(|err| anyhow::anyhow!("keypair: {err}"));
    };
    let private_pem =
        std::fs::read(&private).with_context(|| format!("reading the private key at {private}"))?;
    let public_pem =
        std::fs::read(&public).with_context(|| format!("reading the public key at {public}"))?;
    TokenAuthority::from_ed_pem(&private_pem, &public_pem, config)
        .map_err(|err| anyhow::anyhow!("loading the signing keypair: {err}"))
}

/// The auth service, sharing a session store with a sync server when
/// `DATABASE_URL` names one.
async fn build_service(
    authority: TokenAuthority,
    config: &AuthConfig,
) -> Result<Arc<AuthService<ServerStore>>> {
    let authority = Arc::new(authority);
    let Ok(url) = std::env::var("DATABASE_URL") else {
        println!("  store        in-memory (set DATABASE_URL to share one)");
        return Ok(Arc::new(AuthService::new(
            authority,
            Arc::new(ServerStore::InMemory(InMemoryAuthStore::new(
                config.refresh_lifetimes(),
            ))),
        )));
    };
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder()
        .build(manager)
        .await
        .context("building the Postgres pool for the shared session store")?;
    Ok(Arc::new(AuthService::new(
        authority,
        Arc::new(ServerStore::Db(DbAuthStore::new(
            pool,
            config.refresh_lifetimes(),
            Arc::new(DefaultUuidResolver),
        ))),
    )))
}

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
        },
        &format!("{base}/authorize"),
        &format!("{base}/token"),
        jwks,
        openidconnect::reqwest::Client::new(),
    )
    .map_err(|err| anyhow::anyhow!("building the provider: {err}"))?;

    let config = AuthConfig::default();
    // The sync server verifies what this stack mints, so the two must agree on
    // both halves: the signing key (a signature check) and the session store (a
    // liveness check). Point both processes at the same key files and the same
    // Postgres and a token minted here opens a handshake there. With neither
    // set this falls back to an ephemeral key and an in-memory store, which
    // suits a login-only loop where nothing syncs.
    let service = build_service(load_authority(&config)?, &config).await?;

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
