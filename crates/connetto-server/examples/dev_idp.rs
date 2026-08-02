//! A standalone OIDC provider for local loops, standing in for Google or Entra.
//!
//! The reference `connetto-server` binary is a confidential OAuth client, so it
//! needs a real provider to talk to. This runs one: `oauth2-test-server`, whose
//! authorize handler auto-grants consent, so no human and no login form is
//! involved. Nothing about connetto lives in here, which is the point. The server
//! reaches it over the same discovery, token, and JWKS endpoints it would use for a
//! commercial provider.
//!
//! Client credentials are minted per start and cannot be pinned, exactly as a real
//! provider's console mints them once. So this writes them where the server can
//! read them:
//!
//! ```text
//! cargo run --example dev_idp
//! set -a && . target/dev-idp.env && set +a
//! cargo run --bin connetto-server
//! ```
//!
//! The registered redirect defaults to `http://$CONNETTO_AUTH_BIND/auth/callback`,
//! so running this and the server with the same `CONNETTO_AUTH_BIND` needs no
//! further configuration. Set `CONNETTO_DEV_IDP_CALLBACKS` to a comma-separated
//! list to override it, which a deployment behind a reverse proxy has to do: the
//! browser reaches the callback at the proxy's origin, so an app served by trunk on
//! its own port registers that port rather than the server's.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use oauth2_test_server::{AppState, IssuerConfig};
use serde_json::json;

/// Where the provider listens unless `CONNETTO_DEV_IDP_BIND` says otherwise. Fixed
/// rather than ephemeral because the server is configured with the issuer URL up
/// front, and discovery refuses an issuer that is not the URL it was fetched from.
const DEFAULT_BIND: &str = "127.0.0.1:18098";

/// `connetto-server`'s own default for `CONNETTO_AUTH_BIND`, mirrored so the
/// registered callback lands where the server actually serves it.
const DEFAULT_SERVER_AUTH_BIND: &str = "127.0.0.1:8081";

/// The provider name a client names in its login request.
const PROVIDER: &str = "dev-idp";

/// Where the credentials land unless `CONNETTO_DEV_IDP_ENV` says otherwise.
const DEFAULT_ENV_FILE: &str = "target/dev-idp.env";

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    let bind = std::env::var("CONNETTO_DEV_IDP_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_owned());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    let addr = listener.local_addr().context("reading the bound address")?;
    let issuer = format!("http://{addr}");

    // Defaulted from the same variable the server reads for its auth bind, because
    // the provider redirects the browser to the server's own callback. Deriving it
    // means the two agree by construction: a server moved to another port would
    // otherwise leave the provider redirecting to a dead one, which fails remotely
    // and late, at the provider-to-server hop.
    let auth_bind =
        std::env::var("CONNETTO_AUTH_BIND").unwrap_or_else(|_| DEFAULT_SERVER_AUTH_BIND.to_owned());
    let callbacks: Vec<String> = std::env::var("CONNETTO_DEV_IDP_CALLBACKS")
        .unwrap_or_else(|_| format!("http://{auth_bind}/auth/callback"))
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    anyhow::ensure!(
        !callbacks.is_empty(),
        "CONNETTO_DEV_IDP_CALLBACKS listed no redirect URIs"
    );

    let idp = AppState::new(IssuerConfig {
        scheme: "http".to_owned(),
        host: addr.ip().to_string(),
        port: addr.port(),
        ..IssuerConfig::default()
    });
    let client = idp
        .register_client(json!({
            "redirect_uris": callbacks.clone(),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid",
        }))
        .await
        .map_err(|err| anyhow::anyhow!("registering connetto as a client: {err:?}"))?;
    let secret = client
        .client_secret
        .clone()
        .context("the provider issued no client secret")?;

    // One callback goes into the environment, because the server holds a single
    // redirect URL. The rest stay registered so one provider can serve several
    // origins across runs.
    let env_path = PathBuf::from(
        std::env::var("CONNETTO_DEV_IDP_ENV").unwrap_or_else(|_| DEFAULT_ENV_FILE.to_owned()),
    );
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let env_file = format!(
        "CONNETTO_OIDC_PROVIDER=generic\n\
         CONNETTO_OIDC_NAME={PROVIDER}\n\
         CONNETTO_OIDC_ISSUER={issuer}\n\
         CONNETTO_OIDC_CLIENT_ID={}\n\
         CONNETTO_OIDC_CLIENT_SECRET={secret}\n\
         CONNETTO_OIDC_REDIRECT_URL={}\n",
        client.client_id, callbacks[0],
    );
    std::fs::write(&env_path, &env_file)
        .with_context(|| format!("writing {}", env_path.display()))?;

    tracing::info!(
        issuer = %issuer,
        provider = PROVIDER,
        callbacks = %callbacks.join(","),
        env_file = %env_path.display(),
        "dev idp listening"
    );
    axum::serve(listener, oauth2_test_server::router::build_router(idp))
        .await
        .context("serving")?;
    Ok(())
}
