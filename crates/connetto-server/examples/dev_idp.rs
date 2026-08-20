//! A standalone OIDC provider for local loops, standing in for Google or Entra.
//!
//! The reference `connetto-server` binary is a confidential OAuth client, so it
//! needs a real provider to talk to. This starts the same containerised mock the
//! tests use. The provider serves discovery, tokens and keys over HTTP, and its
//! login form lets a browser choose the subject.
//!
//! The helper writes the environment the server reads:
//!
//! ```text
//! cargo run --example dev_idp
//! set -a && . target/dev-idp.env && set +a
//! cargo run --bin connetto-server
//! ```
//!
//! The redirect defaults to `http://$CONNETTO_AUTH_BIND/auth/callback`, so the
//! provider and server agree when they use the same `CONNETTO_AUTH_BIND`.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use connetto_test_harness::{MOCK_OAUTH_CLIENT_ID, MOCK_OAUTH_CLIENT_SECRET, MockOauth};

/// `connetto-server`'s own default for `CONNETTO_AUTH_BIND`, mirrored so the
/// callback lands where the server serves it.
const DEFAULT_SERVER_AUTH_BIND: &str = "127.0.0.1:8081";

/// The provider name a client names in its login request.
const PROVIDER: &str = "dev-idp";

/// Where the credentials land unless `CONNETTO_DEV_IDP_ENV` says otherwise.
const DEFAULT_ENV_FILE: &str = "target/dev-idp.env";

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();

    let auth_bind =
        std::env::var("CONNETTO_AUTH_BIND").unwrap_or_else(|_| DEFAULT_SERVER_AUTH_BIND.to_owned());
    let callback = format!("http://{auth_bind}/auth/callback");
    let idp = MockOauth::start().await;

    let env_path = PathBuf::from(
        std::env::var("CONNETTO_DEV_IDP_ENV").unwrap_or_else(|_| DEFAULT_ENV_FILE.to_owned()),
    );
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let env_file = format!(
        "CONNETTO_OIDC_PROVIDERS={PROVIDER}\n\
         CONNETTO_OIDC_DEV_IDP_KIND=generic\n\
         CONNETTO_OIDC_DEV_IDP_ISSUER={}\n\
         CONNETTO_OIDC_DEV_IDP_CLIENT_ID={MOCK_OAUTH_CLIENT_ID}\n\
         CONNETTO_OIDC_DEV_IDP_CLIENT_SECRET={MOCK_OAUTH_CLIENT_SECRET}\n\
         CONNETTO_OIDC_DEV_IDP_REDIRECT_URL={callback}\n",
        idp.issuer(),
    );
    std::fs::write(&env_path, &env_file)
        .with_context(|| format!("writing {}", env_path.display()))?;

    tracing::info!(
        issuer = %idp.issuer(),
        provider = PROVIDER,
        callback = %callback,
        env_file = %env_path.display(),
        "dev idp listening"
    );

    tokio::signal::ctrl_c()
        .await
        .context("waiting for shutdown")?;
    Ok(())
}
