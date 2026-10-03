//! The connetto server embedded in an application's own axum router.
//!
//! The example reads the environment the `connetto-server` binary reads at
//! minimum (the two database roles, the schema documents, the persisted
//! signing keypair, the authorization endpoint and store, the identity
//! providers, and `CONNETTO_BIND`), builds the [`ServerBuilder`] parts, and
//! mounts them beside a route of its own, so the application serves the sync,
//! login and file routes from its own listener.

use anyhow::{Context, Result, anyhow};
use connetto_core::env::{read_ddl, var_or};
use connetto_server::builder::{
    Database, OidcProvider, OpenFga, ServerBuilder, ServerSchema, TokenKeys,
};
use connetto_server::{AuthConfig, OidcProviderConfig};
use tokio::net::TcpListener;

/// The environment prefix a provider's settings live under: the name upper-cased
/// with everything outside `A-Z0-9` turned into an underscore, so a name like
/// `dev-idp` reads `CONNETTO_OIDC_DEV_IDP_*`.
fn env_prefix(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// One provider's configuration from its own `CONNETTO_OIDC_<NAME>_*` settings.
fn oidc_config_from_env(
    config: &AuthConfig,
    name: &str,
    prefix: &str,
) -> Result<OidcProviderConfig> {
    let client_id = std::env::var(format!("CONNETTO_OIDC_{prefix}_CLIENT_ID"))
        .with_context(|| format!("set CONNETTO_OIDC_{prefix}_CLIENT_ID for provider {name:?}"))?;
    let redirect =
        std::env::var(format!("CONNETTO_OIDC_{prefix}_REDIRECT_URL")).with_context(|| {
            format!("set CONNETTO_OIDC_{prefix}_REDIRECT_URL for provider {name:?}")
        })?;
    Ok(OidcProviderConfig::new(
        name,
        client_id,
        var_or(&format!("CONNETTO_OIDC_{prefix}_ISSUER"), config.issuer()),
        redirect,
    )
    .with_client_secret(std::env::var(format!("CONNETTO_OIDC_{prefix}_CLIENT_SECRET")).ok())
    .with_scopes(
        var_or(&format!("CONNETTO_OIDC_{prefix}_SCOPES"), "")
            .split(',')
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    ))
}

/// The identity providers `CONNETTO_OIDC_PROVIDERS` names, each from its own
/// `CONNETTO_OIDC_<NAME>_*` settings.
fn oidc_providers() -> Result<Vec<OidcProvider>> {
    let names = var_or("CONNETTO_OIDC_PROVIDERS", "")
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Err(anyhow!(
            "CONNETTO_OIDC_PROVIDERS is unset, expected a comma-separated list of provider names"
        ));
    }
    let config = AuthConfig::default();
    names
        .iter()
        .map(|name| {
            let prefix = env_prefix(name);
            let kind = var_or(&format!("CONNETTO_OIDC_{prefix}_KIND"), "");
            let provider_config = oidc_config_from_env(&config, name, &prefix)?;
            Ok(match kind.as_str() {
                "google" => OidcProvider::Google(provider_config),
                "microsoft" => OidcProvider::Microsoft(provider_config),
                "generic" => OidcProvider::Generic(provider_config),
                other => {
                    return Err(anyhow!(
                        "unknown CONNETTO_OIDC_{prefix}_KIND {other:?} for provider {name:?}, \
                         expected google, microsoft or generic"
                    ));
                }
            })
        })
        .collect()
}

/// The persisted JWT keypair, both halves required.
fn jwt_keys() -> Result<TokenKeys> {
    let private_path = std::env::var("CONNETTO_JWT_PRIVATE_KEY_FILE")
        .context("set CONNETTO_JWT_PRIVATE_KEY_FILE to the PKCS8 PEM private half")?;
    let public_path = std::env::var("CONNETTO_JWT_PUBLIC_KEY_FILE")
        .context("set CONNETTO_JWT_PUBLIC_KEY_FILE to the PKCS8 PEM public half")?;
    let private =
        std::fs::read(&private_path).with_context(|| format!("reading {private_path}"))?;
    let public = std::fs::read(&public_path).with_context(|| format!("reading {public_path}"))?;
    Ok(TokenKeys::from_pem(private, public))
}

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout_with_default("info,pg_walstream=warn");
    let database = Database::new(
        std::env::var("DATABASE_URL").context("set DATABASE_URL")?,
        std::env::var("CONNETTO_READER_URL")
            .map_err(|_| anyhow!("set CONNETTO_READER_URL to the non-superuser role"))?,
    );
    let schema = ServerSchema::new(
        read_ddl("CONNETTO_PG_DDL")?,
        read_ddl("CONNETTO_PG_POLICIES")?,
    );
    let keys = jwt_keys()?;
    let openfga = OpenFga::new(
        var_or("CONNETTO_FGA_URL", "http://127.0.0.1:8081"),
        std::env::var("CONNETTO_FGA_STORE").map_err(|_| anyhow!("set CONNETTO_FGA_STORE"))?,
    );
    let builder =
        ServerBuilder::new(database, schema, keys, openfga).oidc_providers(oidc_providers()?);
    let parts = builder.build().await?;
    // The application's own route beside the sync, login and file routes.
    let router = parts
        .router
        .route("/app/ping", axum::routing::get(|| async { "pong" }));
    let bind = var_or("CONNETTO_BIND", "127.0.0.1:8080");
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(bind = %bind, "serving");
    let mut change_stream = tokio::spawn(parts.change_stream);
    tokio::select! {
        outcome = &mut change_stream => {
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::error!(error = %err, "the change stream stopped"),
                Err(err) => tracing::error!(error = %err, "the change stream task failed"),
            }
            let closed = parts.handle.shutdown().await;
            tracing::info!(closed, "the change stream ended, shutting down");
        }
        _ = tokio::signal::ctrl_c() => {
            let closed = parts.handle.shutdown().await;
            tracing::info!(closed, "shutting down");
            change_stream.abort();
        }
        outcome = axum::serve(listener, router) => {
            if let Err(err) = outcome {
                tracing::error!(error = %err, "the listener stopped");
            }
            parts.handle.shutdown().await;
            change_stream.abort();
        }
    }
    Ok(())
}
