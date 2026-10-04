//! The connetto sync server as a runnable process.
//!
//! The binary is a translation from its environment into a
//! [`ServerBuilder`], which owns the assembly, and from its signal surface
//! into the process outcome. It reads every setting, hands over the named
//! collaborators, binds the one listener, and serves through the builder's
//! own lifecycle. It owns what a process owns and a library must not own:
//! the logging, the shutdown signal, and the exit code.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_BIND` (default `127.0.0.1:8080`): the one listener that
//!   serves the `/sync` WebSocket route, the login endpoints, and the file
//!   routes.
//! - `DATABASE_URL`: the owner conninfo, a role that may create and read the
//!   replication slot.
//! - `CONNETTO_READER_URL`: a non-superuser conninfo subject to row-level
//!   security. Every read a caller touches and every replica snapshot goes
//!   through this role, so connetto never serves reads or writes from the
//!   owner pool.
//! - `CONNETTO_PG_DDL` or `CONNETTO_PG_DDL_FILE`: the catalog DDL.
//! - `CONNETTO_PG_POLICIES` or `CONNETTO_PG_POLICIES_FILE`: the read
//!   policies. Both are translated and hashed into the schema version the
//!   server presents at handshake.
//! - `CONNETTO_WRITABLE`: the tables clients may write, one per entry, each
//!   `table` or `table:version_column` for conflict-checked updates.
//! - `CONNETTO_SLOT` (default `connetto_slot`), `CONNETTO_PUBLICATION`
//!   (default `connetto_pub`), `CONNETTO_OPLOG_TABLE` (default
//!   `connetto_oplog`): the replication objects and the reconnect log.
//! - `CONNETTO_OWNER_POOL_SIZE` (default `10`): the owner pool's size.
//! - `CONNETTO_READER_POOL_SIZE` (default `10`) and
//!   `CONNETTO_READER_RESERVE` (default `3`): the reader pool's size and the
//!   share the change path holds back from callers.
//! - `CONNETTO_SLOT_LAG_SECS` (default `60`, `0` turning the watch off): how
//!   far behind the owner's timeline the slot may run before one warning
//!   fires.
//! - `CONNETTO_AUTH`: the login machinery. Only `database` is served, which
//!   stores sessions and provider tokens in Postgres and signs users in
//!   through the identity providers below.
//! - `CONNETTO_AUDIT`: set to `database` to record every access change in
//!   the application's own table.
//! - `CONNETTO_JWT_PRIVATE_KEY_FILE` and `CONNETTO_JWT_PUBLIC_KEY_FILE`:
//!   the persisted Ed25519 signing keypair, PKCS8 PEM, required. A token
//!   minted under one key must verify after a restart, so the deployment
//!   keeps the key on disk.
//! - `CONNETTO_OIDC_PROVIDERS`: a comma-separated list of provider names,
//!   each configured under its own `CONNETTO_OIDC_<NAME>_KIND`
//!   (`google`, `microsoft` or `generic`), `_CLIENT_ID`, `_CLIENT_SECRET`,
//!   `_REDIRECT_URL`, optional `_ISSUER` and `_SCOPES`, the name upper-cased
//!   with everything outside letters and digits turned into underscores.
//! - `CONNETTO_BANS`: set to `database` to ban identities that cross an
//!   abuse threshold.
//! - `CONNETTO_FGA_URL` (default `http://127.0.0.1:8081`): the
//!   authorization endpoint.
//! - `CONNETTO_FGA_STORE`: required. The authorization store the deployment
//!   owns, which connetto fills with the rules it derives from the policies.
//! - `CONNETTO_AUTH_COOKIE_SAMESITE` (default `strict`, or `none` for a
//!   cross-origin deployment): the session cookie's same-site policy.
//! - `CONNETTO_AUTH_REDIRECT_ALLOWLIST`: a comma-separated list of exact
//!   redirect URIs the deployment serves beyond the providers'.
//! - `CONNETTO_AUTH_CORS_ORIGINS`: a comma-separated list of origins whose
//!   login requests carry credentials.
//! - `CONNETTO_CONTENT_URL` (unset serving no files): the address the file
//!   routes answer on. With it set, `CONNETTO_CONTENT_STORE` (required,
//!   `fs:<dir>` or an `object_store` URL) and `CONNETTO_CONTENT_KEY`
//!   (required, the ticket keypair as PKCS8 DER) are required, alongside
//!   `CONNETTO_CONTENT_TICKET_TTL_SECS` (default `3600`),
//!   `CONNETTO_CONTENT_READ_CEILING` (default `67108864`),
//!   `CONNETTO_CONTENT_SWEEP_GRACE_SECS` (default the ticket lifetime),
//!   `CONNETTO_CONTENT_SWEEP_SECS` (default `3600`, `0` turning the sweep
//!   off), `CONNETTO_CONTENT_QUOTA_BYTES` (default `0`, unlimited),
//!   `CONNETTO_CONTENT_STORAGE_CEILING` (default `0`),
//!   `CONNETTO_CONTENT_BANDWIDTH_CEILING` (default `0`),
//!   `CONNETTO_CONTENT_BANDWIDTH_WINDOW_DAYS` (default `30`),
//!   `CONNETTO_CONTENT_WARN_FRACTION` (default `0.8`) and
//!   `CONNETTO_CONTENT_CEILING_REFRESH_SECS` (default `10`).
//!
//! The process exits `1` when the change stream cannot answer what a row
//! looked like before it changed, or gives up reconnecting, and returns its
//! build or HTTP errors as failures.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use connetto_core::env::{read_ddl, var_or};
use connetto_server::builder::{
    ContentSettings, Database, OidcProvider, OpenFga, ServeError, ServerBuilder, ServerSchema,
    StoreSpec, TokenKeys,
};
use connetto_server::{
    AuthConfig, CookieSameSite, OidcProviderConfig, ReaderReserve, RuntimeWritableCatalog,
};
use tokio::net::TcpListener;

/// Read a `u32` from `<key>`, or `default` when unset.
fn env_u32(key: &str, default: u32) -> Result<u32> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(text) => text
            .trim()
            .parse()
            .with_context(|| format!("parsing {key}: {text:?}")),
    }
}

/// Read a `u64` from `<key>`, or `default` when unset.
fn env_u64(key: &str, default: u64) -> Result<u64> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(text) => text
            .trim()
            .parse()
            .with_context(|| format!("parsing {key}: {text:?}")),
    }
}

/// The value of `<key>` when it is set to something other than blank.
fn var_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Split a comma-separated setting into its trimmed non-empty entries.
fn comma_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `key` asks for the database-backed table it names.
///
/// Off unless switched on: the table belongs to the application and connetto
/// emits no DDL, so a server pointed at a database without it must not
/// attempt reads or writes.
fn database_toggle(key: &str) -> Result<bool> {
    match var_or(key, "").as_str() {
        "" => Ok(false),
        "database" => Ok(true),
        other => Err(anyhow!("unknown {key} mode {other:?}, expected database")),
    }
}

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
    let scopes = var_or(&format!("CONNETTO_OIDC_{prefix}_SCOPES"), "")
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
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
    .with_scopes(scopes))
}

/// The identity providers `CONNETTO_OIDC_PROVIDERS` names, each from its own
/// `CONNETTO_OIDC_<NAME>_*` settings. Discovery happens in the build, so this
/// reads settings only.
fn oidc_providers() -> Result<Vec<OidcProvider>> {
    let names = comma_list(&var_or("CONNETTO_OIDC_PROVIDERS", ""));
    if names.is_empty() {
        return Err(anyhow!(
            "CONNETTO_OIDC_PROVIDERS is unset, expected a comma-separated list of provider names, \
             each configured under CONNETTO_OIDC_<NAME>_*"
        ));
    }
    let mut prefixes: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut providers = Vec::with_capacity(names.len());
    let config = AuthConfig::default();
    for name in &names {
        let prefix = env_prefix(name);
        if let Some(other) = prefixes.insert(prefix.clone(), name.clone()) {
            return Err(anyhow!(
                "providers {other:?} and {name:?} both read CONNETTO_OIDC_{prefix}_*"
            ));
        }
        let kind = var_or(&format!("CONNETTO_OIDC_{prefix}_KIND"), "");
        let provider_config = oidc_config_from_env(&config, name, &prefix)?;
        let provider = match kind.as_str() {
            "google" => OidcProvider::Google(provider_config),
            "microsoft" => OidcProvider::Microsoft(provider_config),
            "generic" => OidcProvider::Generic(provider_config),
            "" => {
                return Err(anyhow!(
                    "set CONNETTO_OIDC_{prefix}_KIND for provider {name:?} to google, microsoft \
                     or generic"
                ));
            }
            other => {
                return Err(anyhow!(
                    "unknown CONNETTO_OIDC_{prefix}_KIND {other:?} for provider {name:?}, \
                     expected google, microsoft or generic"
                ));
            }
        };
        providers.push(provider);
    }
    Ok(providers)
}

/// The persisted JWT keypair, both halves required.
fn jwt_keys() -> Result<TokenKeys> {
    let private_path = std::env::var("CONNETTO_JWT_PRIVATE_KEY_FILE").context(
        "set CONNETTO_JWT_PRIVATE_KEY_FILE to the PKCS8 PEM private half of the signing keypair",
    )?;
    let public_path = std::env::var("CONNETTO_JWT_PUBLIC_KEY_FILE").context(
        "set CONNETTO_JWT_PUBLIC_KEY_FILE to the PKCS8 PEM public half of the signing keypair",
    )?;
    let private =
        std::fs::read(&private_path).with_context(|| format!("reading {private_path}"))?;
    let public = std::fs::read(&public_path).with_context(|| format!("reading {public_path}"))?;
    Ok(TokenKeys::from_pem(private, public))
}

/// The reader pool's size and the share of it the change path holds back.
fn reader_reserve() -> Result<ReaderReserve> {
    let total = env_u32("CONNETTO_READER_POOL_SIZE", ReaderReserve::DEFAULT_TOTAL)?;
    let reserved = env_u32("CONNETTO_READER_RESERVE", ReaderReserve::DEFAULT_RESERVED)?;
    if reserved > total {
        return Err(anyhow!(
            "CONNETTO_READER_RESERVE={reserved} cannot exceed CONNETTO_READER_POOL_SIZE={total}"
        ));
    }
    Ok(ReaderReserve::new()
        .with_total(total)
        .with_reserved(reserved))
}

/// The session cookie's same-site policy from `CONNETTO_AUTH_COOKIE_SAMESITE`.
fn cookie_same_site() -> Result<CookieSameSite> {
    let value = var_or("CONNETTO_AUTH_COOKIE_SAMESITE", "strict");
    CookieSameSite::parse(&value).ok_or_else(|| {
        anyhow!("unknown CONNETTO_AUTH_COOKIE_SAMESITE {value:?}, expected strict or none")
    })
}

/// Parse `CONNETTO_WRITABLE` into a runtime write policy. Each comma-separated
/// entry is a table, or `table:version_column` to conflict-check version-bearing
/// updates and deletes on that table. Unset or empty yields no writable tables,
/// so every client mutation is rejected.
fn writable_catalog() -> RuntimeWritableCatalog {
    let spec = var_or("CONNETTO_WRITABLE", "");
    let mut builder = RuntimeWritableCatalog::builder();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        builder = match entry.split_once(':') {
            Some((table, version)) => builder.versioned(table.trim(), version.trim()),
            None => builder.writable(entry),
        };
    }
    builder.build()
}

/// The resolved `CONNETTO_CONTENT_*` settings, or `None` when the deployment
/// serves no files.
async fn content_settings() -> Result<Option<ContentSettings>> {
    let Some(base_url) = var_nonempty("CONNETTO_CONTENT_URL") else {
        return Ok(None);
    };
    if base_url.contains('?') || base_url.contains('#') {
        return Err(anyhow!(
            "CONNETTO_CONTENT_URL must carry no query or fragment, only the address the file \
             routes answer on: {base_url}"
        ));
    }
    let store = StoreSpec::parse(
        &var_nonempty("CONNETTO_CONTENT_STORE")
            .context("set CONNETTO_CONTENT_STORE to fs:<dir> or an object_store URL")?,
    )
    .context("parsing CONNETTO_CONTENT_STORE")?;
    let key_path = var_nonempty("CONNETTO_CONTENT_KEY")
        .context("set CONNETTO_CONTENT_KEY to the PKCS8 DER ticket keypair, required once CONNETTO_CONTENT_URL is set")?;
    // Spawned because startup runs on the async runtime, and one key file is
    // worth the round trip off the worker thread.
    let shown = key_path.clone();
    let key = tokio::task::spawn_blocking(move || std::fs::read(&shown))
        .await
        .map_err(|err| anyhow!("joining the key read: {err}"))?
        .with_context(|| format!("reading {key_path}"))?;
    let ttl = Duration::from_secs(env_u64("CONNETTO_CONTENT_TICKET_TTL_SECS", 3_600)?);
    Ok(Some(ContentSettings {
        base_url: base_url.trim_end_matches('/').to_owned(),
        ttl,
        read_ceiling: env_u64("CONNETTO_CONTENT_READ_CEILING", 1 << 26)?,
        grace: Duration::from_secs(env_u64("CONNETTO_CONTENT_SWEEP_GRACE_SECS", ttl.as_secs())?),
        cadence: Duration::from_secs(env_u64("CONNETTO_CONTENT_SWEEP_SECS", 3_600)?),
        quota_identity: env_u64("CONNETTO_CONTENT_QUOTA_BYTES", 0)?,
        storage_ceiling: env_u64("CONNETTO_CONTENT_STORAGE_CEILING", 0)?,
        bandwidth_ceiling: env_u64("CONNETTO_CONTENT_BANDWIDTH_CEILING", 0)?,
        bandwidth_window_days: {
            let days = env_u64("CONNETTO_CONTENT_BANDWIDTH_WINDOW_DAYS", 30)?;
            i32::try_from(days).map_err(|_| {
                anyhow!("CONNETTO_CONTENT_BANDWIDTH_WINDOW_DAYS={days} is out of range")
            })?
        },
        warn_fraction: match std::env::var("CONNETTO_CONTENT_WARN_FRACTION") {
            Err(_) => 0.8,
            Ok(text) => text
                .trim()
                .parse::<f64>()
                .map(|fraction| fraction.clamp(0.0, 1.0))
                .with_context(|| format!("parsing CONNETTO_CONTENT_WARN_FRACTION: {text:?}"))?,
        },
        ceiling_refresh: Duration::from_secs(env_u64("CONNETTO_CONTENT_CEILING_REFRESH_SECS", 10)?),
        owner_pool_size: env_u32("CONNETTO_OWNER_POOL_SIZE", 10)?,
        store,
        key,
    }))
}

/// The builder from the environment, every setting read once at startup.
///
/// # Errors
///
/// When any setting is absent, blank, or names a mode this binary no longer
/// serves.
async fn builder_from_env() -> Result<ServerBuilder> {
    let auth = var_or("CONNETTO_AUTH", "");
    match auth.as_str() {
        "database" => {}
        "" => {
            return Err(anyhow!(
                "set CONNETTO_AUTH to database: the server refuses to run without the login \
                 machinery, because it would otherwise have no way to check a grant or to sign \
                 the credential a run resumes on"
            ));
        }
        other => {
            return Err(anyhow!(
                "unknown CONNETTO_AUTH mode {other:?}, expected database"
            ));
        }
    }
    let audit = database_toggle("CONNETTO_AUDIT")?;
    let bans = database_toggle("CONNETTO_BANS")?;
    let database = Database::new(
        std::env::var("DATABASE_URL").context("set DATABASE_URL")?,
        std::env::var("CONNETTO_READER_URL").map_err(|_| {
            anyhow!(
                "set CONNETTO_READER_URL to a non-superuser conninfo subject to row-level \
                 security: connetto serves no reads or writes from the owner pool"
            )
        })?,
    );
    let schema = ServerSchema::new(
        read_ddl("CONNETTO_PG_DDL")?,
        read_ddl("CONNETTO_PG_POLICIES")?,
    );
    let providers = oidc_providers()?;
    let keys = jwt_keys()?;
    let content = content_settings().await?;
    let openfga = OpenFga::new(
        var_or("CONNETTO_FGA_URL", "http://127.0.0.1:8081"),
        std::env::var("CONNETTO_FGA_STORE").map_err(|_| {
            anyhow!("set CONNETTO_FGA_STORE to the authorization store this deployment owns")
        })?,
    );
    Ok(ServerBuilder::new(database, schema, keys, openfga)
        .slot(var_or("CONNETTO_SLOT", "connetto_slot"))
        .publication(var_or("CONNETTO_PUBLICATION", "connetto_pub"))
        .oplog_table(var_or("CONNETTO_OPLOG_TABLE", "connetto_oplog"))
        .owner_pool_size(env_u32("CONNETTO_OWNER_POOL_SIZE", 10)?)
        .slot_lag_watch(Duration::from_secs(u64::from(env_u32(
            "CONNETTO_SLOT_LAG_SECS",
            60,
        )?)))
        .reader_reserve(reader_reserve()?)
        .oidc_providers(providers)
        .audit(audit)
        .bans(bans)
        .redirect_allowlist(comma_list(&var_or("CONNETTO_AUTH_REDIRECT_ALLOWLIST", "")))
        .cors_origins(comma_list(&var_or("CONNETTO_AUTH_CORS_ORIGINS", "")))
        .cookie_same_site(cookie_same_site()?)
        .writable(writable_catalog())
        .content(content))
}

/// Resolve on the first SIGINT or SIGTERM. On a platform without SIGTERM only
/// the interrupt arm can fire.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "no SIGTERM handler, interrupt only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // `pg_walstream` reports every standby status update at `info`, which is
    // one line per ten seconds whether or not anything happened, and it
    // buries this server's own events. `RUST_LOG` brings it back.
    connetto_core::logging::init_stdout_with_default("info,pg_walstream=warn");
    let builder = builder_from_env().await?;
    let bind = var_or("CONNETTO_BIND", "127.0.0.1:8080");
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(bind = %bind, "serving the sync, login and file routes");
    match builder.serve(listener, shutdown_signal()).await {
        Ok(()) => Ok(()),
        Err(err @ ServeError::ChangeStreamUnusable(_)) => {
            tracing::error!(error = %err, "the change stream cannot answer, refusing to serve");
            std::process::exit(1);
        }
        Err(err @ ServeError::ChangeStreamStopped(_)) => {
            tracing::error!(error = %err, "the change stream stopped, refusing to serve");
            std::process::exit(1);
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comma_lists_trim_and_drop_empties() {
        assert_eq!(
            comma_list(" a , ,b ,c,, "),
            vec!["a", "b", "c"],
            "entries are trimmed and blanks dropped"
        );
        assert_eq!(
            comma_list(""),
            Vec::<String>::new(),
            "blank reads as nothing"
        );
        assert_eq!(
            comma_list("   "),
            Vec::<String>::new(),
            "whitespace reads as nothing"
        );
    }
}
