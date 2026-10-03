//! The connetto sync client as a runnable process.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_SERVER`: server WebSocket URL (default `ws://127.0.0.1:8080/`),
//!   `wss://` anywhere and plain `ws://` only to a loopback host.
//! - `CONNETTO_SCHEMA_SQL` or `CONNETTO_SCHEMA_SQL_FILE`: the Postgres schema
//!   the server serves (required). The client translates it, with
//!   `CONNETTO_POLICIES_SQL` or `CONNETTO_POLICIES_SQL_FILE` beside it (default
//!   none), into its replica schema, so the replica and the handshake's schema
//!   version are the ones the server derives from the same sources.
//! - `CONNETTO_TOKEN`: the login grant (default none, so no identity).
//! - `CONNETTO_USER`: the user id `CONNETTO_TOKEN` stands for, which the
//!   replica's policy views compare against (required with a token).
//! - `CONNETTO_DB`: the replica file of a signed-in client (required with a
//!   token). The replica is encrypted at rest under a key kept in the OS
//!   keyring, one entry per path. A client with no token keeps its replica in
//!   memory.
//! - `CONNETTO_KEYS`: share keys, comma separated, each written as its grant,
//!   `=`, and the subject it renders as (default none). Each is checked on its
//!   own, so an expired one costs the caller only what that key opened.
//! - `CONNETTO_SUB_ID`: subscription id (default `default`).
//! - `CONNETTO_QUERY`: the row subscription `SELECT` (required).
//! - `CONNETTO_KEY_STORE`: `keyutils` keeps the replica keys in the kernel
//!   session keyring on Linux, which a reboot empties. Unset means the detected
//!   durable store.
//! - `CONNETTO_WRITE`: optional SQL run on the managed local connection after
//!   subscribing, one statement per line. Each line is run and pushed to the
//!   server as a separate mutation, in order, and the server applies them to
//!   Postgres. The first statement the replica's own policy refuses ends the
//!   run with an error, once the server has answered every write before it.
//!
//! Connects, subscribes, and pumps inbound frames, printing each client event
//! until the server closes the connection or a SIGINT or SIGTERM arrives, either
//! of which ends the process normally. When `CONNETTO_WRITE` is set, the
//! client applies those writes locally and pushes them over the established
//! session right after subscribing, then observes its own rows echoed back
//! over CDC.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use connetto_client::auth::KeyringKeyStore;
use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoConnection, ContentPlace, Gate, Grant,
    HeldCredential, Located, NativeTransport, ReplicaPlace, SyncSchema,
};
use connetto_core::auth::CapabilitySubject;
use connetto_core::env::{read_ddl, var_or};
use diesel::connection::SimpleConnection;

/// Keyring service holding this binary's replica keys, one entry per
/// `CONNETTO_DB` path.
const KEYRING_SERVICE: &str = "connetto-client";

/// The replica file at exactly `CONNETTO_DB`, its key recorded under the
/// same path, since the operator chose the file rather than the identity.
struct DbPath(PathBuf);

impl ReplicaPlace for DbPath {
    fn locate(&self, _name: &str) -> Result<Located, ClientError> {
        let url = self
            .0
            .to_str()
            .ok_or_else(|| ClientError::Session("CONNETTO_DB is not valid UTF-8".to_owned()))?;
        Ok(Located::new(
            url,
            url,
            self.0.exists(),
            ContentPlace::InMemory,
        ))
    }
}

/// The share keys `CONNETTO_KEYS` names.
fn share_keys() -> Result<Vec<(Grant, CapabilitySubject<String>)>> {
    std::env::var("CONNETTO_KEYS")
        .ok()
        .iter()
        .flat_map(|keys| keys.split(','))
        .filter(|key| !key.is_empty())
        .map(|key| {
            let (grant, subject) = key
                .split_once('=')
                .ok_or_else(|| anyhow!("a CONNETTO_KEYS entry is grant=subject, got {key}"))?;
            Ok((
                Grant::new(grant.to_owned()),
                CapabilitySubject::new(subject.to_owned()),
            ))
        })
        .collect()
}

/// Connect as the environment says, returning the connected, unstarted
/// connection this binary drives frame by frame.
async fn connect(
    schema: SyncSchema,
    server: String,
) -> Result<ConnettoConnection<NativeTransport>> {
    let dial = move || {
        let url = server.clone();
        async move { connetto_core::dial(&url).await }
    };
    let builder = ClientBuilder::new(schema, dial).with_share_keys(share_keys()?);
    let connected = match std::env::var("CONNETTO_TOKEN").ok() {
        None => builder.connect_driven().await,
        Some(token) => {
            let user = std::env::var("CONNETTO_USER")
                .context("set CONNETTO_USER to the user id CONNETTO_TOKEN stands for")?;
            let db_path = std::env::var("CONNETTO_DB")
                .context("set CONNETTO_DB to the replica file of a signed-in client")?;
            builder
                .signed_in(HeldCredential::new(Grant::new(token), &user)?)
                .durable(DbPath(PathBuf::from(db_path)), key_store()?)
                .with_gate(Gate::off())
                .connect_driven()
                .await
        }
    };
    connected.map_err(|err| anyhow!("connecting sync client: {err}"))
}

/// Run and push each `CONNETTO_WRITE` statement in order, stopping at the
/// first one the replica refuses or a push that fails to send.
async fn run_writes(client: &mut ConnettoConnection<NativeTransport>) -> Result<()> {
    let Ok(writes) = std::env::var("CONNETTO_WRITE") else {
        return Ok(());
    };
    for stmt in writes
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        client
            .conn()
            .batch_execute(stmt)
            .map_err(|err| anyhow!("running CONNETTO_WRITE: {err}"))?;
        let seq = client
            .push()
            .await
            .map_err(|err| anyhow!("pushing local write: {err}"))?;
        tracing::info!(client_seq = ?seq, "pushed a local write");
    }
    Ok(())
}

/// Before an early exit, wait until the server has answered every write
/// already pushed, then close the connection with its handshake, so a
/// refusal further down the script loses none of the writes ahead of it.
async fn settle(client: &mut ConnettoConnection<NativeTransport>) {
    while !client.unsynced().is_empty() {
        match client.pump_one().await {
            Ok(ClientEvent::Closed | ClientEvent::ServerClosed { .. }) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if let Err(err) = client.close().await {
        tracing::warn!(error = %err, "closing after an early exit");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    // Armed before any work, so a SIGTERM at any point ends the process by returning from main.
    let terminated = terminate_signal()?;
    tokio::select! {
        result = run() => result,
        () = terminated => {
            tracing::info!("terminated");
            Ok(())
        }
    }
}

/// Resolves on the first SIGINT, or on unix the first SIGTERM.
#[cfg_attr(
    not(unix),
    expect(
        clippy::unnecessary_wraps,
        reason = "only unix installs a fallible SIGTERM handler"
    )
)]
fn terminate_signal() -> Result<impl Future<Output = ()>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
}

async fn run() -> Result<()> {
    let server = var_or("CONNETTO_SERVER", "ws://127.0.0.1:8080/");
    let sub_id = var_or("CONNETTO_SUB_ID", "default");
    let query = std::env::var("CONNETTO_QUERY").context("set CONNETTO_QUERY")?;
    let schema_sql = read_ddl("CONNETTO_SCHEMA_SQL").context("set CONNETTO_SCHEMA_SQL")?;
    let policies_sql = read_ddl("CONNETTO_POLICIES_SQL").unwrap_or_default();
    let bundle = connetto_schema::translate::<String>(&schema_sql, &policies_sql)
        .map_err(|err| anyhow!("translating CONNETTO_SCHEMA_SQL: {err}"))?;

    let mut client = connect(SyncSchema::new(bundle), server).await?;
    tracing::info!(connection = ?client.connection_id(), "connected");
    client
        .subscribe(&sub_id, &query)
        .await
        .map_err(|err| anyhow!("subscribing: {err}"))?;

    if let Err(err) = run_writes(&mut client).await {
        settle(&mut client).await;
        return Err(err);
    }

    loop {
        match client
            .pump_one()
            .await
            .map_err(|err| anyhow!("pumping frames: {err}"))?
        {
            ClientEvent::ServerClosed { reason } => {
                tracing::info!(reason = ?reason, "the server closed the session");
                return Ok(());
            }
            ClientEvent::Closed => {
                tracing::info!("the server closed the connection");
                return Ok(());
            }
            event => tracing::info!(event = ?event, "client event"),
        }
    }
}

/// The replica-key store `CONNETTO_KEY_STORE` names, or the detected one.
fn key_store() -> anyhow::Result<KeyringKeyStore> {
    key_store_named(std::env::var("CONNETTO_KEY_STORE").ok().as_deref())
}

fn key_store_named(name: Option<&str>) -> anyhow::Result<KeyringKeyStore> {
    match name {
        None => Ok(KeyringKeyStore::new(KEYRING_SERVICE)),
        #[cfg(target_os = "linux")]
        Some("keyutils") => Ok(KeyringKeyStore::with_linux_store(
            KEYRING_SERVICE,
            connetto_client::LinuxStore::Keyutils,
        )),
        Some(other) => Err(anyhow!(
            "CONNETTO_KEY_STORE={other} names no store this platform has"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::key_store_named;

    #[test]
    fn an_unknown_store_name_is_refused_naming_it() {
        let err = key_store_named(Some("secret-service"))
            .err()
            .expect("refused");
        assert!(
            err.to_string()
                .contains("CONNETTO_KEY_STORE=secret-service"),
            "got {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn keyutils_and_detection_are_the_two_choices() {
        let keyutils = key_store_named(Some("keyutils")).expect("keyutils");
        assert_eq!(
            keyutils.backend().await.expect("opens"),
            connetto_client::Backend::Keyutils
        );
        assert!(
            key_store_named(None).is_ok(),
            "unset means the detected store"
        );
    }
}
