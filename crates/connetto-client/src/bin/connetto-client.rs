//! The connetto sync client as a runnable process.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_SERVER`: server WebSocket URL (default `ws://127.0.0.1:8080/`).
//! - `CONNETTO_DB`: local SQLite file path (required, not `:memory:`, since the
//!   capture and apply connections share the file). The replica is encrypted at
//!   rest under a key kept in the OS keyring, one entry per path.
//! - `CONNETTO_SQLITE_DDL` or `CONNETTO_SQLITE_DDL_FILE`: local schema DDL.
//! - `CONNETTO_CLIENT_ID`: identity presented at handshake (default `anonymous`).
//! - `CONNETTO_TOKEN`: the login grant (default none, so no identity).
//! - `CONNETTO_KEYS`: share-key grants, comma separated (default none). Each is
//!   checked on its own, so an expired one costs the caller only what that key
//!   opened.
//! - `CONNETTO_SCHEMA_SQL` or `CONNETTO_SCHEMA_SQL_FILE`: the shared canonical
//!   schema source this build is compiled against, hashed into the handshake
//!   schema version for staleness detection. It must be the SAME source the
//!   server hashes (`CONNETTO_PG_DDL`), not the local SQLite DDL. Unset means
//!   the client declares no version and a versioned server rejects it.
//! - `CONNETTO_SUB_ID`: subscription id (default `default`).
//! - `CONNETTO_QUERY`: the row subscription `SELECT` (required).
//! - `CONNETTO_WRITE`: optional SQL run on the managed local connection after
//!   subscribing, one statement per line. Each line is run and pushed to the
//!   server as a separate mutation, in order. The server applies them to
//!   Postgres.
//!
//! Connects, subscribes, and pumps inbound frames, printing each client event
//! until the server closes the connection. When `CONNETTO_WRITE` is set, the
//! client applies those writes locally and pushes them right after subscribing,
//! then observes its own rows echoed back over CDC.

use anyhow::{Context, Result, anyhow};
use connetto_client::auth::{KeyringKeyStore, provision_replica_key};
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::env::{read_ddl, var_or};
use connetto_core::traits::ReplicaKeyStore;
use connetto_core::transport::WebSocketTransport;
use diesel::connection::SimpleConnection;
use tokio::net::TcpStream;

/// Keyring service holding this binary's replica keys, one entry per
/// `CONNETTO_DB` path.
const KEYRING_SERVICE: &str = "connetto-client";

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    let server = var_or("CONNETTO_SERVER", "ws://127.0.0.1:8080/");
    let db_path = std::env::var("CONNETTO_DB").context("set CONNETTO_DB to a file path")?;
    let sqlite_ddl = read_ddl("CONNETTO_SQLITE_DDL")?;
    let sub_id = var_or("CONNETTO_SUB_ID", "default");
    let query = std::env::var("CONNETTO_QUERY").context("set CONNETTO_QUERY")?;
    // Declared only when a shared canonical source is provided, matching the
    // server's version. Absent, the client declares nothing and a versioned
    // server rejects it.
    let schema_version = read_ddl("CONNETTO_SCHEMA_SQL")
        .ok()
        .map(|source| connetto_core::SchemaVersion::from_source(&source));
    let client_id = var_or("CONNETTO_CLIENT_ID", "anonymous");
    let config = ClientConfig::new(client_id)
        // CONNETTO_TOKEN carries the caller's identity grant. Unset means no
        // identity: the server accepts an anonymous caller.
        .with_login(std::env::var("CONNETTO_TOKEN").ok().map(Grant::new))
        .with_capabilities(
            std::env::var("CONNETTO_KEYS")
                .ok()
                .iter()
                .flat_map(|keys| keys.split(','))
                .filter(|key| !key.is_empty())
                .map(Grant::new)
                .collect::<Vec<_>>(),
        )
        .with_schema_version(schema_version);

    // The ws URL's authority is also the TCP target.
    let authority = server
        .strip_prefix("ws://")
        .unwrap_or(&server)
        .split('/')
        .next()
        .unwrap_or(&server);
    let tcp = TcpStream::connect(authority)
        .await
        .with_context(|| format!("connecting to {authority}"))?;
    let transport = WebSocketTransport::connect(&server, tcp)
        .await
        .map_err(|err| anyhow!("websocket handshake to {server}: {err}"))?;

    // Provision-once, addressed by the replica path since this binary has no
    // identity to name a record after. A replica already on disk reads the cache
    // and never mints: a fresh key for an existing file decrypts nothing, and
    // writing one would fill the record that restoring a backup still could.
    let keys = KeyringKeyStore::new(KEYRING_SERVICE);
    let resolved = if std::path::Path::new(&db_path).exists() {
        keys.load(&db_path)
            .await
            .with_context(|| format!("reading the replica key for {db_path}"))?
    } else {
        Some(
            provision_replica_key(&keys, &db_path)
                .await
                .with_context(|| format!("minting the replica key for {db_path}"))?,
        )
    };
    let replica = Replica::encrypted_file(&db_path, resolved)?;

    let mut client = ConnettoConnection::connect(transport, &replica, &sqlite_ddl, &config, None)
        .await
        .map_err(|err| anyhow!("connecting sync client: {err}"))?;
    tracing::info!(connection = ?client.connection_id(), "connected");
    client
        .subscribe(&sub_id, &query)
        .await
        .map_err(|err| anyhow!("subscribing: {err}"))?;

    if let Ok(writes) = std::env::var("CONNETTO_WRITE") {
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
