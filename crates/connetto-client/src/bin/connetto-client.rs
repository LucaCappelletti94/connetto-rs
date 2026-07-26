//! The connetto sync client as a runnable process.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_SERVER`: server WebSocket URL (default `ws://127.0.0.1:8080/`).
//! - `CONNETTO_DB`: local SQLite file path (required, not `:memory:`, since the
//!   capture and apply connections share the file).
//! - `CONNETTO_SQLITE_DDL` or `CONNETTO_SQLITE_DDL_FILE`: local schema DDL.
//! - `CONNETTO_CLIENT_ID`: identity presented at handshake (default `anonymous`).
//! - `CONNETTO_TOKEN`: opaque auth token (default empty).
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
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::transport::WebSocketTransport;
use diesel::connection::SimpleConnection;
use tokio::net::TcpStream;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Read a DDL from `<key>` directly, or from the path in `<key>_FILE`.
fn read_ddl(key: &str) -> Result<String> {
    if let Ok(inline) = std::env::var(key) {
        return Ok(inline);
    }
    let file_key = format!("{key}_FILE");
    let path = std::env::var(&file_key).map_err(|_| anyhow!("set {key} or {file_key}"))?;
    std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = env_or("CONNETTO_SERVER", "ws://127.0.0.1:8080/");
    let db_path = std::env::var("CONNETTO_DB").context("set CONNETTO_DB to a file path")?;
    let sqlite_ddl = read_ddl("CONNETTO_SQLITE_DDL")?;
    let sub_id = env_or("CONNETTO_SUB_ID", "default");
    let query = std::env::var("CONNETTO_QUERY").context("set CONNETTO_QUERY")?;
    // Declared only when a shared canonical source is provided, matching the
    // server's version. Absent, the client declares nothing and a versioned
    // server rejects it.
    let schema_version = read_ddl("CONNETTO_SCHEMA_SQL")
        .ok()
        .map(|source| connetto_core::SchemaVersion::from_source(&source));
    let config = ClientConfig {
        client_id: env_or("CONNETTO_CLIENT_ID", "anonymous"),
        auth_token: env_or("CONNETTO_TOKEN", ""),
        schema_version,
    };

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

    let mut client = ConnettoConnection::connect(transport, &db_path, &sqlite_ddl, &config, None)
        .await
        .map_err(|err| anyhow!("connecting sync client: {err}"))?;
    eprintln!("connected, session {}", client.session_id());
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
            eprintln!("pushed local write as client_seq {seq:?}");
        }
    }

    loop {
        match client
            .pump_one()
            .await
            .map_err(|err| anyhow!("pumping frames: {err}"))?
        {
            ClientEvent::Closed => {
                eprintln!("server closed the connection");
                return Ok(());
            }
            event => println!("{event:?}"),
        }
    }
}
