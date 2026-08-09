//! Phase 7: schema-version staleness detection at handshake.
//!
//! connetto does not migrate schemas at runtime. The schema is baked into the
//! app at build time and the client never runs DDL, so when the server advertises
//! a different schema version the right reaction is to tell the app to reload,
//! not to keep running against a shape it was not compiled for. Detection happens
//! at the handshake, before any pending mutation is replayed, so a stale build
//! never pushes old-schema changesets to a new-schema server.
//!
//! A deterministic fake server completes the handshake advertising a chosen
//! schema version, so the test controls exactly what the client compares against.

use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Grant, Replica};
use connetto_core::messages::{ControlMessage, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, SchemaVersion, loopback};

const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";

/// Complete the handshake as a fake server advertising `server_version`, then
/// drain. Returns the client end of the loopback.
fn fake_server(server_version: Option<SchemaVersion>) -> LoopbackTransport {
    let (client_end, mut server_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) =
            server_end.recv().await
        else {
            return;
        };
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "server".to_owned(),
                session_token: "server".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                resume_token: "server".to_owned(),
                schema_version: server_version,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await;
        while let Ok(Some(_)) = server_end.recv().await {}
    });
    client_end
}

fn config(schema_version: Option<SchemaVersion>) -> ClientConfig {
    ClientConfig::new("schema-detection")
        .with_login(Some(Grant::new("user:token")))
        .with_schema_version(schema_version)
}

#[tokio::test]
async fn stale_baked_schema_is_rejected_at_handshake() {
    let server_version = SchemaVersion::from_source("CREATE TABLE orders (id INT, extra INT);");
    let client_version = SchemaVersion::from_source("CREATE TABLE orders (id INT);");
    let transport = fake_server(Some(server_version.clone()));

    let result = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        SQLITE_DDL,
        &config(Some(client_version.clone())),
        None,
    )
    .await;

    match result {
        Err(ClientError::SchemaOutdated { client, server }) => {
            assert_eq!(
                client,
                Some(client_version),
                "the error reports the client's baked version"
            );
            assert_eq!(
                server, server_version,
                "the error reports the server's version"
            );
        }
        Err(other) => panic!("expected SchemaOutdated, got {other:?}"),
        Ok(_) => panic!("a stale client connected instead of being told to reload"),
    }
}

#[tokio::test]
async fn matching_schema_connects() {
    let version = SchemaVersion::from_source("CREATE TABLE orders (id INT, quantity INT);");
    let transport = fake_server(Some(version.clone()));

    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        SQLITE_DDL,
        &config(Some(version)),
        None,
    )
    .await;

    assert!(
        conn.is_ok(),
        "a matching schema version proceeds normally: {:?}",
        conn.err()
    );
}

#[tokio::test]
async fn undeclared_client_rejected_by_versioned_server() {
    // Detection is server-gated: once the server advertises a version, a client
    // that declares none (`None`) is stale and must reload, so a build that
    // forgot to bake its version fails loudly rather than mis-parsing.
    let server_version = SchemaVersion::from_source("CREATE TABLE orders (id INT);");
    let transport = fake_server(Some(server_version.clone()));

    let result = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        SQLITE_DDL,
        &config(None),
        None,
    )
    .await;

    match result {
        Err(ClientError::SchemaOutdated { client, server }) => {
            assert_eq!(client, None, "the undeclared client reports no version");
            assert_eq!(server, server_version, "against the server's real version");
        }
        Err(other) => panic!("expected SchemaOutdated, got {other:?}"),
        Ok(_) => panic!("an undeclared client connected to a versioned server"),
    }
}

#[tokio::test]
async fn empty_server_skips_detection() {
    // A server that advertises no version (`None`) opts out of the contract, so
    // even a versioned client connects. This is the only remaining skip.
    let transport = fake_server(None);

    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        SQLITE_DDL,
        &config(Some(SchemaVersion::from_source(
            "CREATE TABLE orders (id INT);",
        ))),
        None,
    )
    .await;

    assert!(
        conn.is_ok(),
        "a versioned client connects to an unversioned server: {:?}",
        conn.err()
    );
}
