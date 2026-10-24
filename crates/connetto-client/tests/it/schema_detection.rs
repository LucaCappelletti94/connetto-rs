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

use connetto_client::{ClientBuilder, ClientError, SyncSchema};
use connetto_core::messages::{ControlMessage, FatalError, FatalErrorReason, HandshakeAck};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, Major, SchemaVersion, loopback};

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
                writer: Some(connetto_core::messages::WriterGrant {
                    number: 1,
                    frontier: 0,
                }),
            }))
            .await;
        while let Ok(Some(_)) = server_end.recv().await {}
    });
    client_end
}

#[tokio::test]
async fn stale_baked_schema_is_rejected_at_handshake() {
    let bundle = super::support::bundle(SQLITE_DDL);
    let client_version = bundle.version();
    let server_version = SchemaVersion::from_hash(b"orders-extra");
    assert_ne!(
        client_version, server_version,
        "the two sides must hash different schemas"
    );
    let transport = fake_server(Some(server_version.clone()));

    let result = ClientBuilder::new(bundle, super::support::Once::new(transport))
        .signed_in(super::support::held("token"))
        .connect_driven()
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
    let bundle = super::support::bundle(SQLITE_DDL);
    let version = bundle.version();
    let transport = fake_server(Some(version));

    let conn = ClientBuilder::new(bundle, super::support::Once::new(transport))
        .signed_in(super::support::held("token"))
        .connect_driven()
        .await;
    assert!(
        conn.is_ok(),
        "a matching schema version proceeds normally: {:?}",
        conn.err()
    );
}

#[tokio::test]
async fn empty_server_skips_detection() {
    // A server that advertises no version (`None`) opts out of the contract, so
    // even a versioned client connects. This is the only remaining skip.
    let bundle = super::support::bundle(SQLITE_DDL);
    let transport = fake_server(None);

    let conn = ClientBuilder::new(bundle, super::support::Once::new(transport))
        .signed_in(super::support::held("token"))
        .connect_driven()
        .await;

    assert!(
        conn.is_ok(),
        "a versioned client connects to an unversioned server: {:?}",
        conn.err()
    );
}

/// Answer the handshake as a server at `server` major that refuses the
/// client's, and hand back the major the client declared.
fn refusing_server(
    server: Major,
) -> (
    LoopbackTransport,
    tokio::sync::oneshot::Receiver<Option<Major>>,
) {
    let (client_end, mut server_end) = loopback();
    let (declared_tx, declared_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(handshake)))) =
            server_end.recv().await
        else {
            return;
        };
        let _ = declared_tx.send(handshake.schema_major);
        let _ = server_end
            .send_control(ControlMessage::FatalError(FatalError::new(
                FatalErrorReason::MajorMismatch {
                    server,
                    client: handshake.schema_major,
                },
            )))
            .await;
    });
    (client_end, declared_rx)
}

/// The bundle's major is what the handshake declares, and a server at a
/// newer major tells this build to update (R31).
#[tokio::test]
async fn a_newer_server_major_requires_an_update() {
    let bundle = super::support::bundle(SQLITE_DDL);
    let built = bundle.major();
    let server = Major::new(built.get() + 1).expect("one above a major is a major");
    let (transport, declared) = refusing_server(server);

    let result = ClientBuilder::new(bundle, super::support::Once::new(transport))
        .signed_in(super::support::held("token"))
        .connect_driven()
        .await;

    assert_eq!(declared.await.expect("the handshake arrived"), Some(built));
    match result {
        Err(ClientError::UpdateRequired {
            client,
            server: told,
        }) => {
            assert_eq!(client, Some(built));
            assert_eq!(told, server);
        }
        Err(other) => panic!("expected UpdateRequired, got {other:?}"),
        Ok(_) => panic!("a build behind the server's major connected"),
    }
}

/// A server at an older major than this build is behind, which is a
/// deployment's problem rather than a reason to update the app (R31).
#[tokio::test]
async fn an_older_server_major_reads_as_server_behind() {
    let bundle = SyncSchema::new(
        SchemaBundle::new(
            "-- connetto:major 2",
            "",
            SQLITE_DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 2"),
    );
    let server = Major::new(1).expect("one is a major");
    let (transport, _declared) = refusing_server(server);

    let result = ClientBuilder::new(bundle, super::support::Once::new(transport))
        .signed_in(super::support::held("token"))
        .connect_driven()
        .await;

    match result {
        Err(ClientError::ServerBehind {
            client,
            server: told,
        }) => {
            assert_eq!(client, Major::new(2).expect("two is a major"));
            assert_eq!(told, server);
        }
        Err(other) => panic!("expected ServerBehind, got {other:?}"),
        Ok(_) => panic!("a build ahead of the server's major connected"),
    }
}
