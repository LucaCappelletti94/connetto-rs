//! The complete topology: one server minting the tokens its own sync handshake
//! verifies, against a real provider and a durable session store.
//!
//! Every other auth test stops short of this. The in-process ones build an auth
//! router by hand and never open a sync connection, and the browser ones run the
//! login against a fixture stack whose session store the sync side cannot see, so
//! the handshake there accepts the token without checking it. This closes that gap:
//! the token is minted by the running `connetto-server`, the session lands in
//! Postgres, and the same process verifies it when the client connects.
//!
//! The negative case is the load-bearing one. A passing positive is equally
//! consistent with a trusting stand-in that accepts anything, so the proof
//! that verification is on is that a forged token is refused.
//!
//! Ignored by default, because it needs the dev stack up:
//!
//! ```text
//! docker run -d --rm --name connetto-dev-pg -e POSTGRES_PASSWORD=postgres \
//!   -p 55470:5432 postgres:16 -c wal_level=logical
//! # apply examples/wasm-smoke/schema.sql, a publication, a slot,
//! # _connetto_mutations, connetto_sessions, connetto_provider_tokens,
//! # and examples/wasm-smoke/roles.sql for the reader role
//! cargo run --release -p connetto-server --example dev_idp
//! set -a && . target/dev-idp.env && set +a
//! CONNETTO_AUTH=database CONNETTO_AUTH_BIND=127.0.0.1:18081 \
//!   CONNETTO_BIND=127.0.0.1:7777 CONNETTO_WRITABLE=orders \
//!   CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql \
//!   DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55470/postgres \
//!   CONNETTO_READER_URL=postgres://connetto_reader:connetto_reader@127.0.0.1:55470/postgres \
//!   cargo run --release -p connetto-server --bin connetto-server
//!
//! cargo test --release -p connetto-client --features native-auth \
//!   --test verified_topology -- --ignored
//! ```

#![cfg(feature = "native-auth")]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_client::{
    ClientConfig, ClientError, ConnettoConnection, Grant, Replica, SqlFunctions,
};
use connetto_core::transport::WebSocketTransport;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// The server's auth endpoints, its `CONNETTO_AUTH_BIND`.
fn auth_base() -> String {
    std::env::var("CONNETTO_TEST_AUTH_BASE").unwrap_or_else(|_| "http://127.0.0.1:18081".to_owned())
}

/// The server's sync endpoint, its `CONNETTO_BIND`.
fn ws_url() -> String {
    std::env::var("CONNETTO_TEST_WS").unwrap_or_else(|_| "ws://127.0.0.1:7777/".to_owned())
}

/// The provider name `dev_idp` registers.
fn provider() -> String {
    std::env::var("CONNETTO_TEST_PROVIDER").unwrap_or_else(|_| "dev-idp".to_owned())
}

/// The upstream schema version, hashed from the very file the server was started
/// with. A client that presents no version is refused rather than waved through,
/// which is right: not knowing its schema is not evidence of being current.
fn schema_version() -> connetto_core::SchemaVersion {
    let path = std::env::var("CONNETTO_TEST_PG_DDL_FILE").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/wasm-smoke/schema.sql"
        )
        .to_owned()
    });
    let ddl = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading the upstream DDL at {path}: {err}"));
    connetto_core::SchemaVersion::from_source(&ddl)
}

/// A high-entropy value for the PKCE verifier and the CSRF state, both of which
/// only need to be unguessable and made of unreserved characters.
fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Percent-encode a redirect URL for use as a query value. Hand-rolled because the
/// only characters at stake are the scheme colon and the path slashes.
fn encode_query_value(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

/// Answer one request on a loopback port and return its path plus query.
///
/// This stands in for the listener a native client binds for its redirect. The
/// client here is the test, so it plays that part itself rather than driving
/// `NativeAuthenticator`, whose own flow is covered by `native_auth.rs`.
async fn catch_one_redirect(listener: TcpListener) -> String {
    let (mut stream, _) = listener.accept().await.expect("accept the redirect");
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).await.expect("read the request");
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        .await
        .expect("answer the redirect");
    let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
    request
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

/// Walk the whole login the way a browser would and return connetto's own access
/// token for the session it creates.
async fn log_in() -> String {
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token();

    // Bound before the walk, because the last hop of the chain is a redirect to
    // this very port and the walk follows it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback redirect");
    let redirect = format!(
        "http://{}/cb",
        listener.local_addr().expect("the bound address")
    );
    let caught = tokio::spawn(catch_one_redirect(listener));

    // No cookie jar: the dev provider auto-grants consent, so no step of the chain
    // carries session state.
    let http = reqwest::Client::new();
    let login = format!(
        "{}/auth/login?provider={}&redirect_uri={}&code_challenge={challenge}&state={state}",
        auth_base(),
        provider(),
        encode_query_value(&redirect),
    );
    let walked = http
        .get(&login)
        .send()
        .await
        .expect("the dev stack must be up: see this file's header");
    assert!(
        walked.status().is_success(),
        "the login chain ended at {}",
        walked.status()
    );

    let path = caught.await.expect("the redirect catcher ran");
    let query = path
        .split_once('?')
        .expect("the redirect carries a query")
        .1;
    let mut code = None;
    let mut echoed = None;
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("code", value)) => code = Some(value.to_owned()),
            Some(("state", value)) => echoed = Some(value.to_owned()),
            _ => {}
        }
    }
    assert_eq!(
        echoed.as_deref(),
        Some(state.as_str()),
        "the state comes back unchanged"
    );

    let tokens: serde_json::Value = http
        .post(format!("{}/auth/token", auth_base()))
        .json(&serde_json::json!({
            "code": code.expect("a delivered authorization code"),
            "code_verifier": verifier,
            "redirect_uri": redirect,
        }))
        .send()
        .await
        .expect("redeem the code")
        .json()
        .await
        .expect("the token response is JSON");
    tokens
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .expect("an access token")
        .to_owned()
}

/// Connect presenting `token` as the only grant, and report the run handle the
/// server put on the ack.
async fn handshake_with(token: &str) -> Result<String, ClientError> {
    let url = ws_url();
    let authority = url
        .strip_prefix("ws://")
        .unwrap_or(&url)
        .split('/')
        .next()
        .unwrap_or(&url)
        .to_owned();
    let tcp = TcpStream::connect(&authority)
        .await
        .expect("the sync endpoint must be up: see this file's header");
    let transport = WebSocketTransport::connect(&url, tcp)
        .await
        .expect("websocket upgrade");
    let replica = tempfile::NamedTempFile::new().expect("a temp replica");
    let path = replica.path().to_string_lossy().into_owned();
    // No subscription, so nothing past the handshake is under test. A local DDL that
    // does not mirror the upstream is fine when no snapshot is ever requested.
    let config = ClientConfig {
        client_id: format!("verified-topology-{}", random_token()),
        login: Some(Grant::new(token.to_owned())),
        capabilities: Vec::new(),
        schema_version: Some(schema_version()),
        sql_functions: SqlFunctions::new(),
    };
    ConnettoConnection::connect(
        transport,
        &Replica::encrypted_file(&path, Some(connetto_core::test_support::replica_key()))
            .expect("key provided"),
        "CREATE TABLE probe (id INTEGER PRIMARY KEY)",
        &config,
        None,
    )
    .await
    .map(|conn| {
        conn.session_handle()
            .expect("a connected run has a handle")
            .to_owned()
    })
}

#[tokio::test]
#[ignore = "requires the dev stack (Postgres, dev_idp, connetto-server with CONNETTO_AUTH=database)"]
async fn the_server_verifies_the_tokens_it_mints_and_the_rest_identify_nobody() {
    // A token this server minted, for a session it stored, is accepted, and the
    // run it opens is the one the store already knows: presenting the same
    // token twice continues the same run rather than starting a second.
    let token = log_in().await;
    let first = handshake_with(&token)
        .await
        .expect("a token this server minted is accepted at its own handshake");
    let again = handshake_with(&token)
        .await
        .expect("the same token opens the same run");
    assert_eq!(
        first, again,
        "one login is one run, however many sockets it opens"
    );

    // A forged token no longer ends anything: under R3 a refused grant leaves
    // the connection open and says nothing on the wire. What it cannot do is
    // identify anybody, and the handle is where that shows: each refused
    // handshake gets a freshly minted run of its own instead of the login's.
    // This is what proves the checking is real. The trusting default would have
    // put the forged caller on a run derived from what it claimed to be.
    let forged = handshake_with("not-a-token")
        .await
        .expect("a refused grant does not close the connection");
    let forged_again = handshake_with("not-a-token")
        .await
        .expect("a refused grant does not close the connection");
    assert_ne!(
        forged, first,
        "a forged token must not land on the login's run"
    );
    assert_ne!(
        forged, forged_again,
        "each unidentified visit is its own run, so nothing is shared by guessing"
    );

    // And a well-formed token for a session this server never issued lands the
    // same way, so the check is against the signature and the store rather than
    // merely against the shape.
    let tampered = handshake_with(&format!("{token}tampered"))
        .await
        .expect("a refused grant does not close the connection");
    assert_ne!(
        tampered, first,
        "a tampered token must not land on the login's run"
    );
}
