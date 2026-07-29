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
//! consistent with [`TrustingSessionVerifier`](connetto_core::auth::TrustingSessionVerifier),
//! which accepts anything, so the proof that verification is on is that a forged
//! token is refused.
//!
//! Ignored by default, because it needs the dev stack up:
//!
//! ```text
//! docker run -d --rm --name connetto-dev-pg -e POSTGRES_PASSWORD=postgres \
//!   -p 55470:5432 postgres:16 -c wal_level=logical
//! # apply examples/wasm-smoke/schema.sql, a publication, a slot,
//! # _connetto_mutations, connetto_sessions, and connetto_provider_tokens
//! cargo run --release -p connetto-server --example dev_idp
//! set -a && . target/dev-idp.env && set +a
//! CONNETTO_AUTH=database CONNETTO_AUTH_BIND=127.0.0.1:18081 \
//!   CONNETTO_BIND=127.0.0.1:7777 CONNETTO_WRITABLE=orders \
//!   CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql \
//!   DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55470/postgres \
//!   cargo run --release -p connetto-server --bin connetto-server
//!
//! cargo test --release -p connetto-client --features native-auth \
//!   --test verified_topology -- --ignored
//! ```

#![cfg(feature = "native-auth")]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Replica, SqlFunctions};
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

/// Open a sync connection with `token` and report what the handshake decided.
async fn handshake_with(token: &str) -> Result<(), ClientError> {
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
        auth_token: token.to_owned(),
        schema_version: Some(schema_version()),
        sql_functions: SqlFunctions::new(),
    };
    ConnettoConnection::connect(
        transport,
        &Replica::PlaintextFile { path: &path },
        "CREATE TABLE probe (id INTEGER PRIMARY KEY)",
        &config,
        None,
    )
    .await
    .map(drop)
}

#[tokio::test]
#[ignore = "requires the dev stack (Postgres, dev_idp, connetto-server with CONNETTO_AUTH=database)"]
async fn the_server_verifies_the_tokens_it_mints_and_refuses_the_rest() {
    // A token this server minted, for a session it stored, is accepted.
    let token = log_in().await;
    handshake_with(&token)
        .await
        .expect("a token this server minted is accepted at its own handshake");

    // A forged token is refused. This is what proves the verifier is real: the
    // trusting default would have accepted it just as happily as the one above.
    let forged = handshake_with("not-a-token").await;
    assert!(
        matches!(forged, Err(ClientError::Auth(_))),
        "a forged token must be refused, got {forged:?}"
    );

    // And a well-formed token for a session this server never issued is refused
    // too, so the check is against the store and not merely against the shape.
    let unknown = handshake_with(&format!("{token}tampered")).await;
    assert!(
        matches!(unknown, Err(ClientError::Auth(_))),
        "a tampered token must be refused, got {unknown:?}"
    );
}
