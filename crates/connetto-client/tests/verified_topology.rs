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
//! The browser-stack runner supplies the server binary and service environment.

#![cfg(feature = "native-auth")]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Grant, Replica};
use connetto_core::transport::WebSocketTransport;
use sha2::{Digest as _, Sha256};
use std::process::{Child, Command, Stdio};
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, sleep, timeout};

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

fn bind_from_ws(url: &str) -> String {
    url.strip_prefix("ws://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_owned()
}

fn bind_from_http(base: &str) -> String {
    base.strip_prefix("http://")
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or(base)
        .to_owned()
}

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

async fn wait_for_child_port(child: &mut Child, bind: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(bind).await.is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("check connetto-server status") {
            panic!("connetto-server exited before opening {bind}: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "connetto-server did not open {bind}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn maybe_spawn_server() -> Option<ServerGuard> {
    let bin = std::env::var("CONNETTO_SERVER_BIN").ok()?;
    let bind = bind_from_ws(&ws_url());
    let auth_bind = bind_from_http(&auth_base());
    let mut command = Command::new(&bin);
    command
        .env("CONNETTO_BIND", &bind)
        .env("CONNETTO_AUTH_BIND", &auth_bind)
        .env("CONNETTO_AUTH", "database")
        .env("CONNETTO_WRITABLE", "orders")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Ok(path) = std::env::var("CONNETTO_TEST_PG_DDL_FILE") {
        command.env("CONNETTO_PG_DDL_FILE", path);
    }
    if let Ok(path) = std::env::var("CONNETTO_TEST_PG_POLICIES_FILE") {
        command.env("CONNETTO_PG_POLICIES_FILE", path);
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|err| panic!("spawning connetto-server at {bin}: {err}"));
    wait_for_child_port(&mut child, &bind).await;
    wait_for_child_port(&mut child, &auth_bind).await;
    Some(ServerGuard(child))
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

fn redirect_location(response: &reqwest::Response, step: &str) -> String {
    assert!(
        response.status().is_redirection(),
        "{step} returned {}",
        response.status()
    );
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .unwrap_or_else(|| panic!("{step} did not return a Location header"))
        .to_str()
        .unwrap_or_else(|err| panic!("{step} returned a non UTF-8 Location header: {err}"))
        .to_owned()
}

/// Walk the whole login the way a browser would and return connetto's own access
/// token for the session it creates.
async fn log_in() -> String {
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token();

    let redirect = "http://127.0.0.1:1/cb";
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the HTTP client");
    let login = format!(
        "{}/auth/login?provider={}&redirect_uri={}&code_challenge={challenge}&state={state}",
        auth_base(),
        provider(),
        encode_query_value(redirect),
    );
    let login_response = http
        .get(&login)
        .send()
        .await
        .expect("start the login with connetto");
    let form_url = redirect_location(&login_response, "login start");
    let callback_response = http
        .post(&form_url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body("username=verified")
        .send()
        .await
        .expect("submit the provider login");
    let callback_url = redirect_location(&callback_response, "provider login");
    let client_response = http
        .get(&callback_url)
        .send()
        .await
        .expect("complete the provider callback");
    let client_url = redirect_location(&client_response, "server callback");
    let query = client_url
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
    let config = ClientConfig::new(format!("verified-topology-{}", random_token()))
        .with_login(Some(Grant::new(token.to_owned())))
        .with_schema_version(Some(schema_version()));
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
#[ignore = "requires connetto-browser-stack or equivalent server environment"]
async fn the_server_verifies_the_tokens_it_mints_and_the_rest_identify_nobody() {
    let _server = maybe_spawn_server().await;

    // A token this server minted, for a session it stored, is accepted, and the
    // run it opens is the one the store already knows: presenting the same
    // token twice continues the same run rather than starting a second.
    let token = timeout(Duration::from_secs(15), log_in())
        .await
        .expect("the login flow completes");
    let first = timeout(Duration::from_secs(15), handshake_with(&token))
        .await
        .expect("the first verified handshake returns")
        .expect("a token this server minted is accepted at its own handshake");
    let again = timeout(Duration::from_secs(15), handshake_with(&token))
        .await
        .expect("the repeated verified handshake returns")
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
    let forged = timeout(Duration::from_secs(15), handshake_with("not-a-token"))
        .await
        .expect("the first refused handshake returns")
        .expect("a refused grant does not close the connection");
    let forged_again = timeout(Duration::from_secs(15), handshake_with("not-a-token"))
        .await
        .expect("the second refused handshake returns")
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
    let tampered = timeout(
        Duration::from_secs(15),
        handshake_with(&format!("{token}tampered")),
    )
    .await
    .expect("the tampered handshake returns")
    .expect("a refused grant does not close the connection");
    assert_ne!(
        tampered, first,
        "a tampered token must not land on the login's run"
    );
}
