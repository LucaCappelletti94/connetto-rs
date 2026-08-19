//! End-to-end driver for the R23 passkey gate harness.
//!
//! The wasm package must be built before this test can run:
//!
//! ```text
//! wasm-pack build examples/webauthn-unlock --target web
//! ```
//!
//! Then run from the workspace directory:
//!
//! ```text
//! cargo +stable test -p connetto-webauthn-unlock --test webauthn_unlock
//! ```
//!
//! ChromeDriver is resolved in order: the `CHROMEDRIVER` environment variable,
//! then `chromedriver` on PATH, then the wasm-pack cache at
//! `~/.cache/.wasm-pack/`.

#![cfg(not(target_arch = "wasm32"))]

use anyhow::{Context as _, Result, anyhow, bail};
use reqwest::Client;
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::time::sleep;

// ── artifact check ────────────────────────────────────────────────────────

/// Path of the wasm binary relative to the workspace root (examples/webauthn-unlock).
const WASM_ARTIFACT: &str = "pkg/connetto_webauthn_unlock_bg.wasm";

fn require_wasm_artifact() {
    if !Path::new(WASM_ARTIFACT).exists() {
        panic!(
            "wasm artifact not found at {WASM_ARTIFACT}.\n\
             Build it first:\n\
             \n\
             \twasm-pack build examples/webauthn-unlock --target web\n"
        );
    }
}

// ── free port ─────────────────────────────────────────────────────────────

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding port 0")?;
    Ok(listener.local_addr()?.port())
    // listener drops here, freeing the port
}

// ── chromedriver discovery ────────────────────────────────────────────────

fn chromedriver_path() -> Result<String> {
    if let Ok(v) = std::env::var("CHROMEDRIVER") {
        return Ok(v);
    }
    if which_chromedriver("chromedriver") {
        return Ok("chromedriver".into());
    }
    // wasm-pack cache
    let home = std::env::var("HOME").unwrap_or_default();
    let cached = format!("{home}/.cache/.wasm-pack/.chromedriver/chromedriver");
    if Path::new(&cached).exists() {
        return Ok(cached);
    }
    bail!(
        "chromedriver not found.\n\
         Set CHROMEDRIVER=/path/to/chromedriver or put chromedriver on PATH."
    );
}

fn which_chromedriver(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── WebDriver client ──────────────────────────────────────────────────────

struct WebDriver {
    client: Client,
    base: String,
    session: String,
}

impl WebDriver {
    /// Create a headless Chrome session. `chromedriver_url` is already running.
    async fn new(chromedriver_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building reqwest client")?;

        let body = json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "args": [
                            "--headless=new",
                            "--no-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu",
                            // No --user-data-dir: chromedriver mints a fresh
                            // temporary profile per session and removes it
                            // afterwards, which is what "empty IndexedDB every
                            // run" needs. A fixed path is the opposite, and a
                            // profile left locked by an earlier run makes
                            // Chrome exit at startup.
                            "--disable-search-engine-choice-screen"
                        ]
                    }
                }
            }
        });

        let url = format!("{chromedriver_url}/session");
        let resp: Value = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("POST /session")?
            .json()
            .await
            .context("parsing /session response")?;

        let session = resp["value"]["sessionId"]
            .as_str()
            .ok_or_else(|| anyhow!("no sessionId in /session response: {resp}"))?
            .to_owned();

        Ok(Self {
            client,
            base: chromedriver_url.to_owned(),
            session,
        })
    }

    async fn delete(&self) -> Result<()> {
        self.client
            .delete(format!("{}/session/{}", self.base, self.session))
            .send()
            .await
            .context("DELETE /session")?;
        Ok(())
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        let body = json!({ "url": url });
        self.wd_post("url", &body).await.context("navigate")?;
        Ok(())
    }

    async fn execute(&self, script: &str) -> Result<Value> {
        let body = json!({ "script": script, "args": [] });
        let resp = self.wd_post("execute/sync", &body).await?;
        Ok(resp["value"].clone())
    }

    async fn add_authenticator(&self) -> Result<String> {
        // protocol must be ctap2_1 for PRF extension output to appear.
        let body = json!({
            "protocol": "ctap2_1",
            "transport": "internal",
            "hasResidentKey": true,
            "hasUserVerification": true,
            "isUserVerified": true,
            "extensions": ["prf"]
        });
        let resp = self
            .wd_post("webauthn/authenticator", &body)
            .await
            .context("POST /webauthn/authenticator")?;
        let id = resp["value"]
            .as_str()
            .ok_or_else(|| anyhow!("no authenticatorId in response: {resp}"))?
            .to_owned();
        Ok(id)
    }

    async fn delete_authenticator(&self, id: &str) -> Result<()> {
        self.client
            .delete(format!(
                "{}/session/{}/webauthn/authenticator/{id}",
                self.base, self.session
            ))
            .send()
            .await
            .context("DELETE /webauthn/authenticator")?;
        Ok(())
    }

    async fn wd_post(&self, endpoint: &str, body: &Value) -> Result<Value> {
        let url = format!("{}/session/{}/{endpoint}", self.base, self.session);
        let resp: Value = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {endpoint}"))?
            .json()
            .await
            .with_context(|| format!("parsing {endpoint} response"))?;
        Ok(resp)
    }
}

// ── polling helper ────────────────────────────────────────────────────────

/// Poll `window.__step_result` until any non-empty value appears or the
/// timeout elapses. Clears the result before returning so the next poll
/// starts fresh.
async fn poll_result(driver: &WebDriver, timeout: Duration) -> Result<String> {
    let start = Instant::now();
    loop {
        let val = driver
            .execute("return window.__step_result || null;")
            .await
            .context("reading __step_result")?;
        if let Some(got) = val.as_str().filter(|got| !got.is_empty()) {
            driver
                .execute("window.__step_result = null;")
                .await
                .context("clearing __step_result")?;
            return Ok(got.to_owned());
        }
        if start.elapsed() >= timeout {
            bail!("timed out after {timeout:?} waiting for a result");
        }
        sleep(Duration::from_millis(200)).await;
    }
}

// ── file server ───────────────────────────────────────────────────────────

/// Start an axum file server in the background and return its URL.
/// Serves the workspace root (index.html, db-worker.js) and pkg/ directory.
async fn start_file_server(port: u16) -> Result<()> {
    use axum::{Router, routing::get_service};
    use std::net::SocketAddr;
    use tower_http::services::ServeDir;

    let router = Router::new().fallback_service(get_service(ServeDir::new(".")));

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding file server on port {port}"))?;

    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });

    Ok(())
}

// ── chromedriver process ──────────────────────────────────────────────────

struct ChromeDriver {
    child: Child,
    url: String,
}

impl ChromeDriver {
    async fn start() -> Result<Self> {
        let path = chromedriver_path()?;
        let port = free_port()?;
        let child = Command::new(&path)
            .arg(format!("--port={port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning chromedriver from {path}"))?;

        let url = format!("http://127.0.0.1:{port}");

        // Wait for chromedriver to become ready.
        let client = Client::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if client.get(format!("{url}/status")).send().await.is_ok() {
                break;
            }
            if Instant::now() >= deadline {
                bail!("chromedriver did not become ready within 10 s");
            }
            sleep(Duration::from_millis(100)).await;
        }

        Ok(Self { child, url })
    }
}

impl Drop for ChromeDriver {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            // Best-effort: log and swallow; panicking in Drop is never correct.
            eprintln!("ChromeDriver::drop: kill failed: {e}");
        }
    }
}

// ── test ──────────────────────────────────────────────────────────────────

/// Three assertions:
///
/// 1. The derived key opens the record it wrote (enrolment + write succeed).
/// 2. A worker restart re-derives the same key and still opens it (stable PRF).
/// 3. With the authenticator deleted the open fails (the locked invariant).
#[tokio::test]
async fn passkey_gate_enrol_use_and_lock() -> Result<()> {
    require_wasm_artifact();

    // Clean up any leftover profile from a previous run so IndexedDB is empty.
    let _ = std::fs::remove_dir_all("/tmp/webauthn-unlock-test-profile");

    let cd = ChromeDriver::start().await?;
    let page_port = free_port()?;
    start_file_server(page_port).await?;

    // `localhost`, never the IP literal: WebAuthn rejects an origin whose host
    // is not a registrable domain with `SecurityError: This is an invalid
    // domain`, and `localhost` is the one exempt name that is also a secure
    // context over plain HTTP.
    let page_url = format!("http://localhost:{page_port}/index.html");
    let driver = WebDriver::new(&cd.url).await?;

    let auth_id = driver
        .add_authenticator()
        .await
        .context("installing simulated authenticator")?;

    driver
        .navigate(&page_url)
        .await
        .context("navigating to page")?;

    // Assertion 1: the derived key opens the record it wrote.
    let step1 = poll_result(&driver, Duration::from_secs(30))
        .await
        .context("waiting for step 1 result")?;
    assert!(
        step1 == "step1:ok",
        "assertion 1: derived key opens a record it wrote (got {step1:?})",
    );

    // Restart the worker so step 2 runs a fresh boot with the enrolled profile.
    driver
        .execute("window.restart_worker();")
        .await
        .context("calling restart_worker for step 2")?;

    // Assertion 2: a worker restart re-derives the same key and still opens it.
    let step2 = poll_result(&driver, Duration::from_secs(30))
        .await
        .context("waiting for step 2 result")?;
    assert!(
        step2 == "step2:ok",
        "assertion 2: worker restart re-derives the same key and still opens it (got {step2:?})",
    );

    // Delete the simulated authenticator; the next boot must be refused.
    driver
        .delete_authenticator(&auth_id)
        .await
        .context("deleting authenticator")?;

    // Restart the worker to trigger step 3.
    driver
        .execute("window.restart_worker();")
        .await
        .context("calling restart_worker for step 3")?;

    // Assertion 3: with the authenticator deleted the open fails.
    // Longer than the ceremony's own 60 second bound in `connetto_web::unlock`:
    // with the authenticator gone there is nothing to answer the assertion, so
    // the refusal only arrives when that bound expires. This wait is the proof.
    let step3 = poll_result(&driver, Duration::from_secs(90))
        .await
        .context("waiting for step 3 result")?;
    assert!(
        step3 == "step3:locked",
        "assertion 3: with the authenticator deleted the open fails (got {step3:?})",
    );

    driver.delete().await.context("closing WebDriver session")?;
    Ok(())
}
