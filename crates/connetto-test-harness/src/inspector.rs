//! A remote-inspector session on one web page, the demo's own view or a login
//! page, as the device proofs read and drive them.
//!
//! Chrome and the Android `WebView` speak the `DevTools` protocol directly.
//! `WebKit` on iOS, reached through `ios_webkit_debug_proxy`, multiplexes it, so
//! a connection first announces its page with `Target.targetCreated` and every
//! command travels inside `Target.sendMessageToTarget`, its reply inside
//! `Target.dispatchMessageFromTarget`.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

/// How long one request may take to answer.
pub const REPLY_BOUND: Duration = Duration::from_secs(10);

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// How requests reach the page.
enum Route {
    Direct,
    Target(String),
}

/// One inspector session. Each request carries an id its reply quotes, and
/// each wait for a reply is bounded by [`REPLY_BOUND`].
pub struct PageSession {
    socket: Socket,
    route: Route,
    next_id: u64,
}

impl PageSession {
    /// A session speaking the `DevTools` protocol to the page at `url`.
    ///
    /// # Errors
    ///
    /// When the socket does not open.
    pub async fn devtools(url: &str) -> Result<Self> {
        let (socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .context("opening the DevTools session")?;
        Ok(Self {
            socket,
            route: Route::Direct,
            next_id: 0,
        })
    }

    /// A session speaking the `WebKit` target protocol to the page at `url`.
    ///
    /// # Errors
    ///
    /// When the socket does not open or announces no page within
    /// [`REPLY_BOUND`].
    pub async fn webkit(url: &str) -> Result<Self> {
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .context("opening the WebKit inspector session")?;
        let deadline = Instant::now() + REPLY_BOUND;
        loop {
            let message = next_json(&mut socket, deadline, "the target announcement").await?;
            if message["method"] == "Target.targetCreated" {
                let target = message["params"]["targetInfo"]["targetId"]
                    .as_str()
                    .ok_or_else(|| anyhow!("a target announcement without an id: {message}"))?
                    .to_owned();
                return Ok(Self {
                    socket,
                    route: Route::Target(target),
                    next_id: 0,
                });
            }
        }
    }

    /// Send one request and return its result.
    ///
    /// # Errors
    ///
    /// When sending fails, the page answers with an error, or no reply
    /// arrives within [`REPLY_BOUND`].
    pub async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.next_id += 1;
        let id = self.next_id;
        let request = serde_json::json!({ "id": id, "method": method, "params": params });
        let frame = match &self.route {
            Route::Direct => request,
            Route::Target(target) => {
                self.next_id += 1;
                serde_json::json!({
                    "id": self.next_id,
                    "method": "Target.sendMessageToTarget",
                    "params": { "targetId": target, "message": request.to_string() },
                })
            }
        };
        self.socket
            .send(Message::Text(frame.to_string()))
            .await
            .context("sending an inspector request")?;
        let deadline = Instant::now() + REPLY_BOUND;
        loop {
            let message = next_json(&mut self.socket, deadline, &format!("request {id}")).await?;
            let reply = match self.route {
                Route::Direct => message,
                Route::Target(_) => {
                    if let Some(error) = message.get("error") {
                        bail!("inspector request {id} was refused: {error}");
                    }
                    if message["method"] != "Target.dispatchMessageFromTarget" {
                        continue;
                    }
                    let inner = message["params"]["message"].as_str().unwrap_or_default();
                    serde_json::from_str(inner).context("parsing a wrapped inspector reply")?
                }
            };
            if reply["id"] == id {
                if let Some(error) = reply.get("error") {
                    bail!("inspector request {id} failed: {error}");
                }
                return Ok(reply["result"].clone());
            }
        }
    }

    /// Evaluate `expression` in the page and return its value.
    ///
    /// # Errors
    ///
    /// As [`PageSession::call`].
    pub async fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value> {
        let result = self
            .call(
                "Runtime.evaluate",
                serde_json::json!({ "expression": expression, "returnByValue": true }),
            )
            .await?;
        Ok(result["result"]["value"].clone())
    }

    /// The page's visible text.
    ///
    /// # Errors
    ///
    /// As [`PageSession::call`].
    pub async fn page_text(&mut self) -> Result<String> {
        Ok(self
            .evaluate("document.body.innerText")
            .await?
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    /// Wait until the page shows `text`.
    ///
    /// # Errors
    ///
    /// When `limit` passes first, naming what the page shows.
    pub async fn wait_for_text(&mut self, text: &str, limit: Duration) -> Result<()> {
        self.wait_for_outcome(text, &[], limit).await
    }

    /// Wait until the page shows `text`, failing at once when it shows one of
    /// `refusals` instead.
    ///
    /// # Errors
    ///
    /// When a refusal shows or `limit` passes first, naming what the page shows.
    pub async fn wait_for_outcome(
        &mut self,
        text: &str,
        refusals: &[&str],
        limit: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + limit;
        loop {
            let page = self.page_text().await?;
            if page.contains(text) {
                return Ok(());
            }
            if let Some(refusal) = refusals.iter().find(|refusal| page.contains(**refusal)) {
                bail!("the page showed {refusal:?} rather than {text:?}, it shows:\n{page}");
            }
            if Instant::now() >= deadline {
                bail!("the page never showed {text:?}, it shows:\n{page}");
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Click the button labelled `label`.
    ///
    /// # Errors
    ///
    /// When the page has no such button, or as [`PageSession::call`].
    pub async fn click(&mut self, label: &str) -> Result<()> {
        let script = format!(
            "(() => {{ const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === {}); if (!b) return false; b.click(); return true; }})()",
            serde_json::Value::String(label.to_owned())
        );
        if self.evaluate(&script).await? == true {
            Ok(())
        } else {
            bail!("the page has no button {label:?}")
        }
    }
}

/// The next text frame as JSON, before `deadline`.
async fn next_json(
    socket: &mut Socket,
    deadline: Instant,
    what: &str,
) -> Result<serde_json::Value> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let frame = timeout(remaining, socket.next())
            .await
            .map_err(|_| anyhow!("{what} got no reply within {REPLY_BOUND:?}"))?
            .ok_or_else(|| anyhow!("the inspector session closed"))?
            .context("reading the inspector session")?;
        if let Message::Text(text) = frame {
            return serde_json::from_str(&text).context("parsing an inspector message");
        }
    }
}

/// The pages an inspector endpoint on `port` lists.
///
/// # Errors
///
/// When the endpoint does not answer with a JSON list.
pub async fn list_pages(port: u16) -> Result<Vec<serde_json::Value>> {
    openidconnect::reqwest::get(format!("http://127.0.0.1:{port}/json"))
        .await
        .context("listing inspector pages")?
        .json()
        .await
        .context("reading inspector pages")
}
