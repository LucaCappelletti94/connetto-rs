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

/// The `DevTools` messages of a request the page dropped because it
/// navigated, or its target closed, while the request ran.
const NAVIGATED: [&str; 2] = [
    "Inspected target navigated or closed",
    "Execution context was destroyed.",
];

/// Marks a request the page dropped by navigating, see [`NAVIGATED`].
#[derive(Debug, thiserror::Error)]
#[error("the page navigated while a request ran")]
struct Navigated;

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
    /// The `WebKit` target events the session saw, the first
    /// [`TARGET_EVENTS_KEPT`], which a failed request reports.
    target_events: Vec<String>,
}

/// How many target events a session keeps for its failure reports.
const TARGET_EVENTS_KEPT: usize = 16;

/// Keep `message` on `events` when it is a `WebKit` target event other than a
/// wrapped reply.
fn note_target_event(events: &mut Vec<String>, message: &serde_json::Value) {
    let Some(method) = message["method"].as_str() else {
        return;
    };
    if method.starts_with("Target.")
        && method != "Target.dispatchMessageFromTarget"
        && events.len() < TARGET_EVENTS_KEPT
    {
        events.push(format!("{method} {}", message["params"]));
    }
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
            target_events: Vec::new(),
        })
    }

    /// A session speaking the `WebKit` target protocol to the page at `url`,
    /// on its committed page target. A page mid-navigation also announces the
    /// provisional target of the process it is moving to, and iOS 26 announces
    /// the main frame as a target of its own, whose `Runtime` domain is absent.
    ///
    /// # Errors
    ///
    /// When the socket does not open or announces no committed page within
    /// [`REPLY_BOUND`].
    pub async fn webkit(url: &str) -> Result<Self> {
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .context("opening the WebKit inspector session")?;
        let deadline = Instant::now() + REPLY_BOUND;
        let mut target_events = Vec::new();
        // Frames commit provisional targets too, so only a page's commit is followed.
        let mut provisional_pages = Vec::new();
        loop {
            let message = next_json(&mut socket, deadline, "the target announcement").await?;
            note_target_event(&mut target_events, &message);
            let info = &message["params"]["targetInfo"];
            let committed = match message["method"].as_str() {
                Some("Target.targetCreated") if info["type"] == "page" => {
                    if info["isProvisional"] == true {
                        provisional_pages.push(info["targetId"].clone());
                        continue;
                    }
                    &info["targetId"]
                }
                Some("Target.didCommitProvisionalTarget")
                    if provisional_pages.contains(&message["params"]["newTargetId"]) =>
                {
                    &message["params"]["newTargetId"]
                }
                _ => continue,
            };
            let target = committed
                .as_str()
                .ok_or_else(|| anyhow!("a target announcement without an id: {message}"))?
                .to_owned();
            return Ok(Self {
                socket,
                route: Route::Target(target),
                next_id: 0,
                target_events,
            });
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
            let message = next_json(
                &mut self.socket,
                deadline,
                &format!("request {id} ({method})"),
            )
            .await?;
            let reply = match &mut self.route {
                Route::Direct => message,
                Route::Target(target) => {
                    note_target_event(&mut self.target_events, &message);
                    if let Some(error) = message.get("error") {
                        bail!("inspector request {id} was refused: {error}");
                    }
                    // The old target drops the request, so the caller asks the new one again.
                    if message["method"] == "Target.didCommitProvisionalTarget"
                        && message["params"]["oldTargetId"] == target.as_str()
                    {
                        let new = message["params"]["newTargetId"]
                            .as_str()
                            .ok_or_else(|| anyhow!("a target commit without an id: {message}"))?;
                        new.clone_into(target);
                        return Err(anyhow!("request {id} went to a target the page left")
                            .context(Navigated));
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
                    let failure = match &self.route {
                        Route::Direct => anyhow!("inspector request {id} failed: {error}"),
                        Route::Target(target) => anyhow!(
                            "inspector request {id} to target {target} failed: {error}, after the target events {:?}",
                            self.target_events
                        ),
                    };
                    let navigated = NAVIGATED.contains(&error["message"].as_str().unwrap_or(""));
                    return Err(if navigated {
                        failure.context(Navigated)
                    } else {
                        failure
                    });
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
    /// `refusals` instead. A read the page drops because it navigated is
    /// retried, since a page under a wait may still be loading.
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
            let page = match self.page_text().await {
                Ok(page) => page,
                Err(error) if error.is::<Navigated>() => {
                    if Instant::now() >= deadline {
                        return Err(error.context(format!("the page never showed {text:?}")));
                    }
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
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

    /// Focus the input named `name` and put `text` into it, typed as trusted
    /// input over `DevTools` and set by the page with an `input` event over
    /// `WebKit`.
    ///
    /// # Errors
    ///
    /// When the page has no such input, or as [`Self::call`].
    pub async fn set_input(&mut self, name: &str, text: &str) -> Result<()> {
        let script = format!(
            "(() => {{ const input = document.querySelector('input[name={name:?}]'); if (!input) return false; input.focus(); return true; }})()"
        );
        if self.evaluate(&script).await? != true {
            bail!("the page has no input named {name:?}")
        }
        match self.route {
            Route::Direct => {
                self.call("Input.insertText", serde_json::json!({ "text": text }))
                    .await?;
            }
            // WebKit has no `Input` domain, so the page sets the value through
            // the element's own setter and raises the `input` event its
            // handlers listen for.
            Route::Target(_) => {
                let fill = format!(
                    "(() => {{ const input = document.querySelector('input[name={name:?}]'); \
                     Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, {text:?}); \
                     input.dispatchEvent(new Event('input', {{ bubbles: true }})); return true; }})()"
                );
                if self.evaluate(&fill).await? != true {
                    bail!("the page did not fill the input named {name:?}")
                }
            }
        }
        Ok(())
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

/// The pages an inspector endpoint on `port` lists, within [`REPLY_BOUND`].
///
/// # Errors
///
/// When the endpoint does not answer with a JSON list within [`REPLY_BOUND`].
pub async fn list_pages(port: u16) -> Result<Vec<serde_json::Value>> {
    list_pages_within(port, REPLY_BOUND).await
}

/// An `adb forward` with no browser behind it accepts the connection and never answers.
async fn list_pages_within(port: u16, bound: Duration) -> Result<Vec<serde_json::Value>> {
    let listed = async {
        openidconnect::reqwest::get(format!("http://127.0.0.1:{port}/json"))
            .await
            .context("listing inspector pages")?
            .json()
            .await
            .context("reading inspector pages")
    };
    timeout(bound, listed)
        .await
        .map_err(|_| anyhow!("the inspector page list got no reply within {bound:?}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `DevTools` endpoint answering each `Runtime.evaluate` with the next
    /// entry of `replies`, as an `error` or a string `value`.
    async fn endpoint(replies: Vec<Result<&'static str, serde_json::Value>>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            for reply in replies {
                let Some(Ok(Message::Text(text))) = socket.next().await else {
                    return;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                let answer = match reply {
                    Ok(value) => serde_json::json!({
                        "id": request["id"],
                        "result": { "result": { "type": "string", "value": value } },
                    }),
                    Err(error) => serde_json::json!({ "id": request["id"], "error": error }),
                };
                socket
                    .send(Message::Text(answer.to_string()))
                    .await
                    .unwrap();
            }
        });
        format!("ws://{address}")
    }

    /// A `WebKit` target endpoint, which has no `Input` domain, answering
    /// `Runtime.evaluate` with `true` and recording each expression on
    /// `seen`.
    async fn webkit_endpoint(seen: tokio::sync::mpsc::UnboundedSender<String>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let announce = serde_json::json!({
                "method": "Target.targetCreated",
                "params": { "targetInfo": { "targetId": "page-1", "type": "page" } },
            });
            socket
                .send(Message::Text(announce.to_string()))
                .await
                .unwrap();
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                let inner: serde_json::Value =
                    serde_json::from_str(frame["params"]["message"].as_str().unwrap()).unwrap();
                let reply = if inner["method"] == "Runtime.evaluate" {
                    let _ = seen.send(inner["params"]["expression"].as_str().unwrap().to_owned());
                    serde_json::json!({
                        "id": inner["id"],
                        "result": { "result": { "type": "boolean", "value": true } },
                    })
                } else {
                    serde_json::json!({
                        "id": inner["id"],
                        "error": { "code": -32601, "message": "'Input' domain was not found" },
                    })
                };
                let wrapped = serde_json::json!({
                    "method": "Target.dispatchMessageFromTarget",
                    "params": { "targetId": "page-1", "message": reply.to_string() },
                });
                socket
                    .send(Message::Text(wrapped.to_string()))
                    .await
                    .unwrap();
            }
        });
        format!("ws://{address}")
    }

    /// `WebKit` has no `Input` domain, so a field is filled through the page,
    /// the value set and an `input` event raised for the page's handlers.
    #[tokio::test]
    async fn a_webkit_field_is_filled_through_the_page() {
        let (seen, mut expressions) = tokio::sync::mpsc::unbounded_channel();
        let url = webkit_endpoint(seen).await;
        let mut page = PageSession::webkit(&url).await.unwrap();
        page.set_input("ssid", "iPhone di Luca").await.unwrap();
        let mut all = Vec::new();
        while let Ok(expression) = expressions.try_recv() {
            all.push(expression);
        }
        assert!(
            all.iter()
                .any(|e| e.contains("\"iPhone di Luca\"") && e.contains("'input'")),
            "{all:?}"
        );
    }

    #[tokio::test]
    async fn a_wait_outlasts_the_page_navigating_under_it() {
        let url = endpoint(vec![
            Err(serde_json::json!({
                "code": -32000,
                "message": "Inspected target navigated or closed",
            })),
            Ok("status: connected"),
        ])
        .await;
        let mut page = PageSession::devtools(&url).await.unwrap();
        page.wait_for_text("status: connected", Duration::from_secs(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_wait_stops_at_the_first_other_page_error() {
        let url = endpoint(vec![
            Err(
                serde_json::json!({ "code": -32601, "message": "'Runtime.evaluate' wasn't found" }),
            ),
            Ok("status: connected"),
        ])
        .await;
        let mut page = PageSession::devtools(&url).await.unwrap();
        let error = page
            .wait_for_text("status: connected", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("wasn't found"), "{error:#}");
    }

    /// A `WebKit` target endpoint that first sends `announcements`, then
    /// answers each wrapped request with the frames `respond` returns for its
    /// target and inner message.
    async fn scripted_webkit_endpoint(
        announcements: Vec<serde_json::Value>,
        respond: fn(&str, &serde_json::Value) -> Vec<serde_json::Value>,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            for announcement in announcements {
                socket
                    .send(Message::Text(announcement.to_string()))
                    .await
                    .unwrap();
            }
            while let Some(Ok(Message::Text(text))) = socket.next().await {
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                let target = frame["params"]["targetId"].as_str().unwrap().to_owned();
                let inner: serde_json::Value =
                    serde_json::from_str(frame["params"]["message"].as_str().unwrap()).unwrap();
                for outgoing in respond(&target, &inner) {
                    socket
                        .send(Message::Text(outgoing.to_string()))
                        .await
                        .unwrap();
                }
            }
        });
        format!("ws://{address}")
    }

    /// The wrapped reply `target` gives to `inner`, the page text `text`.
    fn page_reply(target: &str, inner: &serde_json::Value, text: &str) -> serde_json::Value {
        let reply = serde_json::json!({
            "id": inner["id"],
            "result": { "result": { "type": "string", "value": text } },
        });
        serde_json::json!({
            "method": "Target.dispatchMessageFromTarget",
            "params": { "targetId": target, "message": reply.to_string() },
        })
    }

    /// A page mid-navigation announces the provisional target of the process
    /// it moves to, which has no `Runtime` domain until it commits.
    #[tokio::test]
    async fn a_webkit_session_attaches_to_a_provisional_target_once_committed() {
        let url = scripted_webkit_endpoint(
            vec![
                serde_json::json!({
                    "method": "Target.targetCreated",
                    "params": { "targetInfo": { "targetId": "page-2", "type": "page", "isProvisional": true } },
                }),
                serde_json::json!({
                    "method": "Target.didCommitProvisionalTarget",
                    "params": { "oldTargetId": "page-1", "newTargetId": "page-2" },
                }),
            ],
            |target, inner| {
                assert_eq!(target, "page-2", "a request reached a target without Runtime");
                vec![page_reply(target, inner, "status: connected")]
            },
        )
        .await;
        let mut page = PageSession::webkit(&url).await.unwrap();
        page.wait_for_text("status: connected", Duration::from_secs(5))
            .await
            .unwrap();
    }

    /// A navigation that swaps the page's process commits a new target, and
    /// the request the old target dropped is asked again of the new one.
    #[tokio::test]
    async fn a_webkit_wait_follows_a_committed_provisional_target() {
        let url = scripted_webkit_endpoint(
            vec![serde_json::json!({
                "method": "Target.targetCreated",
                "params": { "targetInfo": { "targetId": "page-1", "type": "page" } },
            })],
            |target, inner| {
                if target == "page-2" {
                    return vec![page_reply(target, inner, "status: connected")];
                }
                vec![serde_json::json!({
                    "method": "Target.didCommitProvisionalTarget",
                    "params": { "oldTargetId": "page-1", "newTargetId": "page-2" },
                })]
            },
        )
        .await;
        let mut page = PageSession::webkit(&url).await.unwrap();
        page.wait_for_text("status: connected", Duration::from_secs(5))
            .await
            .unwrap();
    }

    /// `WebKit` on iOS 26 announces the page's main frame as its own target,
    /// which can commit provisional targets of its own, before the page
    /// target, and only the page target has `Runtime`.
    #[tokio::test]
    async fn a_webkit_session_attaches_to_the_page_not_its_frame() {
        let url = scripted_webkit_endpoint(
            vec![
                serde_json::json!({
                    "method": "Target.targetCreated",
                    "params": { "targetInfo": { "targetId": "frame-1", "type": "frame" } },
                }),
                serde_json::json!({
                    "method": "Target.targetCreated",
                    "params": { "targetInfo": { "targetId": "frame-2", "type": "frame", "isProvisional": true } },
                }),
                serde_json::json!({
                    "method": "Target.didCommitProvisionalTarget",
                    "params": { "oldTargetId": "frame-1", "newTargetId": "frame-2" },
                }),
                serde_json::json!({
                    "method": "Target.targetCreated",
                    "params": { "targetInfo": { "targetId": "page-8", "type": "page" } },
                }),
            ],
            |target, inner| {
                assert_eq!(
                    target, "page-8",
                    "a request reached a target without Runtime"
                );
                vec![page_reply(target, inner, "status: connected")]
            },
        )
        .await;
        let mut page = PageSession::webkit(&url).await.unwrap();
        page.wait_for_text("status: connected", Duration::from_secs(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_page_list_that_never_answers_fails_within_its_bound() {
        // Like an `adb forward` with no browser behind it, the connection is accepted and never answered.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let bound = Duration::from_millis(200);
        let listed = timeout(Duration::from_secs(5), list_pages_within(port, bound))
            .await
            .expect("the page list returned within its bound");
        let error = listed.expect_err("an endpoint that never answers lists no pages");
        assert!(
            format!("{error:#}").contains("no reply within 200ms"),
            "{error:#}"
        );
    }
}
