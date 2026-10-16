//! The linux leg of the two-device peer proof (R76 slice 9b), the native
//! client the run drives in place of a second phone, so pippo and the phone
//! make every join both ways.
//!
//! The leg runs in a child process of the proof binary, because the
//! client's linux keyring detection reads the process environment, which
//! the proof sets for the child alone. The child signs in as its own
//! account through a fake browser that walks the real OIDC chain, keeps its
//! refresh token and its replica key in sealed files under the evidence
//! directory, and serves a line-based JSON protocol on its standard
//! streams. The proof sends one line per command, each carrying an id, and
//! reads one line per answer, matched by the id, plus a fatal event line
//! when the client stands down. The waits the walk drives over the leg
//! poll the client's standing rather than events, so a missed broadcast
//! event cannot hold one open.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_client::{
    AccountChoice, Auth, BeaconState, BluetoothState, BrowserOpener, ClientEvent, HotspotOffer,
    HotspotSecurity, NativeClient, NativeClientBuilder, NativeTransport, SyncSchema,
};
use parking_lot::Mutex as Lock;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::Mutex as AsyncLock;
use tokio::time::{Instant, sleep, timeout};
use uuid::Uuid;

use crate::linux_proof::{LegOffer, NearbyHost, bluetooth_state, hex_prefix, single_nearby};
use crate::peer_devices::LINK_END_BOUND;
use crate::stack::DEMO_DEVICE_ROOT_VAR;

/// How long a state query gets on the leg's command stream.
const QUERY_BOUND: Duration = Duration::from_secs(15);
/// How long a leg action gets, past the backend's own bound.
const ACTION_BOUND: Duration = Duration::from_secs(90);
/// How long the leg gets to sign in, enrol and serve its peer listener.
const READY_BOUND: Duration = Duration::from_secs(120);
/// How long the leg's scan gets to find the host's beacon.
const NEARBY_BOUND: Duration = Duration::from_secs(60);
/// How long the leg gets to close once the proof asks it.
const CLOSE_BOUND: Duration = Duration::from_secs(30);

/// The data directory the leg keeps its replica in, which the proof names.
const DATA_VAR: &str = "CONNETTO_LINUX_LEG_DATA";
/// The account the leg signs in as, beside the phone's own.
const LEG_USER: &str = "bob";
/// The keyring service the leg's sealed records name.
const LEG_SERVICE: &str = "connetto-linux-proof";
/// The provider name the demo stack registers.
const PROVIDER: &str = "dev-idp";

/// The proof's side of the leg, which is the child process, its command
/// stream and the waits the walk drives over it.
pub struct LegClient {
    child: AsyncLock<Child>,
    stdin: AsyncLock<Option<ChildStdin>>,
    next_id: AtomicU64,
    waiters: Arc<Lock<HashMap<u64, tokio::sync::oneshot::Sender<serde_json::Value>>>>,
    log: Arc<Lock<Vec<String>>>,
}

/// Drive the leg, the child process of the proof binary, which signs in,
/// enrols and serves the command protocol until the proof asks it to close.
///
/// # Errors
///
/// When a named environment is missing, the demo schema does not translate,
/// the sign-in or the enrolment fails, or the command stream breaks.
pub async fn run_leg() -> Result<()> {
    // The leg's own steps land in `linux-leg.log` beside the evidence, the
    // radios' and the link's included.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,connetto_client::bluetooth=debug,connetto_client::hotspot=debug,connetto_peer=debug",
        ))
        .with_writer(std::io::stderr)
        .try_init();
    let data_dir =
        std::env::var(DATA_VAR).map_err(|_| anyhow!("{DATA_VAR} is unset, run under the proof"))?;
    let ws_url = std::env::var("CONNETTO_DEMO_WS")
        .map_err(|_| anyhow!("CONNETTO_DEMO_WS is unset, run under connetto-demo-stack"))?;
    let auth_origin = std::env::var("CONNETTO_DEMO_AUTH_ORIGIN").map_err(|_| {
        anyhow!("CONNETTO_DEMO_AUTH_ORIGIN is unset, run under connetto-demo-stack")
    })?;
    let root_path = std::env::var(DEMO_DEVICE_ROOT_VAR)
        .map_err(|_| anyhow!("{DEMO_DEVICE_ROOT_VAR} is unset, run under connetto-demo-stack"))?;
    let root = tokio::fs::read(&root_path)
        .await
        .with_context(|| format!("reading the demo's device root {root_path}"))?;
    let demo = crate::stack::repo_path(&["examples", "dioxus-desktop-demo"])?;
    let schema_sql = tokio::fs::read_to_string(demo.join("schema.sql"))
        .await
        .context("reading the demo schema")?;
    let policies_sql = tokio::fs::read_to_string(demo.join("policies.sql"))
        .await
        .context("reading the demo policies")?;
    let bundle =
        connetto_schema::translate::<String, connetto_schema::TextIds>(&schema_sql, &policies_sql)
            .map_err(|err| anyhow!("the demo schema does not translate: {err}"))?;

    tokio::fs::create_dir_all(&data_dir)
        .await
        .with_context(|| format!("creating the leg's data directory {data_dir}"))?;
    let failure = Arc::new(Lock::new(None));
    let sign_in = Auth::new(auth_origin, PROVIDER)
        .with_account(AccountChoice::New)
        .keyring(LEG_SERVICE)
        .with_browser_opener(fake_browser(LEG_USER, Arc::clone(&failure)));
    let connect = NativeClientBuilder::new(ws_url, SyncSchema::new(bundle))
        .signed_in(sign_in)
        .durable(data_dir.as_str())
        .with_deployment_roots([root])
        // With autolink on, the leg's join dials the gateway at the offer's port.
        .with_peer_autolink(true)
        .connect();
    let client = Box::pin(connect).await.map_err(|err| {
        let detail = failure.lock().take();
        match detail {
            Some(detail) => {
                anyhow!("the linux leg never signed in: {err:#}, the fake browser: {detail}")
            }
            None => anyhow!("the linux leg never signed in: {err:#}"),
        }
    })?;
    serve(client).await
}

/// The command loop, one JSON line per command and one per answer, until
/// the proof asks it to close or its stream ends.
///
/// # Errors
///
/// When the command stream breaks or the leg's answer stream closes.
async fn serve(client: NativeClient<NativeTransport>) -> Result<()> {
    let state = Arc::new(LegState::default());
    let (fatal, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
    let events = client.client().events();
    let pump_state = Arc::clone(&state);
    let pump_fatal = fatal.clone();
    let pump = tokio::spawn(async move {
        let mut events = events;
        while let Ok(event) = events.recv().await {
            pump_event(event, &pump_state, &pump_fatal);
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let line = match line {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) => {
                        return Err(anyhow::Error::from(err).context("reading the leg's command stream"));
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(command) = serde_json::from_str::<serde_json::Value>(&line) else {
                    let _ = write_line(&mut out, &json!({"error": "the leg read no JSON line"})).await;
                    continue;
                };
                let reply = handle_command(&client, &state, &command).await;
                if write_line(&mut out, &reply).await.is_err() {
                    return Err(anyhow!("the proof stopped reading the leg's answers"));
                }
                if command.get("cmd").and_then(serde_json::Value::as_str) == Some("close") {
                    break;
                }
            }
            Some(error) = fatal_rx.recv() => {
                if write_line(&mut out, &json!({"event": "fatal", "error": error})).await.is_err() {
                    return Err(anyhow!("the proof stopped reading the leg's answers"));
                }
            }
        }
    }
    client.close().await;
    // The client still holds the event sender, so the pump never sees its
    // stream end and is stopped here.
    pump.abort();
    Ok(())
}

/// One line of the leg's answer stream.
///
/// # Errors
///
/// When the write fails.
async fn write_line(
    out: &mut (impl AsyncWriteExt + Unpin),
    value: &serde_json::Value,
) -> Result<()> {
    let mut line = value.to_string();
    line.push('\n');
    out.write_all(line.as_bytes())
        .await
        .context("writing the leg's answer")?;
    out.flush().await.context("flushing the leg's answer")
}

/// The answer to one command, its refusal carried in the line's `error`
/// field.
async fn handle_command(
    client: &NativeClient<NativeTransport>,
    state: &LegState,
    command: &serde_json::Value,
) -> serde_json::Value {
    let id = command
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cmd = command.get("cmd").and_then(serde_json::Value::as_str);
    let answer = match cmd {
        Some("identity" | "serving" | "beacon" | "bluetooth" | "linked" | "nearby" | "state") => {
            handle_query(client, state, cmd)
        }
        _ => handle_action(client, command).await,
    };
    match answer {
        Ok(value) => json!({ "id": id, "ok": true, "result": value }),
        Err(reason) => json!({ "id": id, "ok": false, "error": reason }),
    }
}

/// The answers that only read the client's standing and the leg's state.
///
/// # Errors
///
/// When the client holds no certificate or serves no listener yet.
fn handle_query(
    client: &NativeClient<NativeTransport>,
    state: &LegState,
    cmd: Option<&str>,
) -> Result<serde_json::Value, String> {
    match cmd {
        Some("identity") => client
            .device_certificate()
            .map(|cert| json!({ "identity": short_identity(cert.identity()) }))
            .ok_or_else(|| "the device holds no certificate yet".to_owned()),
        Some("serving") => client
            .peer_address()
            .map(|address| json!({ "port": address.port() }))
            .ok_or_else(|| "the device does not serve its peer listener yet".to_owned()),
        Some("beacon") => Ok(beacon_json(&client.beacon_state())),
        Some("bluetooth") => Ok(json!({ "state": client.bluetooth_state().to_string() })),
        Some("linked") => {
            let linked = state.linked.lock();
            serde_json::to_value(&**linked)
                .map(|value| json!({ "linked": value }))
                .map_err(|err| err.to_string())
        }
        Some("nearby") => {
            let nearby = state.nearby.lock();
            serde_json::to_value(&**nearby)
                .map(|value| json!({ "nearby": value }))
                .map_err(|err| err.to_string())
        }
        Some("state") => {
            let linked = state.linked.lock();
            let nearby = state.nearby.lock();
            let identity = client
                .device_certificate()
                .map(|cert| short_identity(cert.identity()));
            let port = client.peer_address().map(|address| address.port());
            let linked = serde_json::to_value(&**linked).expect("a list of names serializes");
            let nearby = serde_json::to_value(&**nearby).expect("the nearby standing serializes");
            Ok(json!({
                "identity": identity,
                "port": port,
                "bluetooth": client.bluetooth_state().to_string(),
                "beacon": beacon_json(&client.beacon_state()),
                "linked": linked,
                "nearby": nearby,
            }))
        }
        _ => Err("an unknown leg command".to_owned()),
    }
}

/// The answers that act on the network, the host's side and the joins.
///
/// # Errors
///
/// When the network will not answer or the command is malformed.
async fn handle_action(
    client: &NativeClient<NativeTransport>,
    command: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    match command.get("cmd").and_then(serde_json::Value::as_str) {
        Some("host") => match client.host_hotspot().await {
            Ok(hosted) => Ok(json!({
                "ssid": hosted.offer.ssid,
                "passphrase": hosted.offer.passphrase,
                "port": hosted.offer.port,
                "payload": hosted.offer.to_wifi_payload().to_string(),
                "beacon_off": hosted.beacon.map_err(|err| err.to_string()).ok(),
            })),
            Err(err) => Err(err.to_string()),
        },
        Some("stop") => {
            client.stop_hotspot().await;
            Ok(json!({}))
        }
        Some("leave") => {
            client.leave_hotspot().await;
            Ok(json!({}))
        }
        Some("enable-bt") => client
            .enable_bluetooth()
            .await
            .map_err(|err| err.to_string())
            .map(|()| json!({})),
        Some("join-form") => {
            let ssid = command
                .get("ssid")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let passphrase = command
                .get("passphrase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match command
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .map(u16::try_from)
                .and_then(Result::ok)
            {
                Some(port) => {
                    let offer =
                        HotspotOffer::new(ssid, passphrase, HotspotSecurity::Wpa2, Some(port));
                    join_gateway(client, &offer).await
                }
                None => Err("the join-form command names no port".to_owned()),
            }
        }
        Some("join-payload") => match command.get("payload").and_then(serde_json::Value::as_str) {
            Some(payload) => match HotspotOffer::from_wifi_payload(payload) {
                Ok(offer) => join_gateway(client, &offer).await,
                Err(err) => Err(format!("the payload does not parse: {err}")),
            },
            None => Err("the join-payload command names no payload".to_owned()),
        },
        Some("join-nearby") => match command.get("host").and_then(serde_json::Value::as_u64) {
            Some(host) => match client.join_nearby(&host).await {
                Ok((peer, gateway)) => Ok(json!({
                    "identity": short_identity(&peer),
                    "gateway": gateway.to_string(),
                })),
                Err(err) => Err(err.to_string()),
            },
            None => Err("the join-nearby command names no host".to_owned()),
        },
        Some("close") => Ok(json!({})),
        _ => Err("an unknown leg command".to_owned()),
    }
}

/// The join call with its gateway answer, the two join commands share it.
///
/// # Errors
///
/// When the hotspot's join will not go.
async fn join_gateway(
    client: &NativeClient<NativeTransport>,
    offer: &HotspotOffer,
) -> Result<serde_json::Value, String> {
    client
        .join_hotspot(offer)
        .await
        .map(|gateway| json!({ "gateway": gateway.to_string() }))
        .map_err(|err| err.to_string())
}

/// One event of the client's event stream, kept in the leg's standing for
/// the proof to poll.
fn pump_event(
    event: ClientEvent,
    state: &LegState,
    fatal: &tokio::sync::mpsc::UnboundedSender<String>,
) {
    let fatal_line = |line: String| {
        let _ = fatal.send(line);
    };
    match event {
        ClientEvent::PeerLinked { peer } => {
            state.linked.lock().push(short_identity(&peer));
        }
        ClientEvent::PeerUnlinked { peer, .. } => {
            let held = short_identity(&peer);
            state.linked.lock().retain(|name| *name != held);
        }
        ClientEvent::HostNearby { host, prefix, rssi } => {
            let entry = NearbyHost {
                host,
                prefix: prefix.map(hex_prefix),
                rssi,
            };
            let mut nearby = state.nearby.lock();
            if let Some(same) = nearby.iter_mut().find(|held| held.host == host) {
                *same = entry;
            } else {
                nearby.push(entry);
            }
        }
        ClientEvent::HostGone { host } => {
            state.nearby.lock().retain(|held| held.host != host);
        }
        ClientEvent::PeerListenFailed { address, error } => {
            fatal_line(format!(
                "the peer listener could not bind {address}: {error}"
            ));
        }
        ClientEvent::CertificateExpired => {
            fatal_line("the device certificate is expired".to_owned());
        }
        ClientEvent::DeviceRevoked => {
            fatal_line("the device was revoked".to_owned());
        }
        ClientEvent::CertificateWithdrawn => {
            fatal_line("the device certificate was withdrawn".to_owned());
        }
        ClientEvent::ClockOutsideWindow { ahead } => {
            fatal_line(format!(
                "the device clock is outside the certificate window, ahead {ahead}"
            ));
        }
        ClientEvent::AttestationRequired => {
            fatal_line("the server requires attestation".to_owned());
        }
        _ => {}
    }
}

/// The identity's short form, `account` over the key's first 8 hex digits,
/// which the demo pages show and the proof matches against.
fn short_identity(identity: &connetto_core::device_cert::DeviceIdentity) -> String {
    let key = identity.key().to_string();
    let prefix = key.get(..8).unwrap_or_default();
    format!("{}/{prefix}", identity.account())
}

/// The beacon's answer fields, advertising with its prefix or off with its
/// reason.
fn beacon_json(state: &BeaconState) -> serde_json::Value {
    match state {
        BeaconState::Advertising { prefix } => json!({ "prefix": hex_prefix(*prefix) }),
        BeaconState::Off { reason } => json!({ "beacon_off": reason }),
    }
}

/// A browser opener that walks the real OIDC chain for `subject`, posting
/// the login form where the chain names it, until the authenticator's
/// loopback listener takes the code. A broken chain records its failure,
/// which the sign-in's error carries.
fn fake_browser(subject: &str, failure: Arc<Lock<Option<String>>>) -> BrowserOpener {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a plain http client");
    let subject = subject.to_owned();
    Arc::new(move |login_url: &str| {
        let http = http.clone();
        let subject = subject.clone();
        let failure = Arc::clone(&failure);
        let login_url = login_url.to_owned();
        tokio::spawn(async move {
            let mut next_url = login_url;
            let mut submitted = false;
            for _ in 0..6 {
                let resp = match http.get(&next_url).send().await {
                    Ok(resp) => resp,
                    Err(err) => {
                        *failure.lock() = Some(format!("the hop to {next_url} failed: {err}"));
                        return;
                    }
                };
                if !submitted && resp.url().path().ends_with("/authorize") {
                    let form_url = resp.url().to_string();
                    let posted = match http
                        .post(form_url.as_str())
                        .header(
                            reqwest::header::CONTENT_TYPE,
                            "application/x-www-form-urlencoded",
                        )
                        .body(format!("username={subject}"))
                        .send()
                        .await
                    {
                        Ok(posted) => posted,
                        Err(err) => {
                            *failure.lock() =
                                Some(format!("the login form to {form_url} failed: {err}"));
                            return;
                        }
                    };
                    submitted = true;
                    let Some(loc) = posted.headers().get(reqwest::header::LOCATION) else {
                        *failure.lock() =
                            Some(format!("the login form at {form_url} answered no location"));
                        return;
                    };
                    let Ok(loc) = loc.to_str() else {
                        *failure.lock() = Some("the login form's location is not utf8".to_owned());
                        return;
                    };
                    loc.clone_into(&mut next_url);
                    continue;
                }
                match resp.headers().get(reqwest::header::LOCATION) {
                    Some(loc) => match loc.to_str() {
                        Ok(loc) => loc.clone_into(&mut next_url),
                        Err(err) => {
                            *failure.lock() = Some(format!("a location is not utf8: {err}"));
                            return;
                        }
                    },
                    None => break,
                }
            }
        });
        Ok(())
    })
}

/// The leg's standing the proof polls between commands.
#[derive(Default)]
struct LegState {
    linked: Lock<Vec<String>>,
    nearby: Lock<Vec<NearbyHost>>,
}

impl LegClient {
    /// Start the leg under `evidence`, giving it a fresh credential and state
    /// directory with a fresh wrap key, the data directory beside them, and
    /// the child re-running this binary as its own process.
    ///
    /// # Errors
    ///
    /// When the directories cannot be made or the child will not start.
    pub async fn spawn(evidence: &Path) -> Result<Self> {
        let dir = evidence.join("linux-leg");
        let credentials = dir.join("credentials");
        let state = dir.join("state");
        let data = dir.join("data");
        for path in [&credentials, &state, &data] {
            tokio::fs::create_dir_all(path)
                .await
                .with_context(|| format!("creating {}", path.display()))?;
        }
        let mut wrap_key = Vec::with_capacity(32);
        wrap_key.extend_from_slice(Uuid::new_v4().as_bytes());
        wrap_key.extend_from_slice(Uuid::new_v4().as_bytes());
        tokio::fs::write(credentials.join("connetto.wrap-key"), &wrap_key)
            .await
            .context("writing the leg's wrap key")?;
        let program = std::env::current_exe().context("finding the proof binary")?;
        let mut child = tokio::process::Command::new(program)
            .arg("--linux-leg")
            .env("CREDENTIALS_DIRECTORY", &credentials)
            .env("STATE_DIRECTORY", &state)
            .env(DATA_VAR, &data)
            // A portal marker in the proof's environment would send the
            // child's keyring detection to the sandbox instead of the
            // sealed files.
            .env_remove("DESKTOP_PORTAL")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting the linux leg")?;
        let stdin = child.stdin.take().context("the leg has no stdin")?;
        let stdout = child.stdout.take().context("the leg has no stdout")?;
        let stderr = child.stderr.take().context("the leg has no stderr")?;
        let child = AsyncLock::new(child);
        let log = Arc::new(Lock::new(Vec::new()));
        let log_lines = Arc::clone(&log);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[leg] {line}");
                log_lines.lock().push(line);
            }
        });
        let waiters: Arc<Lock<HashMap<u64, tokio::sync::oneshot::Sender<serde_json::Value>>>> =
            Arc::new(Lock::new(HashMap::new()));
        let read_waiters = Arc::clone(&waiters);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                    eprintln!("[leg] an unparseable line: {line}");
                    continue;
                };
                if let Some(id) = value.get("id").and_then(serde_json::Value::as_u64) {
                    if let Some(waiter) = read_waiters.lock().remove(&id) {
                        let _ = waiter.send(value);
                    }
                } else if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
                    eprintln!("[leg] fatal: {error}");
                }
            }
        });
        Ok(Self {
            child,
            stdin: AsyncLock::new(Some(stdin)),
            next_id: AtomicU64::new(0),
            waiters,
            log,
        })
    }

    /// One command over the stream, answered within `bound` on the
    /// monotonic clock.
    ///
    /// # Errors
    ///
    /// When the leg will not answer, closes its stream or answers with a
    /// refusal.
    async fn request(
        &self,
        command: &'static str,
        body: serde_json::Value,
        bound: Duration,
    ) -> Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.waiters.lock().insert(id, sender);
        let mut request = body;
        request["id"] = json!(id);
        request["cmd"] = json!(command);
        let mut line = serde_json::to_string(&request)
            .map_err(|err| anyhow!("encoding the {command} command: {err}"))?;
        line.push('\n');
        let written = {
            let mut guard = self.stdin.lock().await;
            match guard.as_mut() {
                Some(stdin) => match stdin.write_all(line.as_bytes()).await {
                    Ok(()) => stdin.flush().await,
                    Err(err) => Err(err),
                },
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "the leg's stdin is closed",
                )),
            }
        };
        if let Err(err) = written {
            self.waiters.lock().remove(&id);
            if self.exited().await {
                bail!("the linux leg exited before it took {command}");
            }
            bail!("writing {command} to the linux leg: {err}");
        }
        let answer = match timeout(bound, receiver).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => bail!("the linux leg closed its stream without answering {command}"),
            Err(_) => {
                self.waiters.lock().remove(&id);
                if self.exited().await {
                    bail!("the linux leg exited before it answered {command}");
                }
                bail!("the linux leg gave no {command} answer within {bound:?}");
            }
        };
        if answer.get("ok") != Some(&json!(true)) {
            let reason = answer
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("an unnamed refusal");
            bail!("the linux leg refused {command}: {reason}");
        }
        Ok(answer
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// Whether the leg's process has exited.
    async fn exited(&self) -> bool {
        self.child
            .lock()
            .await
            .try_wait()
            .is_ok_and(|exit| exit.is_some())
    }

    /// The leg's own peer identity, which its enrolment stands up.
    ///
    /// # Errors
    ///
    /// When the leg answers a refusal or gives no answer within the bound.
    pub async fn identity(&self) -> Result<String> {
        let answer = self.request("identity", json!({}), QUERY_BOUND).await?;
        answer
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("the identity answer names no identity"))
    }

    /// The port the leg serves its peer listener on.
    ///
    /// # Errors
    ///
    /// When the listener does not serve or the leg gives no answer within
    /// the bound.
    pub async fn serving(&self) -> Result<u16> {
        let answer = self.request("serving", json!({}), QUERY_BOUND).await?;
        answer
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .map(u16::try_from)
            .and_then(Result::ok)
            .ok_or_else(|| anyhow!("the serving answer names no port"))
    }

    /// The beacon's prefix as 16 hex digits, while the beacon advertises.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn beacon(&self) -> Result<Option<String>> {
        let answer = self.request("beacon", json!({}), QUERY_BOUND).await?;
        Ok(answer
            .get("prefix")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }

    /// The leg's Bluetooth standing, as the client reads it.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn bluetooth(&self) -> Result<BluetoothState> {
        let answer = self.request("bluetooth", json!({}), QUERY_BOUND).await?;
        let text = answer
            .get("state")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("the bluetooth answer names no state"))?;
        Ok(bluetooth_state(text))
    }

    /// The peers the leg names as linked, its short identities.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn linked(&self) -> Result<Vec<String>> {
        let answer = self.request("linked", json!({}), QUERY_BOUND).await?;
        let list = answer
            .get("linked")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("the linked answer names no list"))?;
        Ok(list
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect())
    }

    /// The hosts the leg's scan stands on, as its standing.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn nearby(&self) -> Result<Vec<NearbyHost>> {
        let answer = self.request("nearby", json!({}), QUERY_BOUND).await?;
        let list = answer
            .get("nearby")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow!("the nearby answer names no list"))?;
        list.iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<NearbyHost>, _>>()
            .map_err(|err| anyhow!("the nearby answer names no host: {err}"))
    }

    /// The leg's full standing, for the run's state files.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn state(&self) -> Result<serde_json::Value> {
        self.request("state", json!({}), QUERY_BOUND).await
    }

    /// Host a hotspot from the leg and read the offer it stands on.
    ///
    /// # Errors
    ///
    /// When the hotspot will not host or the leg gives no answer within
    /// the bound.
    pub async fn host(&self) -> Result<LegOffer> {
        let answer = self.request("host", json!({}), ACTION_BOUND).await?;
        serde_json::from_value(answer).context("reading the host answer")
    }

    /// Stop the hotspot the leg hosts.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn stop(&self) -> Result<()> {
        self.request("stop", json!({}), ACTION_BOUND)
            .await
            .map(drop)
    }

    /// Leave the hotspot the leg joined.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn leave(&self) -> Result<()> {
        self.request("leave", json!({}), ACTION_BOUND)
            .await
            .map(drop)
    }

    /// Turn the leg's Bluetooth on, the platform's action inside the call.
    ///
    /// # Errors
    ///
    /// As [`LegClient::identity`].
    pub async fn enable_bluetooth(&self) -> Result<()> {
        self.request("enable-bt", json!({}), ACTION_BOUND)
            .await
            .map(drop)
    }

    /// Join the phone's hotspot by the form's three lines.
    ///
    /// # Errors
    ///
    /// When the hotspot's join will not go or the leg gives no answer
    /// within the bound.
    pub async fn join_form(&self, ssid: &str, passphrase: &str, port: u16) -> Result<IpAddr> {
        let answer = self
            .request(
                "join-form",
                json!({ "ssid": ssid, "passphrase": passphrase, "port": port }),
                ACTION_BOUND,
            )
            .await?;
        gateway(&answer)
    }

    /// Join the phone's hotspot through its `WIFI:` payload.
    ///
    /// # Errors
    ///
    /// As [`LegClient::join_form`].
    pub async fn join_payload(&self, payload: &str) -> Result<IpAddr> {
        let answer = self
            .request("join-payload", json!({ "payload": payload }), ACTION_BOUND)
            .await?;
        gateway(&answer)
    }

    /// Join the nearby host the leg's scan stands on, through the exchange
    /// behind its beacon.
    ///
    /// # Errors
    ///
    /// As [`LegClient::join_form`].
    pub async fn join_nearby(&self, host: &u64) -> Result<(String, IpAddr)> {
        let answer = self
            .request("join-nearby", json!({ "host": host }), ACTION_BOUND)
            .await?;
        let identity = answer
            .get("identity")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("the join-nearby answer names no identity"))?;
        Ok((identity, gateway(&answer)?))
    }

    /// Hold until the leg has signed in, enrolled and served its peer
    /// listener, which the walk needs before its first join.
    ///
    /// # Errors
    ///
    /// When the leg exits or never stands within the bound.
    pub async fn wait_ready(&self) -> Result<(String, u16)> {
        let deadline = Instant::now() + READY_BOUND;
        loop {
            let identity = self.identity().await;
            let serving = self.serving().await;
            match (identity, serving) {
                (Ok(identity), Ok(serving)) => return Ok((identity, serving)),
                (Err(err), _) | (_, Err(err)) => {
                    if self.exited().await {
                        bail!("the linux leg exited before it stood: {err:#}");
                    }
                    if Instant::now() >= deadline {
                        bail!("the linux leg never stood within {READY_BOUND:?}: {err:#}");
                    }
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Hold until the leg names `peer` as linked, polling its standing.
    ///
    /// # Errors
    ///
    /// When the leg never names `peer` within `bound`.
    pub async fn wait_linked(&self, peer: &str, bound: Duration) -> Result<()> {
        let deadline = Instant::now() + bound;
        loop {
            let linked = self.linked().await?;
            if linked.iter().any(|held| held == peer) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("the linux leg never named {peer} as linked, it names: {linked:?}");
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    /// Hold until the leg drops `peer` from its linked list, which the
    /// leave and the stop end the link.
    ///
    /// # Errors
    ///
    /// When the leg still names `peer` past [`LINK_END_BOUND`].
    pub async fn wait_unlinked(&self, peer: &str) -> Result<()> {
        let deadline = Instant::now() + LINK_END_BOUND;
        loop {
            let linked = self.linked().await?;
            if !linked.iter().any(|held| held == peer) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("the linux leg still names {peer} as linked after the leave and the stop");
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Hold until the leg's scan stands the host whose beacon carries
    /// `prefix` and it alone, which the beacon join names to the walk.
    ///
    /// # Errors
    ///
    /// When the leg never stands a lone host with the prefix within the
    /// bound.
    pub async fn wait_nearby(&self, prefix: &str) -> Result<u64> {
        let deadline = Instant::now() + NEARBY_BOUND;
        loop {
            let hosts = self.nearby().await?;
            if let Some(host) = single_nearby(&hosts, prefix) {
                return Ok(host);
            }
            if Instant::now() >= deadline {
                bail!(
                    "the linux leg never stood a lone host with the beacon prefix {prefix}, \
                     it stands: {hosts:?}"
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Hold until the leg's beacon advertises, which the host stands up
    /// beside the hotspot.
    ///
    /// # Errors
    ///
    /// When the beacon never advertises within the bound.
    pub async fn wait_beacon(&self) -> Result<String> {
        let deadline = Instant::now() + NEARBY_BOUND;
        loop {
            if let Some(prefix) = self.beacon().await? {
                return Ok(prefix);
            }
            if Instant::now() >= deadline {
                bail!("the linux leg's beacon never advertised within {NEARBY_BOUND:?}");
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Hold until the leg serves its peer listener.
    ///
    /// # Errors
    ///
    /// When the listener never serves within the bound.
    pub async fn wait_serving(&self) -> Result<u16> {
        let deadline = Instant::now() + NEARBY_BOUND;
        loop {
            if let Ok(port) = self.serving().await {
                return Ok(port);
            }
            if Instant::now() >= deadline {
                bail!("the linux leg never served its peer listener within {NEARBY_BOUND:?}");
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Ask the leg to close and hold until it exits, killing it past the
    /// bound.
    ///
    /// # Errors
    ///
    /// When the leg does not close within the bound or exits on its own.
    pub async fn close(&self) -> Result<()> {
        let _ = self.request("close", json!({}), CLOSE_BOUND).await;
        // The leg's stdin read sits in the runtime's blocking pool, which
        // a shutdown waits for. Dropping the pipe ends it on EOF.
        self.stdin.lock().await.take();
        let deadline = Instant::now() + CLOSE_BOUND;
        loop {
            let exit = self.child.lock().await.try_wait();
            match exit {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    bail!("the linux leg exited with {status} while the proof asked it to close");
                }
                Err(err) => bail!("reading the linux leg's exit: {err}"),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let mut child = self.child.lock().await;
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        bail!("the linux leg did not close within {CLOSE_BOUND:?}");
                    }
                    sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// The leg's standard error so far, for the run's evidence.
    pub fn take_log(&self) -> String {
        let mut lines = self.log.lock();
        std::mem::take(&mut *lines).join("\n")
    }
}

/// The gateway a join answer names, as an address.
///
/// # Errors
///
/// When the answer names no gateway or names one that does not parse.
fn gateway(answer: &serde_json::Value) -> Result<IpAddr> {
    let text = answer
        .get("gateway")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("the join answer names no gateway"))?;
    text.parse()
        .map_err(|err| anyhow!("the join answer names no gateway address: {err}"))
}
