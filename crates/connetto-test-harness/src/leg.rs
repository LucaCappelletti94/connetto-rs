//! The leg of the two-device peer proof (R76 slices 9b and 9c), the native
//! client the run drives in place of a second phone, so the phone and the
//! leg make every join both ways.
//!
//! The leg runs in a child process of the proof binary. On linux that is a
//! direct spawn, since the client's keyring detection reads the process
//! environment, which the proof sets for the child alone. On macos it is a
//! signed `ConnettoProofLeg.app` started through `open`, so Launch
//! Services stands the leg as its own responsible process, its grants
//! persist across runs, and its secrets sit in the login keychain, which
//! the bundle reaches without a provisioning profile. The child signs in
//! as its own account through a fake browser that walks the real OIDC
//! chain, keeps its refresh token and its replica key in sealed files
//! under the evidence directory, and serves a line-based JSON protocol on
//! its standard streams. The proof sends one line per command, each
//! carrying an id, and reads one line per answer, matched by the id, plus
//! a fatal event line when the client stands down. The `linked` and
//! `nearby` answers read the client's own standing, so a missed broadcast
//! event leaves nothing stale, and the pump keeps the one-shot fatal
//! notices. A lag is itself a fatal line, since a missed fatal notice
//! cannot be read back.

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_client::{
    AccountChoice, Auth, BeaconState, BluetoothError, BluetoothState, BrowserOpener, ClientEvent,
    Gate, HotspotError, HotspotOffer, HotspotSecurity, JoinError, JoinNearbyError, NativeClient,
    NativeClientBuilder, NativeTransport, SyncSchema, WifiPayloadError,
};
use parking_lot::Mutex as Lock;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncLock;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, sleep, timeout};
use uuid::Uuid;

#[cfg(target_os = "macos")]
use crate::leg_wire::info_plist;
use crate::leg_wire::{LegOffer, NearbyHost, bluetooth_state, hex_prefix, single_nearby};
use crate::peer_devices::LINK_END_BOUND;
use crate::stack::DEMO_DEVICE_ROOT_VAR;
#[cfg(target_os = "macos")]
use crate::stack::repo_path;

/// The leg's command stream end the proof writes through, a pipe on linux
/// and the fifos' write end on macos.
#[cfg(not(target_os = "macos"))]
type LegIn = tokio::process::ChildStdin;
/// The leg's answer stream end the proof reads from, a pipe on linux and
/// the fifos' read end on macos.
#[cfg(not(target_os = "macos"))]
type LegOut = tokio::process::ChildStdout;
/// The leg's command stream end the proof writes through, the fifos' write
/// end.
#[cfg(target_os = "macos")]
type LegIn = tokio::net::unix::pipe::Sender;
/// The leg's answer stream end the proof reads from, the fifos' read end.
#[cfg(target_os = "macos")]
type LegOut = tokio::net::unix::pipe::Receiver;

/// How long a state query gets on the leg's command stream.
const QUERY_BOUND: Duration = Duration::from_secs(15);
/// How long a leg action gets, past the backend's own bound.
const ACTION_BOUND: Duration = Duration::from_secs(90);
/// How long the leg gets to sign in, enrol and serve its peer listener.
const READY_BOUND: Duration = Duration::from_secs(120);
/// How long the leg's own sign-in and enrolment get, inside [`READY_BOUND`],
/// so a failed sign-in ends the leg with its reason before the proof gives up.
const SIGN_IN_BOUND: Duration = Duration::from_secs(90);
/// How long the leg's scan gets to find the host's beacon.
const NEARBY_BOUND: Duration = Duration::from_secs(60);
/// How long the leg gets to close once the proof asks it.
const CLOSE_BOUND: Duration = Duration::from_secs(30);

/// How long the platform's location prompt gets a grant, which the leg's
/// first join on macos asks.
#[cfg(target_os = "macos")]
const GRANT_BOUND: Duration = Duration::from_secs(300);
/// How long a join command gets, past the location grant the leg's first
/// join on macos waits on.
#[cfg(target_os = "macos")]
const JOIN_BOUND: Duration = ACTION_BOUND.saturating_add(GRANT_BOUND);
/// How long a join command gets.
#[cfg(not(target_os = "macos"))]
const JOIN_BOUND: Duration = ACTION_BOUND;

/// The data directory the leg keeps its replica in, which the proof names.
#[cfg(not(target_os = "macos"))]
const DATA_VAR: &str = "CONNETTO_LINUX_LEG_DATA";
/// The evidence subdirectory the leg's directories sit in.
#[cfg(not(target_os = "macos"))]
const LEG_DIR: &str = "linux-leg";
/// The keyring service the leg's sealed records name.
#[cfg(not(target_os = "macos"))]
const LEG_SERVICE: &str = "connetto-linux-proof";
/// The data directory the leg keeps its replica in, which the proof names.
#[cfg(target_os = "macos")]
const DATA_VAR: &str = "CONNETTO_MAC_LEG_DATA";
/// The evidence subdirectory the leg's directories and fifos sit in.
#[cfg(target_os = "macos")]
const LEG_DIR: &str = "mac-leg";
/// The keyring service the leg's login keychain items name.
#[cfg(target_os = "macos")]
const LEG_SERVICE: &str = "connetto-mac-proof";
/// The bundle the mac leg stands in, beside the run's evidence.
#[cfg(target_os = "macos")]
const LEG_BUNDLE: &str = "ConnettoProofLeg.app";
/// The executable the bundle carries, a copy of the running proof binary.
#[cfg(target_os = "macos")]
const LEG_EXECUTABLE: &str = "ConnettoProofLeg";
/// The account the leg signs in as, beside the phone's own.
const LEG_USER: &str = "bob";
/// The provider name the demo stack registers.
const PROVIDER: &str = "dev-idp";

/// The proof's side of the leg, which is the child process, its command
/// stream and the waits the walk drives over it.
pub struct LegClient {
    child: AsyncLock<Child>,
    stdin: AsyncLock<Option<LegIn>>,
    next_id: AtomicU64,
    answers: Arc<Answers>,
    log: Arc<Lock<Vec<String>>>,
}

/// The leg's answer stream as the proof reads it, each answer handed to
/// its waiting command, and the first fatal line kept as the cause every
/// later command fails with.
#[derive(Default)]
struct Answers {
    waiters: Lock<HashMap<u64, tokio::sync::oneshot::Sender<serde_json::Value>>>,
    fatal: Lock<Option<String>>,
}

impl Answers {
    /// One line of the leg's answer stream.
    fn route(&self, line: &str) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            eprintln!("[leg] an unparseable line: {line}");
            return;
        };
        if let Some(id) = value.get("id").and_then(serde_json::Value::as_u64) {
            if let Some(waiter) = self.waiters.lock().remove(&id) {
                let _ = waiter.send(value);
            }
        } else if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
            eprintln!("[leg] fatal: {error}");
            self.fatal.lock().get_or_insert_with(|| error.to_owned());
            // The dropped senders end every pending wait on the cause.
            self.waiters.lock().clear();
        }
    }

    /// The fatal line's cause, once the leg stood down.
    fn fatal(&self) -> Option<String> {
        self.fatal.lock().clone()
    }
}

/// Drive the leg in its own process, the child of the proof binary, the
/// sign in, the enrolment and the command protocol until the proof asks it
/// to close.
///
/// # Errors
///
/// When a named environment is missing, the demo schema does not translate,
/// the sign-in or the enrolment fails, or the command stream breaks.
pub async fn run_leg() -> Result<()> {
    // The leg's own steps land in its log file beside the evidence, the
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
    let demo = crate::stack::repo_path(&["examples", "deployment"])?;
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
        // The leg runs unattended, so its secrets stand ungated on every
        // platform, as Linux keeps them, and no Touch ID prompt waits.
        .with_gate(Gate::off())
        .with_deployment_roots([root])
        // With autolink on, the leg's join dials the gateway at the offer's port.
        .with_peer_autolink(true)
        .connect();
    // A login whose browser hop failed waits on its loopback callback with
    // no end, so the sign-in gets a bound that names the hop's failure.
    let connected = timeout(SIGN_IN_BOUND, Box::pin(connect)).await;
    let browser = || {
        failure.lock().take().map_or_else(String::new, |detail| {
            format!(", the fake browser: {detail}")
        })
    };
    let client = match connected {
        Ok(Ok(client)) => client,
        Ok(Err(err)) => bail!("the leg never signed in: {err:#}{}", browser()),
        Err(_) => bail!(
            "the leg did not sign in within {SIGN_IN_BOUND:?}{}",
            browser()
        ),
    };
    serve(client).await
}

/// Run the leg as a process of its own, the sign in, the enrolment and the
/// command protocol on the process's standard streams.
///
/// On macos the main thread stands the platform's main queue draining,
/// which the Location Services prompt and its reads stand on, and the leg
/// itself runs on a worker thread's runtime, which ends the process when
/// it answers.
///
/// # Errors
///
/// As [`run_leg`].
pub fn leg_process() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("starting the leg's runtime")?;
    #[cfg(target_os = "macos")]
    {
        std::thread::spawn(move || match runtime.block_on(run_leg()) {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                eprintln!("the mac leg stood down: {err:#}");
                std::process::exit(1);
            }
        });
        dispatch2::dispatch_main();
    }
    #[cfg(not(target_os = "macos"))]
    runtime.block_on(run_leg())
}

/// The command loop, one JSON line per command and one per answer, until
/// the proof asks it to close or its stream ends.
///
/// # Errors
///
/// When the command stream breaks or the leg's answer stream closes.
async fn serve(client: NativeClient<NativeTransport>) -> Result<()> {
    let (fatal, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
    let events = client.client().events();
    let pump_fatal = fatal.clone();
    let pump = tokio::spawn(async move {
        let mut events = events;
        while pump_received(events.recv().await, &pump_fatal).is_continue() {}
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
                let reply = handle_command(&client, &command).await;
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
                // The client stood down, so the leg does too.
                break;
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
    command: &serde_json::Value,
) -> serde_json::Value {
    let id = command
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let cmd = command.get("cmd").and_then(serde_json::Value::as_str);
    let answer = match cmd {
        Some("identity" | "serving" | "beacon" | "bluetooth" | "linked" | "nearby" | "state") => {
            handle_query(client, cmd)
        }
        _ => handle_action(client, command).await,
    };
    answer_line(&id, &answer)
}

/// The line the command's answer stands, its refusal's text in the line's
/// `error` field.
fn answer_line(
    id: &serde_json::Value,
    answer: &Result<serde_json::Value, LegCommandError>,
) -> serde_json::Value {
    match answer {
        Ok(value) => json!({ "id": id, "ok": true, "result": value }),
        Err(reason) => json!({ "id": id, "ok": false, "error": reason.to_string() }),
    }
}

/// The leg's command refusals, which the answer line's `error` field
/// carries.
#[derive(Debug, thiserror::Error)]
enum LegCommandError {
    /// The command is not one the leg answers.
    #[error("an unknown leg command")]
    Unknown,
    /// The command names no field the call reads.
    #[error("the {command} command names no {field}")]
    MissingField {
        /// The command's name.
        command: &'static str,
        /// The field's name.
        field: &'static str,
    },
    /// The payload the command names does not parse.
    #[error("the payload does not parse: {0}")]
    Payload(#[from] WifiPayloadError),
    /// The client holds no certificate yet.
    #[error("the device holds no certificate yet")]
    NoCertificate,
    /// The client serves no peer listener yet.
    #[error("the device does not serve its peer listener yet")]
    NoListener,
    /// The client's hotspot host refused.
    #[error(transparent)]
    Host(#[from] HotspotError),
    /// The client's Bluetooth call refused.
    #[error(transparent)]
    Bluetooth(#[from] BluetoothError),
    /// The client's hotspot join refused.
    #[error(transparent)]
    Join(#[from] JoinError),
    /// The client's nearby join refused.
    #[error(transparent)]
    NearbyJoin(#[from] JoinNearbyError),
    /// The platform's location access stands denied.
    #[cfg(target_os = "macos")]
    #[error("location access stands denied")]
    LocationDenied,
    /// The platform's location access never settled to a grant.
    #[cfg(target_os = "macos")]
    #[error("location access never stood granted within {0:?}")]
    LocationUnsettled(Duration),
}

/// The answers that read the client's standing.
///
/// # Errors
///
/// When the client holds no certificate or serves no listener yet, or the
/// command is unknown.
fn handle_query(
    client: &NativeClient<NativeTransport>,
    cmd: Option<&str>,
) -> Result<serde_json::Value, LegCommandError> {
    match cmd {
        Some("identity") => client
            .device_certificate()
            .map(|cert| json!({ "identity": short_identity(cert.identity()) }))
            .ok_or(LegCommandError::NoCertificate),
        Some("serving") => client
            .peer_address()
            .map(|address| json!({ "port": address.port() }))
            .ok_or(LegCommandError::NoListener),
        Some("beacon") => Ok(beacon_json(&client.beacon_state())),
        Some("bluetooth") => Ok(json!({ "state": client.bluetooth_state().to_string() })),
        Some("linked") => Ok(json!({
            "linked": client.linked_peers().iter().map(|link| short_identity(&link.peer)).collect::<Vec<_>>(),
        })),
        Some("nearby") => Ok(json!({ "nearby": nearby_entries(&client.nearby_hosts()) })),
        Some("state") => {
            let identity = client
                .device_certificate()
                .map(|cert| short_identity(cert.identity()));
            let port = client.peer_address().map(|address| address.port());
            Ok(json!({
                "identity": identity,
                "port": port,
                "bluetooth": client.bluetooth_state().to_string(),
                "beacon": beacon_json(&client.beacon_state()),
                "linked": client
                    .linked_peers()
                    .iter()
                    .map(|link| short_identity(&link.peer))
                    .collect::<Vec<_>>(),
                "nearby": nearby_entries(&client.nearby_hosts()),
            }))
        }
        _ => Err(LegCommandError::Unknown),
    }
}

/// The answers that act on the network, the host's side and the joins.
///
/// # Errors
///
/// When the client's call refuses, a field or payload is missing or
/// unparseable, or the command is unknown.
async fn handle_action(
    client: &NativeClient<NativeTransport>,
    command: &serde_json::Value,
) -> Result<serde_json::Value, LegCommandError> {
    match command.get("cmd").and_then(serde_json::Value::as_str) {
        Some("host") => match client.host_hotspot().await {
            Ok(hosted) => Ok(json!({
                "ssid": hosted.offer.ssid,
                "passphrase": hosted.offer.passphrase,
                "port": hosted.offer.port,
                "payload": hosted.offer.to_wifi_payload().to_string(),
                "beacon_off": hosted.beacon.map_err(|err| err.to_string()).ok(),
            })),
            Err(err) => Err(err.into()),
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
            .map_err(LegCommandError::Bluetooth)
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
                None => Err(LegCommandError::MissingField {
                    command: "join-form",
                    field: "port",
                }),
            }
        }
        Some("join-payload") => match command.get("payload").and_then(serde_json::Value::as_str) {
            Some(payload) => match HotspotOffer::from_wifi_payload(payload) {
                Ok(offer) => join_gateway(client, &offer).await,
                Err(err) => Err(err.into()),
            },
            None => Err(LegCommandError::MissingField {
                command: "join-payload",
                field: "payload",
            }),
        },
        Some("join-nearby") => match command.get("host").and_then(serde_json::Value::as_u64) {
            Some(host) => match client.join_nearby(&host).await {
                Ok((peer, gateway)) => Ok(json!({
                    "identity": short_identity(&peer),
                    "gateway": gateway.to_string(),
                })),
                Err(err) => Err(err.into()),
            },
            None => Err(LegCommandError::MissingField {
                command: "join-nearby",
                field: "host",
            }),
        },
        Some("close") => Ok(json!({})),
        _ => Err(LegCommandError::Unknown),
    }
}

/// The join call with its gateway answer, the two join commands share it.
///
/// # Errors
///
/// When the hotspot's join will not go, or, on macos, the location grant
/// the first join asks will not settle.
async fn join_gateway(
    client: &NativeClient<NativeTransport>,
    offer: &HotspotOffer,
) -> Result<serde_json::Value, LegCommandError> {
    let joined = client.join_hotspot(offer).await;
    #[cfg(target_os = "macos")]
    let joined = if matches!(&joined, Err(JoinError::MissingPermission(_))) {
        // macOS refuses a join by name without Location Services access,
        // so the leg asks for it the way the demo does, waits for the
        // grant and joins again (R76 slice 9c).
        request_location_grant().await?;
        client.join_hotspot(offer).await
    } else {
        joined
    };
    joined
        .map(|gateway| json!({ "gateway": gateway.to_string() }))
        .map_err(LegCommandError::Join)
}

/// One receive of the client's event stream. A lag is a fatal line, since a
/// missed one-shot fatal notice cannot be read back, and a close ends the
/// pump.
fn pump_received(
    received: Result<ClientEvent, RecvError>,
    fatal: &tokio::sync::mpsc::UnboundedSender<String>,
) -> ControlFlow<()> {
    match received {
        Ok(event) => pump_event(event, fatal),
        Err(RecvError::Lagged(n)) => {
            let _ = fatal.send(format!(
                "the leg missed {n} of the client's events and may have lost a fatal notice"
            ));
        }
        Err(RecvError::Closed) => return ControlFlow::Break(()),
    }
    ControlFlow::Continue(())
}

/// Ask the platform for its location access and hold until it stands
/// granted, which the leg's first join on macos needs.
///
/// # Errors
///
/// When the standing is a denial, or never settles to a grant within
/// [`GRANT_BOUND`].
#[cfg(target_os = "macos")]
async fn request_location_grant() -> Result<(), LegCommandError> {
    use connetto_peer_apple::hotspot::{LocationAccess, location_access, request_location_access};
    if location_access() == LocationAccess::Granted {
        return Ok(());
    }
    request_location_access();
    let deadline = Instant::now() + GRANT_BOUND;
    loop {
        match location_access() {
            LocationAccess::Granted => return Ok(()),
            LocationAccess::Denied => {
                return Err(LegCommandError::LocationDenied);
            }
            LocationAccess::NotAsked => {}
        }
        if Instant::now() >= deadline {
            return Err(LegCommandError::LocationUnsettled(GRANT_BOUND));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// The one-shot fatal notices the leg reports as its fatal lines, the rest
/// of the events read the client's standing and carry nothing here.
fn pump_event(event: ClientEvent, fatal: &tokio::sync::mpsc::UnboundedSender<String>) {
    let fatal_line = |line: String| {
        let _ = fatal.send(line);
    };
    match event {
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

/// The `nearby` answer's hosts, each with its beacon's prefix in hex and
/// its last signal.
fn nearby_entries(hosts: &[connetto_client::NearbyHost]) -> Vec<serde_json::Value> {
    hosts
        .iter()
        .map(|host| {
            json!({
                "host": host.host,
                "prefix": host.prefix.map(hex_prefix),
                "rssi": host.rssi,
            })
        })
        .collect()
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

impl LegClient {
    /// Start the leg under `evidence`, giving it a fresh credential and state
    /// directory with a fresh wrap key, the data directory beside them, and
    /// the child re-running this binary as its own process, which on linux
    /// is a direct spawn and on macos a signed bundle through `open`.
    ///
    /// `identity` names the signing identity the macos bundle signs with,
    /// which the linux child ignores.
    ///
    /// # Errors
    ///
    /// When the directories cannot be made, the bundle cannot be signed or
    /// the child will not start.
    pub async fn spawn(evidence: &Path, identity: Option<&str>) -> Result<Self> {
        let dir = evidence.join(LEG_DIR);
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
        // The identity stands for the macos bundle's signature, which the
        // linux child never reads.
        #[cfg(not(target_os = "macos"))]
        let _ = identity;
        #[cfg(not(target_os = "macos"))]
        let (child, stdin, stdout, stderr) = spawn_linux(&program, &credentials, &state, &data)?;
        #[cfg(target_os = "macos")]
        let (child, stdin, stdout) = spawn_macos(&program, evidence, &data, identity).await?;
        let child = AsyncLock::new(child);
        let log = Arc::new(Lock::new(Vec::new()));
        #[cfg(not(target_os = "macos"))]
        {
            let log_lines = Arc::clone(&log);
            tokio::spawn(async move {
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    eprintln!("[leg] {line}");
                    log_lines.lock().push(line);
                }
            });
        }
        let answers = Arc::new(Answers::default());
        let read_answers = Arc::clone(&answers);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                read_answers.route(&line);
            }
        });
        Ok(Self {
            child,
            stdin: AsyncLock::new(Some(stdin)),
            next_id: AtomicU64::new(0),
            answers,
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
        self.answers.waiters.lock().insert(id, sender);
        // A fatal line that landed before the wait stood ends it here.
        if let Some(cause) = self.answers.fatal() {
            self.answers.waiters.lock().remove(&id);
            bail!("the leg stood down before {command}: {cause}");
        }
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
            self.answers.waiters.lock().remove(&id);
            if self.exited().await {
                bail!("the leg exited before it took {command}");
            }
            bail!("writing {command} to the leg: {err}");
        }
        let answer = match timeout(bound, receiver).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => match self.answers.fatal() {
                Some(cause) => {
                    bail!("the leg stood down before it answered {command}: {cause}")
                }
                None => bail!("the leg closed its stream without answering {command}"),
            },
            Err(_) => {
                self.answers.waiters.lock().remove(&id);
                if self.exited().await {
                    bail!("the leg exited before it answered {command}");
                }
                bail!("the leg gave no {command} answer within {bound:?}");
            }
        };
        if answer.get("ok") != Some(&json!(true)) {
            let reason = answer
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("an unnamed refusal");
            bail!("the leg refused {command}: {reason}");
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
                JOIN_BOUND,
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
            .request("join-payload", json!({ "payload": payload }), JOIN_BOUND)
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
            .request("join-nearby", json!({ "host": host }), JOIN_BOUND)
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
                        bail!("the leg exited before it stood: {err:#}");
                    }
                    if Instant::now() >= deadline {
                        bail!("the leg never stood within {READY_BOUND:?}: {err:#}");
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
                bail!("the leg never named {peer} as linked, it names: {linked:?}");
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
                bail!("the leg still names {peer} as linked after the leave and the stop");
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// Hold until the leg's scan stands the host whose beacon carries
    /// `prefix` and it alone, which the beacon join names to the walk, with
    /// `None` for an Apple host, whose beacon carries no prefix.
    ///
    /// # Errors
    ///
    /// When the leg never stands a lone host with the prefix within the
    /// bound.
    pub async fn wait_nearby(&self, prefix: Option<&str>) -> Result<u64> {
        let deadline = Instant::now() + NEARBY_BOUND;
        loop {
            let hosts = self.nearby().await?;
            if let Some(host) = single_nearby(&hosts, prefix) {
                return Ok(host);
            }
            if Instant::now() >= deadline {
                bail!(
                    "the leg never stood a lone host with the beacon prefix {prefix:?}, \
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
                bail!("the leg's beacon never advertised within {NEARBY_BOUND:?}");
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
                bail!("the leg never served its peer listener within {NEARBY_BOUND:?}");
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
                    bail!("the leg exited with {status} while the proof asked it to close");
                }
                Err(err) => bail!("reading the leg's exit: {err}"),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // On macos the child is `open`, so the app ends apart.
                        #[cfg(target_os = "macos")]
                        end_leg_app().await;
                        let mut child = self.child.lock().await;
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        bail!("the leg did not close within {CLOSE_BOUND:?}");
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

/// The linux leg's child, a direct spawn carrying the sealed-files keyring
/// environment the proof sets for it alone.
///
/// # Errors
///
/// When the child will not start.
#[cfg(not(target_os = "macos"))]
fn spawn_linux(
    program: &Path,
    credentials: &Path,
    state: &Path,
    data: &Path,
) -> Result<(Child, LegIn, LegOut, tokio::process::ChildStderr)> {
    let mut child = Command::new(program)
        .arg("--linux-leg")
        .env("CREDENTIALS_DIRECTORY", credentials)
        .env("STATE_DIRECTORY", state)
        .env(DATA_VAR, data)
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
    Ok((child, stdin, stdout, stderr))
}

/// The macos leg's start, the bundle built and signed, the fifos made, and
/// `open` standing the app with the stack's environment through `--env`,
/// so the platform's grants follow the bundle and the run's fifos carry
/// the leg's standard streams.
///
/// # Errors
///
/// When the bundle cannot be made or signed, a named environment is
/// missing, `open` will not start, or the app never opens the fifos.
#[cfg(target_os = "macos")]
async fn spawn_macos(
    program: &Path,
    evidence: &Path,
    data: &Path,
    identity: Option<&str>,
) -> Result<(Child, LegIn, LegOut)> {
    let identity = identity
        .map(str::to_owned)
        .context("the mac leg needs the identity connetto-ios-signing printed")?;
    crate::ios_signing::unlock().await?;
    let app = build_bundle(program, &identity).await?;
    let dir = evidence.join(LEG_DIR);
    let fifo_in = dir.join("fifo-in");
    let fifo_out = dir.join("fifo-out");
    for fifo in [&fifo_in, &fifo_out] {
        let _ = tokio::fs::remove_file(fifo).await;
        mkfifo(fifo).await?;
    }
    // The ends open before `open` runs, since the system opens the app's
    // ends inside its own launch, and a fifo open there blocks Launch
    // Services for the whole session until the other end opens.
    let (stdin, stdout) = open_fifo_ends(&fifo_in, &fifo_out)?;
    let var = |key: &str| {
        std::env::var(key).map_err(|_| anyhow!("{key} is unset, run under connetto-demo-stack"))
    };
    let ws = var("CONNETTO_DEMO_WS")?;
    let auth_origin = var("CONNETTO_DEMO_AUTH_ORIGIN")?;
    let device_root = var(DEMO_DEVICE_ROOT_VAR)?;
    let child = Command::new("open")
        .arg("-W")
        .arg("-n")
        .arg("--stdin")
        .arg(&fifo_in)
        .arg("--stdout")
        .arg(&fifo_out)
        .arg("--stderr")
        .arg(evidence.join("mac-leg.log"))
        .arg("--env")
        .arg(format!("{DATA_VAR}={}", data.display()))
        .arg("--env")
        .arg(format!("CONNETTO_DEMO_WS={ws}"))
        .arg("--env")
        .arg(format!("CONNETTO_DEMO_AUTH_ORIGIN={auth_origin}"))
        .arg("--env")
        .arg(format!("{DEMO_DEVICE_ROOT_VAR}={device_root}"))
        .arg(&app)
        .arg("--args")
        .arg("--mac-leg")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("starting open for the mac leg")?;
    Ok((child, stdin, stdout))
}

/// The leg's bundle, rebuilt for every run, the running proof binary under
/// a minimal `ConnettoProofLeg.app`, signed with the identity and verified,
/// so Launch Services stands the leg as its own responsible process.
///
/// # Errors
///
/// When the bundle cannot be made, signed or verified.
#[cfg(target_os = "macos")]
async fn build_bundle(program: &Path, identity: &str) -> Result<PathBuf> {
    let app = repo_path(&["target", "proof-leg"])?.join(LEG_BUNDLE);
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    tokio::fs::create_dir_all(&macos)
        .await
        .with_context(|| format!("creating {}", macos.display()))?;
    tokio::fs::copy(program, macos.join(LEG_EXECUTABLE))
        .await
        .with_context(|| format!("copying the proof binary into {}", app.display()))?;
    tokio::fs::write(contents.join("Info.plist"), info_plist())
        .await
        .with_context(|| "writing the bundle's Info.plist".to_string())?;
    codesign(&["--force", "--sign", identity], &app).await?;
    codesign(&["--verify", "--strict"], &app).await?;
    Ok(app)
}

/// End the leg's app by its bundle executable, which Launch Services runs
/// apart from the `open` the proof holds.
#[cfg(target_os = "macos")]
async fn end_leg_app() {
    let Ok(dir) = repo_path(&["target", "proof-leg"]) else {
        return;
    };
    let executable = dir
        .join(LEG_BUNDLE)
        .join("Contents")
        .join("MacOS")
        .join(LEG_EXECUTABLE);
    let ended = Command::new("pkill")
        .arg("-9")
        .arg("-f")
        .arg(&executable)
        .status();
    if let Err(err) = timeout(CLOSE_BOUND, ended)
        .await
        .map_err(|_| "timed out".to_owned())
        .and_then(|run| run.map_err(|err| err.to_string()))
    {
        eprintln!("the leg's app could not be ended: {err}");
    }
}

/// One `codesign` call, named with its refusal on failure.
///
/// # Errors
///
/// When `codesign` refuses.
#[cfg(target_os = "macos")]
async fn codesign(args: &[&str], path: &Path) -> Result<()> {
    let output = Command::new("codesign")
        .args(args)
        .arg(path)
        .output()
        .await
        .context("starting codesign")?;
    if !output.status.success() {
        bail!(
            "codesign {} {} failed: {}",
            args.first().copied().unwrap_or_default(),
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// One `mkfifo`, named with its refusal on failure.
///
/// # Errors
///
/// When `mkfifo` refuses.
#[cfg(target_os = "macos")]
async fn mkfifo(path: &Path) -> Result<()> {
    let output = Command::new("mkfifo")
        .arg(path)
        .output()
        .await
        .context("starting mkfifo")?;
    if !output.status.success() {
        bail!(
            "mkfifo {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// The proof's ends of the two fifos, each opened for reading and writing,
/// which never blocks, so the system's opens of the app's ends find the
/// other side already standing. The ends are polled by the runtime, never
/// read on a blocking thread, since the proof's own write end keeps the
/// answers' fifo from ever reading its end of file.
///
/// # Errors
///
/// When a fifo will not open.
#[cfg(target_os = "macos")]
fn open_fifo_ends(fifo_in: &Path, fifo_out: &Path) -> Result<(LegIn, LegOut)> {
    let open = |path: &Path| {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("opening the fifo {}", path.display()))
    };
    let writer = tokio::net::unix::pipe::Sender::from_file(open(fifo_in)?)
        .context("polling the commands' fifo")?;
    let reader = tokio::net::unix::pipe::Receiver::from_file(open(fifo_out)?)
        .context("polling the answers' fifo")?;
    Ok((writer, reader))
}

#[cfg(test)]
mod tests {
    /// A fatal line ends every pending wait and stands as the cause, the
    /// first one kept, while an answer still reaches its command.
    #[test]
    fn a_fatal_line_ends_the_waits_and_stands_as_the_cause() {
        let answers = super::Answers::default();
        let (answered, mut answer) = tokio::sync::oneshot::channel();
        answers.waiters.lock().insert(1, answered);
        answers.route(r#"{"id":1,"ok":true}"#);
        assert_eq!(
            answer.try_recv().ok(),
            Some(serde_json::json!({"id": 1, "ok": true}))
        );
        let (pending, mut waiting) = tokio::sync::oneshot::channel();
        answers.waiters.lock().insert(2, pending);
        answers.route(r#"{"event":"fatal","error":"the device was revoked"}"#);
        assert!(matches!(
            waiting.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
        answers.route(r#"{"event":"fatal","error":"a later cause"}"#);
        assert_eq!(answers.fatal().as_deref(), Some("the device was revoked"));
    }

    /// A lagged stream is a fatal line, since a missed one-shot fatal
    /// notice cannot be read back, and a closed one ends the pump.
    #[test]
    fn a_lag_stands_the_leg_down_and_a_close_ends_the_pump() {
        use tokio::sync::broadcast::error::RecvError;
        let (fatal, mut lines) = tokio::sync::mpsc::unbounded_channel();
        assert!(super::pump_received(Err(RecvError::Lagged(3)), &fatal).is_continue());
        assert_eq!(
            lines.try_recv().ok().as_deref(),
            Some("the leg missed 3 of the client's events and may have lost a fatal notice")
        );
        assert!(super::pump_received(Err(RecvError::Closed), &fatal).is_break());
        assert!(lines.try_recv().is_err());
    }

    /// The answer line's `error` field stands the refusal's text, so each
    /// variant's line stays the wire's.
    #[test]
    fn the_command_errors_stand_their_answer_lines() {
        use super::LegCommandError;

        let line = super::answer_line(&serde_json::json!("7"), &Err(LegCommandError::Unknown));
        assert_eq!(line["id"], "7");
        assert_eq!(line["ok"], false);
        assert_eq!(line["error"], "an unknown leg command");

        for (error, text) in [
            (
                LegCommandError::MissingField {
                    command: "join-form",
                    field: "port",
                },
                "the join-form command names no port",
            ),
            (
                LegCommandError::MissingField {
                    command: "join-payload",
                    field: "payload",
                },
                "the join-payload command names no payload",
            ),
            (
                LegCommandError::MissingField {
                    command: "join-nearby",
                    field: "host",
                },
                "the join-nearby command names no host",
            ),
            (
                LegCommandError::NoCertificate,
                "the device holds no certificate yet",
            ),
            (
                LegCommandError::NoListener,
                "the device does not serve its peer listener yet",
            ),
            (
                LegCommandError::Payload(connetto_client::WifiPayloadError::NotWifi),
                "the payload does not parse: the string is not a WIFI: payload",
            ),
            (
                LegCommandError::Host(connetto_client::HotspotError::NoChannel),
                "no channel is available for the hotspot",
            ),
            (
                LegCommandError::Bluetooth(connetto_client::BluetoothError::Unsupported),
                "this system has no Bluetooth",
            ),
            (
                LegCommandError::Join(connetto_client::JoinError::Declined),
                "the network is not available to this device",
            ),
            (
                LegCommandError::NearbyJoin(connetto_client::JoinNearbyError::Bluetooth(
                    connetto_client::BluetoothError::Busy,
                )),
                "an exchange is already running",
            ),
        ] {
            let line = super::answer_line(&serde_json::json!("7"), &Err(error));
            assert_eq!(line["ok"], false, "the {text} line");
            assert_eq!(line["error"], text, "the {text} line");
        }

        let line = super::answer_line(
            &serde_json::json!("7"),
            &Ok(serde_json::json!({ "port": 8080 })),
        );
        assert_eq!(line["id"], "7");
        assert_eq!(line["ok"], true);
        assert_eq!(line["result"], serde_json::json!({ "port": 8080 }));
    }

    /// The nearby answer's hosts carry the beacon's prefix in hex and the
    /// signal, and an empty scan stands an empty list.
    #[test]
    fn the_nearby_answer_stands_the_hosts_with_their_hex_prefix() {
        let hosts = [
            connetto_client::NearbyHost {
                host: 7,
                prefix: Some([9; 8]),
                rssi: Some(-55),
            },
            connetto_client::NearbyHost {
                host: 8,
                prefix: None,
                rssi: None,
            },
        ];
        assert_eq!(
            super::nearby_entries(&hosts),
            vec![
                serde_json::json!({ "host": 7, "prefix": "0909090909090909", "rssi": -55 }),
                serde_json::json!({ "host": 8, "prefix": null, "rssi": null }),
            ]
        );
        assert_eq!(super::nearby_entries(&[]), Vec::<serde_json::Value>::new());
    }
}
