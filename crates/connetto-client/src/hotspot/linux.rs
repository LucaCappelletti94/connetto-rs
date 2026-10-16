//! The Linux hotspot backend, over `NetworkManager` (R76 slice 9b).
//!
//! The backend drives `NetworkManager` on one thread of its own, the machine's
//! polled calls reaching it over a channel and the host and join standings
//! coming back through the shared standing. The volatile profile bound to
//! the D-Bus connection keeps the hosted credentials in memory only, and a
//! device whose `5 GHz` attempt failed is remembered for the life of the
//! process.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;

use connetto_peer::linux::{
    AddError, AddRequest, Band, NETWORK_CONTROL, NmEvent, NmIo, SETTINGS_MODIFY_OWN,
    STATE_ACTIVATED, STATE_DEACTIVATED, STATE_DEACTIVATING, Security, WIFI_SHARE_PROTECTED,
    WifiDevice,
};

use super::{
    HostStatus, HotspotBackend, HotspotError, HotspotOffer, HotspotSecurity, JoinError, JoinStatus,
    TICK,
};

/// The bound the `5 GHz` attempt gets, on the monotonic clock.
const FIVE_GHZ_BOUND: Duration = Duration::from_secs(10);
/// The hotspot's SSID prefix, the four random hex digits following it.
const SSID_PREFIX: &str = "connetto-";
/// The hotspot's passphrase length.
const PASSPHRASE_LEN: usize = 16;
/// The alphabet the passphrase draws from.
const PASSPHRASE_ALPHABET: [u8; 36] = *b"0123456789abcdefghijklmnopqrstuvwxyz";

/// The host table's column.
#[derive(Clone, Debug, Default)]
enum HostStanding {
    /// Idle, nothing requested.
    #[default]
    Idle,
    /// The `5 GHz` request in flight.
    Five {
        /// The request's generation, the stale answers' refusal.
        generation: u64,
        /// The request's origin, the bound's.
        sent: Instant,
        /// The device's hardware address, the `5 GHz` memory's key.
        hw_address: String,
        /// The device's D-Bus object path.
        device: String,
        /// The active connection's path, once the request answers.
        active: Option<String>,
        /// The network name, kept for the fallback.
        ssid: String,
        /// The passphrase, kept for the fallback.
        passphrase: String,
    },
    /// The `2.4 GHz` request in flight.
    Two {
        /// The request's generation, the stale answers' refusal.
        generation: u64,
        /// The active connection's path, once the request answers.
        active: Option<String>,
        /// The network name, kept for the fallback.
        ssid: String,
        /// The passphrase, kept for the fallback.
        passphrase: String,
    },
    /// The hotspot is up.
    Active {
        /// The active connection's path.
        active: String,
        /// The network name.
        ssid: String,
        /// The passphrase.
        passphrase: String,
    },
    /// The stop is draining.
    Ending,
    /// Ended, with the column's reason.
    Ended(HostOutcome),
}

/// The host table's ended column's reason.
#[derive(Clone, Debug)]
enum HostOutcome {
    /// The request's refusal, with the mapped reason.
    Failed(HotspotError),
    /// The hotspot stopped.
    Stopped,
}

/// The join table's column.
#[derive(Clone, Debug, Default)]
enum JoinStanding {
    /// Idle, nothing requested.
    #[default]
    Idle,
    /// The request in flight.
    Requesting {
        /// The request's generation, the stale answers' refusal.
        generation: u64,
        /// The active connection's path, once the request answers.
        active: Option<String>,
        /// The connection is activated without a gateway yet.
        awaiting_gateway: bool,
    },
    /// Joined, with the network's details.
    Joined {
        /// The active connection's path.
        active: String,
        /// The device's address on the network.
        address: Ipv4Addr,
        /// The subnet's prefix length.
        prefix: u8,
        /// The network's gateway.
        gateway: IpAddr,
    },
    /// Ended, with the column's reason.
    Ended(JoinOutcome),
}

/// The join table's ended column's reason.
#[derive(Clone, Debug)]
enum JoinOutcome {
    /// The network will not stand.
    Unavailable,
    /// The joined network is gone.
    Lost,
}

/// The environment the pre-checks answer from, the thread's read.
#[derive(Clone, Debug, Default)]
struct Env {
    /// Wi-Fi's enabled standing.
    wifi_enabled: bool,
    /// The permission table, by name.
    permissions: HashMap<String, String>,
    /// The Wi-Fi devices, in `NetworkManager`'s order.
    devices: Vec<WifiDevice>,
    /// The devices whose `5 GHz` attempt failed, held for the life of the
    /// process.
    five_ghz_failed: BTreeSet<String>,
}

/// The backend's shared state, the polled calls' read.
#[derive(Default)]
struct State {
    /// The host table's column.
    host: HostStanding,
    /// The host request's generation, the stale answers' refusal.
    host_gen: u64,
    /// The join table's column.
    join: JoinStanding,
    /// The join request's generation, the stale answers' refusal.
    join_gen: u64,
    /// The pre-checks' environment.
    env: Env,
}

/// The backend's shared standing, the polled calls' read.
type Standing = Arc<Mutex<State>>;

/// What the machine's polled calls ask of the thread.
enum Command {
    /// The host table's `request_host` row's request, under its generation.
    Host {
        /// The request's generation.
        generation: u64,
        /// The request `NetworkManager` activates.
        req: AddRequest,
    },
    /// The join table's `request_join` row's request, under its generation.
    Join {
        /// The request's generation.
        generation: u64,
        /// The request `NetworkManager` activates.
        req: AddRequest,
    },
    /// The host or join table's deactivate row's connection.
    Deactivate(String),
}

/// The Linux hotspot backend, over `NetworkManager` (R76 slice 9b).
pub(crate) struct LinuxHotspotBackend {
    commands: mpsc::UnboundedSender<Command>,
    standing: Standing,
}

impl LinuxHotspotBackend {
    /// The backend over `io`, its thread driving the tables on its own
    /// current-thread runtime.
    pub(crate) fn new<IO>(io: Arc<IO>) -> Self
    where
        IO: NmIo + Send + 'static,
    {
        let (commands, receiver) = mpsc::unbounded_channel();
        let standing: Standing = Arc::new(Mutex::new(State::default()));
        let drive_standing = Arc::clone(&standing);
        match std::thread::Builder::new()
            .name("connetto-nm".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("NetworkManager's thread could not run");
                    return;
                };
                runtime.block_on(Self::drive(io, drive_standing, receiver));
            }) {
            Ok(_) => {}
            Err(err) => tracing::error!("NetworkManager's thread did not start: {err}"),
        }
        Self { commands, standing }
    }

    /// The backend's channel and standing, the thread's loop left to the
    /// caller's runtime, for the table proofs.
    #[cfg(test)]
    fn unstarted() -> (Self, mpsc::UnboundedReceiver<Command>) {
        let (commands, receiver) = mpsc::unbounded_channel();
        (
            Self {
                commands,
                standing: Arc::new(Mutex::new(State::default())),
            },
            receiver,
        )
    }

    fn send(&self, command: Command) {
        if self.commands.send(command).is_err() {
            tracing::warn!("NetworkManager's thread has ended");
        }
    }

    /// The thread's loop: the machine's commands and `NetworkManager`'s
    /// signals against the tables, until either end is dropped.
    async fn drive<IO>(
        io: Arc<IO>,
        standing: Standing,
        mut commands: mpsc::UnboundedReceiver<Command>,
    ) where
        IO: NmIo + Send + 'static,
    {
        let io: &IO = io.as_ref();
        read_env(io, &standing).await;
        loop {
            settle(&standing);
            if five_ghz_bound_due(&standing) {
                five_ghz_bound_row(io, &standing).await;
                continue;
            }
            gateway_repoll(io, &standing).await;
            let Some(item) = next_item(io, &mut commands, next_deadline(&standing)).await else {
                break;
            };
            match item {
                Item::Command(Command::Host { generation, req }) => {
                    match io.add_and_activate(&req).await {
                        Ok(active) => host_add_answered(io, &standing, generation, active).await,
                        Err(err) => host_add_refused(io, &standing, &req, generation, err).await,
                    }
                }
                Item::Command(Command::Join { generation, req }) => {
                    match io.add_and_activate(&req).await {
                        Ok(active) => join_add_answered(io, &standing, generation, active).await,
                        Err(err) => join_add_refused(&standing, generation, err),
                    }
                }
                Item::Command(Command::Deactivate(path)) => {
                    if let Err(err) = io.deactivate(&path).await {
                        tracing::debug!(%path, %err, "the active connection will not deactivate");
                    }
                }
                Item::Event(event) => handle_event(io, &standing, event).await,
                Item::Deadline => {}
            }
        }
    }
}

/// What the thread's look takes, from either end.
enum Item {
    /// The machine's command.
    Command(Command),
    /// `NetworkManager`'s signal.
    Event(NmEvent),
    /// The `5 GHz` bound or the gateway's repoll ran.
    Deadline,
}

/// The machine's command, `NetworkManager`'s signal, or the bound's run.
async fn next_item<IO: NmIo>(
    io: &IO,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    deadline: Option<Instant>,
) -> Option<Item> {
    let deadline = deadline.map(tokio::time::sleep_until);
    Some(tokio::select! {
        command = commands.recv() => match command {
            Some(command) => Item::Command(command),
            None => return None,
        },
        event = io.next_event() => match event {
            Some(event) => Item::Event(event),
            None => return None,
        },
        () = wait_deadline(deadline) => Item::Deadline,
    })
}

/// The bound's run, standing pending where no bound is due.
async fn wait_deadline(deadline: Option<tokio::time::Sleep>) {
    match deadline {
        Some(deadline) => deadline.await,
        None => std::future::pending().await,
    }
}

/// The host table's `stop_host` row's end: the stop's drain is done.
fn settle(standing: &Standing) {
    let mut s = standing.lock();
    if matches!(s.host, HostStanding::Ending) {
        s.host = HostStanding::Idle;
    }
}

/// Whether the `5 GHz` bound has run: the column stands `5 GHz` and the bound's
/// instant is past.
fn five_ghz_bound_due(standing: &Standing) -> bool {
    let s = standing.lock();
    match &s.host {
        HostStanding::Five { sent, .. } => Instant::now() >= *sent + FIVE_GHZ_BOUND,
        _ => false,
    }
}

/// The next bound or repoll the thread's look waits for, where one stands.
fn next_deadline(standing: &Standing) -> Option<Instant> {
    let s = standing.lock();
    let mut due = None;
    if let HostStanding::Five { sent, .. } = &s.host {
        due = Some(*sent + FIVE_GHZ_BOUND);
    }
    if matches!(
        &s.join,
        JoinStanding::Requesting {
            awaiting_gateway: true,
            ..
        }
    ) {
        let repoll = Instant::now() + TICK;
        due = due.map_or(Some(repoll), |due| Some(due.min(repoll)));
    }
    due
}

/// The host table's `FIVE_GHZ_BOUND runs` row: deactivate, remember the
/// device, send band `bg` under the same SSID and passphrase.
async fn five_ghz_bound_row<IO: NmIo>(io: &IO, standing: &Standing) {
    let (active, req, generation) = {
        let mut s = standing.lock();
        let HostStanding::Five {
            generation: slot_gen,
            hw_address,
            device,
            active,
            ssid,
            passphrase,
            ..
        } = &s.host
        else {
            return;
        };
        let (generation, hw_address, device, ssid, passphrase, active) = (
            *slot_gen,
            hw_address.clone(),
            device.clone(),
            ssid.clone(),
            passphrase.clone(),
            active.clone(),
        );
        s.env.five_ghz_failed.insert(hw_address.clone());
        s.host = HostStanding::Two {
            generation,
            active: None,
            ssid: ssid.clone(),
            passphrase: passphrase.clone(),
        };
        (
            active,
            AddRequest::Host {
                device: device.clone(),
                band: Band::Two,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            },
            generation,
        )
    };
    if let Some(path) = active
        && let Err(err) = io.deactivate(&path).await
    {
        tracing::debug!(%path, %err, "the 5 GHz connection will not deactivate");
    }
    send_two_ghz(io, standing, generation, req).await;
}

/// The host table's `2.4 GHz` attempt: the band-`bg` request and its answers,
/// the column already standing it.
async fn send_two_ghz<IO: NmIo>(io: &IO, standing: &Standing, generation: u64, req: AddRequest) {
    match io.add_and_activate(&req).await {
        Ok(active) => host_add_answered(io, standing, generation, active).await,
        // The refusal row can send the `2.4 GHz` request again, so its future
        // is boxed to give the recursion a size.
        Err(err) => Box::pin(host_add_refused(io, standing, &req, generation, err)).await,
    }
}

/// The join table's `activated without a gateway yet` row's repoll,
/// standing the gateway once it arrives.
async fn gateway_repoll<IO: NmIo>(io: &IO, standing: &Standing) {
    let path = {
        let s = standing.lock();
        match &s.join {
            JoinStanding::Requesting {
                active: Some(path),
                awaiting_gateway: true,
                ..
            } => Some(path.clone()),
            _ => None,
        }
    };
    let Some(path) = path else {
        return;
    };
    match io.ipv4(&path).await {
        Ok(ipv4) => {
            let Some(gateway) = ipv4.gateway else {
                return;
            };
            let mut s = standing.lock();
            if let JoinStanding::Requesting {
                active: Some(slot),
                awaiting_gateway: true,
                ..
            } = &mut s.join
                && slot == &path
            {
                s.join = JoinStanding::Joined {
                    active: slot.clone(),
                    address: ipv4.address,
                    prefix: ipv4.prefix,
                    gateway,
                };
            }
        }
        Err(err) => tracing::debug!(%path, %err, "the IPv4 standing will not read"),
    }
}

/// The host table's request row's answer: the active connection's path
/// stands on the column, or the column has moved and the connection orphans
/// to the stop.
async fn host_add_answered<IO: NmIo>(
    io: &IO,
    standing: &Standing,
    generation: u64,
    active: String,
) {
    let stale = {
        let mut s = standing.lock();
        match &mut s.host {
            HostStanding::Five {
                generation: slot_gen,
                active: slot,
                ..
            }
            | HostStanding::Two {
                generation: slot_gen,
                active: slot,
                ..
            } if *slot_gen == generation => {
                *slot = Some(active.clone());
                false
            }
            _ => true,
        }
    };
    if stale {
        release_orphan(io, active).await;
    }
}

/// The host table's request row's refusal: `PermissionDenied` ends the
/// column, another error on the `5 GHz` band remembers the device and sends
/// band `bg`, another on the `2.4 GHz` band ends the column.
async fn host_add_refused<IO: NmIo>(
    io: &IO,
    standing: &Standing,
    req: &AddRequest,
    generation: u64,
    err: AddError,
) {
    let current = {
        let s = standing.lock();
        matches!(
            &s.host,
            HostStanding::Five { generation: slot, .. }
            | HostStanding::Two { generation: slot, .. } if *slot == generation
        )
    };
    if !current {
        return;
    }
    // The row's band-`bg` attempt, where the `5 GHz` request refused for a
    // D-Bus error, the device remembered for the life of the process.
    if let AddError::Failed(_) = err
        && let AddRequest::Host {
            device,
            band: Band::Five,
            ssid,
            passphrase,
        } = req
    {
        let two = {
            let mut s = standing.lock();
            let HostStanding::Five {
                generation: slot_gen,
                hw_address,
                ..
            } = &s.host
            else {
                return;
            };
            if *slot_gen != generation {
                return;
            }
            let (slot_gen, hw_address) = (*slot_gen, hw_address.clone());
            s.env.five_ghz_failed.insert(hw_address.clone());
            s.host = HostStanding::Two {
                generation: slot_gen,
                active: None,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            };
            AddRequest::Host {
                device: device.clone(),
                band: Band::Two,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            }
        };
        send_two_ghz(io, standing, generation, two).await;
        return;
    }
    // The column ends, the `PermissionDenied` refusal's mapped reason, the
    // `2.4 GHz` band's failure's.
    let outcome = match err {
        AddError::PermissionDenied => HostOutcome::Failed(HotspotError::MissingPermission(
            WIFI_SHARE_PROTECTED.to_string(),
        )),
        AddError::Failed(_) => HostOutcome::Failed(HotspotError::Failed),
    };
    let mut s = standing.lock();
    if matches!(
        &s.host,
        HostStanding::Five { generation: slot, .. } | HostStanding::Two { generation: slot, .. } if *slot == generation
    ) {
        s.host = HostStanding::Ended(outcome);
    }
}

/// The join table's request row's answer: the active connection's path
/// stands on the column, or the column has moved and the connection orphans
/// to the leave.
async fn join_add_answered<IO: NmIo>(
    io: &IO,
    standing: &Standing,
    generation: u64,
    active: String,
) {
    let stale = {
        let mut s = standing.lock();
        match &mut s.join {
            JoinStanding::Requesting {
                generation: slot_gen,
                active: slot,
                ..
            } if *slot_gen == generation => {
                *slot = Some(active.clone());
                false
            }
            _ => true,
        }
    };
    if stale {
        release_orphan(io, active).await;
    }
}

/// The join table's request row's refusal: the column ends unavailable, the
/// refused right where `NetworkManager` names it.
fn join_add_refused(standing: &Standing, generation: u64, err: AddError) {
    let mut s = standing.lock();
    match &mut s.join {
        JoinStanding::Requesting {
            generation: slot_gen,
            ..
        } if *slot_gen == generation => match err {
            AddError::PermissionDenied => {
                tracing::debug!("NetworkManager refused the join request for lack of a permission");
                s.join = JoinStanding::Ended(JoinOutcome::Unavailable);
            }
            AddError::Failed(reason) => {
                tracing::debug!(%reason, "NetworkManager refused the join request");
                s.join = JoinStanding::Ended(JoinOutcome::Unavailable);
            }
        },
        _ => {}
    }
}

/// `NetworkManager`'s signal, against the host and join tables' rows.
async fn handle_event<IO: NmIo>(io: &IO, standing: &Standing, event: NmEvent) {
    match event {
        NmEvent::CheckPermissions => read_permissions(io, standing).await,
        NmEvent::WirelessEnabled(on) => {
            standing.lock().env.wifi_enabled = on;
        }
        NmEvent::StateChanged {
            active,
            state,
            reason,
        } => state_changed(io, standing, &active, state, reason).await,
    }
}

/// The active connection's state change, the host and join tables' rows.
async fn state_changed<IO: NmIo>(
    io: &IO,
    standing: &Standing,
    active: &str,
    state: u32,
    reason: u32,
) {
    match state {
        STATE_ACTIVATED => {
            host_activated(standing, active);
            join_activated(io, standing, active).await;
        }
        STATE_DEACTIVATING | STATE_DEACTIVATED => {
            if let Some((req, generation)) = host_deactivated(standing, active, reason) {
                send_two_ghz(io, standing, generation, req).await;
            }
            join_deactivated(standing, active, reason);
        }
        _ => {}
    }
}

/// The host's `activated` row: the column stands the hotspot.
fn host_activated(standing: &Standing, active: &str) {
    let mut s = standing.lock();
    let row = match &mut s.host {
        HostStanding::Five {
            active: slot,
            ssid,
            passphrase,
            ..
        }
        | HostStanding::Two {
            active: slot,
            ssid,
            passphrase,
            ..
        } if slot.as_deref() == Some(active) => Some((ssid.clone(), passphrase.clone())),
        _ => None,
    };
    if let Some((ssid, passphrase)) = row {
        s.host = HostStanding::Active {
            active: active.to_string(),
            ssid,
            passphrase,
        };
    }
}

/// The join's `activated` row: the `IPv4` standing, the gateway where it
/// stands, the repoll where it does not.
async fn join_activated<IO: NmIo>(io: &IO, standing: &Standing, active: &str) {
    let due = {
        let s = standing.lock();
        matches!(
            &s.join,
            JoinStanding::Requesting {
                active: Some(slot),
                ..
            } if slot == active
        )
    };
    if !due {
        return;
    }
    match io.ipv4(active).await {
        Ok(ipv4) => {
            let mut s = standing.lock();
            if let JoinStanding::Requesting {
                generation,
                active: Some(slot),
                ..
            } = &mut s.join
                && slot == active
            {
                let generation = *generation;
                s.join = match ipv4.gateway {
                    Some(gateway) => JoinStanding::Joined {
                        active: slot.clone(),
                        address: ipv4.address,
                        prefix: ipv4.prefix,
                        gateway,
                    },
                    None => JoinStanding::Requesting {
                        generation,
                        active: Some(slot.clone()),
                        awaiting_gateway: true,
                    },
                };
            }
        }
        Err(err) => {
            tracing::debug!(%active, %err, "the IPv4 standing will not read");
            join_awaiting_gateway(standing, active);
        }
    }
}

/// The join's `deactivated` row: the column ends unavailable.
fn join_deactivated(standing: &Standing, active: &str, reason: u32) {
    let mut s = standing.lock();
    match &s.join {
        JoinStanding::Requesting {
            active: Some(slot), ..
        } if slot == active => {
            tracing::debug!(%reason, "the joined connection will not stand");
            s.join = JoinStanding::Ended(JoinOutcome::Unavailable);
        }
        JoinStanding::Joined { active: slot, .. } if slot == active => {
            s.join = JoinStanding::Ended(JoinOutcome::Lost);
        }
        _ => {}
    }
}

/// The join's `activated` row's repoll's standing, the gateway's read gone.
fn join_awaiting_gateway(standing: &Standing, active: &str) {
    let mut s = standing.lock();
    if let JoinStanding::Requesting {
        generation,
        active: Some(slot),
        ..
    } = &mut s.join
        && slot == active
    {
        let generation = *generation;
        s.join = JoinStanding::Requesting {
            generation,
            active: Some(slot.clone()),
            awaiting_gateway: true,
        };
    }
}

/// The host's `deactivated` rows: the `5 GHz` column remembers the device and
/// sends band `bg`, the `2.4 GHz` column ends failed, the active column ends
/// stopped.
fn host_deactivated(standing: &Standing, active: &str, reason: u32) -> Option<(AddRequest, u64)> {
    let mut s = standing.lock();
    match &s.host {
        HostStanding::Five {
            hw_address,
            device,
            active: Some(slot),
            ssid,
            passphrase,
            generation,
            ..
        } if slot == active => {
            let (hw_address, device, ssid, passphrase, generation) = (
                hw_address.clone(),
                device.clone(),
                ssid.clone(),
                passphrase.clone(),
                *generation,
            );
            s.env.five_ghz_failed.insert(hw_address.clone());
            s.host = HostStanding::Two {
                generation,
                active: None,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            };
            Some((
                AddRequest::Host {
                    device: device.clone(),
                    band: Band::Two,
                    ssid: ssid.clone(),
                    passphrase: passphrase.clone(),
                },
                generation,
            ))
        }
        HostStanding::Two {
            active: Some(slot), ..
        } if slot == active => {
            tracing::debug!(%reason, "the hosted connection will not stand");
            s.host = HostStanding::Ended(HostOutcome::Failed(HotspotError::Failed));
            None
        }
        HostStanding::Active { active: slot, .. } if slot == active => {
            s.host = HostStanding::Ended(HostOutcome::Stopped);
            None
        }
        _ => None,
    }
}

/// The thread's first reads, the pre-checks' standing.
async fn read_env<IO: NmIo>(io: &IO, standing: &Standing) {
    if let Ok(permissions) = io.permissions().await {
        standing.lock().env.permissions = permissions;
    }
    if let Ok(on) = io.wifi_enabled().await {
        standing.lock().env.wifi_enabled = on;
    }
    if let Ok(devices) = io.wifi_devices().await {
        standing.lock().env.devices = devices;
    }
}

/// The `CheckPermissions` signal's row: the permission table re-read.
async fn read_permissions<IO: NmIo>(io: &IO, standing: &Standing) {
    if let Ok(permissions) = io.permissions().await {
        standing.lock().env.permissions = permissions;
    }
}

/// The orphans' release: the request's column moved, so the activated
/// connection is the stop's or the leave's, and it deactivates.
async fn release_orphan<IO: NmIo>(io: &IO, active: String) {
    if let Err(err) = io.deactivate(&active).await {
        tracing::debug!(%active, %err, "the orphaned connection will not deactivate");
    }
}

/// The fresh SSID and passphrase a hotspot takes, held in memory only.
fn mint_credentials() -> (String, String) {
    let mut suffix = [0u8; 2];
    getrandom::fill(&mut suffix).expect("the platform RNG fills the SSID's suffix");
    let ssid = format!("{SSID_PREFIX}{:02x}{:02x}", suffix[0], suffix[1]);
    let mut bytes = [0u8; PASSPHRASE_LEN];
    getrandom::fill(&mut bytes).expect("the platform RNG fills the passphrase");
    let passphrase: String = bytes
        .iter()
        .map(|byte| char::from(PASSPHRASE_ALPHABET[usize::from(*byte) % PASSPHRASE_ALPHABET.len()]))
        .collect();
    (ssid, passphrase)
}

/// The device a host or join request goes to: the first Wi-Fi device whose
/// capabilities carry the access point flag, the first where they do not.
fn device_of(env: &Env) -> Option<&WifiDevice> {
    env.devices
        .iter()
        .find(|device| device.is_access_point())
        .or_else(|| env.devices.first())
}

impl HotspotBackend for LinuxHotspotBackend {
    fn request_host(&self) -> Result<(), HotspotError> {
        let mut s = self.standing.lock();
        // The column already hosts or asks, so the machine already waits.
        if matches!(
            s.host,
            HostStanding::Five { .. } | HostStanding::Two { .. } | HostStanding::Active { .. }
        ) {
            return Ok(());
        }
        let device: WifiDevice = match s.env.devices.iter().find(|device| device.is_access_point())
        {
            Some(device) => device.clone(),
            None => {
                return if s.env.devices.is_empty() {
                    Err(HotspotError::Unsupported)
                } else {
                    Err(HotspotError::Incompatible)
                };
            }
        };
        if !s.env.wifi_enabled {
            return Err(HotspotError::Disallowed);
        }
        if s.env
            .permissions
            .get(WIFI_SHARE_PROTECTED)
            .is_none_or(|granted| granted != "yes")
        {
            return Err(HotspotError::MissingPermission(
                WIFI_SHARE_PROTECTED.to_string(),
            ));
        }
        if matches!(
            s.join,
            JoinStanding::Requesting { .. } | JoinStanding::Joined { .. }
        ) {
            return Err(HotspotError::Joined);
        }
        let (ssid, passphrase) = mint_credentials();
        let generation = s.host_gen + 1;
        s.host_gen = generation;
        let hw_address = device.hw_address.clone();
        let device_path = device.path.clone();
        if s.env.five_ghz_failed.contains(&device.hw_address) || !device.has_five_ghz() {
            s.host = HostStanding::Two {
                generation,
                active: None,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            };
        } else {
            s.host = HostStanding::Five {
                generation,
                sent: Instant::now(),
                hw_address: hw_address.clone(),
                device: device_path.clone(),
                active: None,
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
            };
        }
        let band = match &s.host {
            HostStanding::Five { .. } => Band::Five,
            _ => Band::Two,
        };
        drop(s);
        self.send(Command::Host {
            generation,
            req: AddRequest::Host {
                device: device_path,
                band,
                ssid,
                passphrase,
            },
        });
        Ok(())
    }

    fn stop_host(&self) {
        let path = {
            let mut s = self.standing.lock();
            if matches!(s.host, HostStanding::Idle | HostStanding::Ending) {
                None
            } else if matches!(s.host, HostStanding::Ended(_)) {
                s.host = HostStanding::Idle;
                None
            } else {
                let path = match &s.host {
                    HostStanding::Five { active, .. } | HostStanding::Two { active, .. } => {
                        active.clone()
                    }
                    HostStanding::Active { active, .. } => Some(active.clone()),
                    _ => None,
                };
                s.host = HostStanding::Ending;
                path
            }
        };
        if let Some(path) = path {
            self.send(Command::Deactivate(path));
        }
    }

    fn host_status(&self) -> HostStatus {
        let s = self.standing.lock();
        match &s.host {
            HostStanding::Idle | HostStanding::Five { .. } | HostStanding::Two { .. } => {
                HostStatus::Pending
            }
            HostStanding::Active {
                ssid, passphrase, ..
            } => HostStatus::Started {
                ssid: ssid.clone(),
                passphrase: passphrase.clone(),
                security: HotspotSecurity::Wpa2,
            },
            HostStanding::Ending | HostStanding::Ended(HostOutcome::Stopped) => HostStatus::Stopped,
            HostStanding::Ended(HostOutcome::Failed(err)) => HostStatus::Failed(err.clone()),
        }
    }

    fn request_join(&self, offer: &HotspotOffer) -> Result<(), JoinError> {
        let mut s = self.standing.lock();
        let replacing = matches!(
            s.join,
            JoinStanding::Requesting { .. } | JoinStanding::Joined { .. }
        );
        if !replacing {
            if s.env.devices.is_empty() {
                return Err(JoinError::Unsupported);
            }
            if !s.env.wifi_enabled {
                return Err(JoinError::Failed);
            }
            for name in [NETWORK_CONTROL, SETTINGS_MODIFY_OWN] {
                if s.env
                    .permissions
                    .get(name)
                    .is_none_or(|granted| granted != "yes")
                {
                    return Err(JoinError::MissingPermission(name.to_string()));
                }
            }
            if matches!(
                s.host,
                HostStanding::Five { .. }
                    | HostStanding::Two { .. }
                    | HostStanding::Active { .. }
                    | HostStanding::Ending
            ) {
                return Err(JoinError::Hosting);
            }
        }
        let Some(device) = device_of(&s.env).cloned() else {
            return Err(JoinError::Unsupported);
        };
        let security = match offer.security {
            HotspotSecurity::Wpa2 => Security::Wpa2,
            HotspotSecurity::Wpa3 => Security::Wpa3,
        };
        let old_active = match &s.join {
            JoinStanding::Requesting { active, .. } => active.clone(),
            JoinStanding::Joined { active, .. } => Some(active.clone()),
            _ => None,
        };
        let generation = s.join_gen + 1;
        s.join_gen = generation;
        s.join = JoinStanding::Requesting {
            generation,
            active: None,
            awaiting_gateway: false,
        };
        let req = AddRequest::Join {
            device: device.path.clone(),
            ssid: offer.ssid.clone(),
            passphrase: offer.passphrase.clone(),
            security,
        };
        drop(s);
        if let Some(path) = old_active {
            self.send(Command::Deactivate(path));
        }
        self.send(Command::Join { generation, req });
        Ok(())
    }

    fn leave_join(&self) {
        let path = {
            let mut s = self.standing.lock();
            if matches!(s.join, JoinStanding::Idle | JoinStanding::Ended(_)) {
                None
            } else {
                let path = match &s.join {
                    JoinStanding::Requesting { active, .. } => active.clone(),
                    JoinStanding::Joined { active, .. } => Some(active.clone()),
                    _ => None,
                };
                s.join = JoinStanding::Idle;
                path
            }
        };
        if let Some(path) = path {
            self.send(Command::Deactivate(path));
        }
    }

    fn join_status(&self) -> JoinStatus {
        let s = self.standing.lock();
        match &s.join {
            JoinStanding::Idle | JoinStanding::Requesting { .. } => JoinStatus::Pending,
            JoinStanding::Joined {
                address,
                prefix,
                gateway,
                ..
            } => JoinStatus::Available {
                address: *address,
                prefix: *prefix,
                gateway: *gateway,
            },
            JoinStanding::Ended(JoinOutcome::Unavailable) => JoinStatus::Unavailable,
            JoinStanding::Ended(JoinOutcome::Lost) => JoinStatus::Lost,
        }
    }

    fn request_personal_host(&self, _ssid: &str, _passphrase: &str) -> Result<(), HotspotError> {
        Err(HotspotError::Unsupported)
    }

    fn personal_landed(&self) -> bool {
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use connetto_peer::linux::{CAP_ACCESS_POINT, CAP_FREQ_5GHZ, Ipv4Standing, NmIoError};

    const DEVICE_PATH: &str = "/org/freedesktop/NetworkManager/Devices/3";
    const HW_ADDRESS: &str = "aa:bb:cc:dd:ee:ff";
    const ACTIVE_PATH: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";
    /// The access point's flag, the table's rows' device.
    const AP_FLAG: u32 = CAP_ACCESS_POINT;
    /// The `5 GHz` band's flag, the table's rows' device.
    const FIVE_FLAG: u32 = CAP_FREQ_5GHZ;

    fn device(capabilities: u32) -> WifiDevice {
        WifiDevice {
            path: DEVICE_PATH.to_string(),
            hw_address: HW_ADDRESS.to_string(),
            capabilities,
            managed: true,
        }
    }

    fn granted_permissions() -> HashMap<String, String> {
        HashMap::from([
            (WIFI_SHARE_PROTECTED.to_string(), "yes".to_string()),
            (NETWORK_CONTROL.to_string(), "yes".to_string()),
            (SETTINGS_MODIFY_OWN.to_string(), "yes".to_string()),
        ])
    }

    fn offer(ssid: &str, security: HotspotSecurity) -> HotspotOffer {
        HotspotOffer::new(ssid, "the-passphrase", security, Some(5432))
    }

    fn ipv4_standing(gateway: Option<IpAddr>) -> Ipv4Standing {
        Ipv4Standing {
            address: Ipv4Addr::new(10, 42, 0, 2),
            prefix: 24,
            gateway,
        }
    }

    /// The fake `NetworkManager` I/O, the table's rows driven.
    struct FakeNm {
        permissions: Mutex<HashMap<String, String>>,
        wifi_enabled: Mutex<bool>,
        devices: Mutex<Vec<WifiDevice>>,
        /// The queued `add_and_activate` answers, in order, the default
        /// answer the active connection's path.
        adds: Mutex<VecDeque<Result<String, AddError>>>,
        /// The `add_and_activate` hold, the test's gate on the answer.
        add_gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        adds_sent: Mutex<Vec<AddRequest>>,
        deactivates: Mutex<Vec<String>>,
        ipv4: Mutex<HashMap<String, Ipv4Standing>>,
        env_reads: AtomicUsize,
        env_ready: AtomicBool,
        events: tokio::sync::Mutex<mpsc::UnboundedReceiver<NmEvent>>,
    }

    impl FakeNm {
        fn new(
            devices: Vec<WifiDevice>,
            permissions: HashMap<String, String>,
            wifi_enabled: bool,
        ) -> (Arc<Self>, mpsc::UnboundedSender<NmEvent>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    permissions: Mutex::new(permissions),
                    wifi_enabled: Mutex::new(wifi_enabled),
                    devices: Mutex::new(devices),
                    adds: Mutex::new(VecDeque::new()),
                    add_gate: Mutex::new(None),
                    adds_sent: Mutex::new(Vec::new()),
                    deactivates: Mutex::new(Vec::new()),
                    ipv4: Mutex::new(HashMap::new()),
                    env_reads: AtomicUsize::new(0),
                    env_ready: AtomicBool::new(false),
                    events: tokio::sync::Mutex::new(rx),
                }),
                tx,
            )
        }

        /// Whether the thread's first reads have stood.
        fn env_ready(&self) -> bool {
            self.env_ready.load(Ordering::Acquire)
        }

        fn hold_add(&self) -> tokio::sync::oneshot::Sender<()> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.add_gate.lock().replace(rx);
            tx
        }
    }

    impl NmIo for FakeNm {
        fn permissions(&self) -> impl Future<Output = Result<HashMap<String, String>, NmIoError>> {
            std::future::ready(Ok(self.permissions.lock().clone()))
        }

        fn wifi_enabled(&self) -> impl Future<Output = Result<bool, NmIoError>> {
            std::future::ready(Ok(*self.wifi_enabled.lock()))
        }

        fn wifi_devices(&self) -> impl Future<Output = Result<Vec<WifiDevice>, NmIoError>> {
            self.env_reads.fetch_add(1, Ordering::Relaxed);
            let devices = self.devices.lock().clone();
            self.env_ready.store(true, Ordering::Release);
            std::future::ready(Ok(devices))
        }

        async fn add_and_activate(&self, req: &AddRequest) -> Result<String, AddError> {
            self.adds_sent.lock().push(req.clone());
            let gate = self.add_gate.lock().take();
            if let Some(gate) = gate {
                assert!(gate.await.is_ok(), "the test's gate never released the add");
            }
            self.adds
                .lock()
                .pop_front()
                .unwrap_or_else(|| Ok(ACTIVE_PATH.to_string()))
        }

        fn deactivate(&self, active: &str) -> impl Future<Output = Result<(), NmIoError>> {
            self.deactivates.lock().push(active.to_string());
            std::future::ready(Ok(()))
        }

        fn ipv4(&self, active: &str) -> impl Future<Output = Result<Ipv4Standing, NmIoError>> {
            std::future::ready(
                self.ipv4
                    .lock()
                    .get(active)
                    .cloned()
                    .ok_or_else(|| NmIoError::Failed("no IPv4 standing".to_string())),
            )
        }

        async fn next_event(&self) -> Option<NmEvent> {
            let mut events = self.events.lock().await;
            events.recv().await
        }
    }

    struct Harness {
        backend: LinuxHotspotBackend,
        fake: Arc<FakeNm>,
        events: mpsc::UnboundedSender<NmEvent>,
        driver: tokio::task::JoinHandle<()>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.driver.abort();
        }
    }

    fn harness(
        devices: Vec<WifiDevice>,
        permissions: HashMap<String, String>,
        wifi_enabled: bool,
    ) -> Harness {
        let (fake, events) = FakeNm::new(devices, permissions, wifi_enabled);
        let (backend, receiver) = LinuxHotspotBackend::unstarted();
        let standing = backend.standing.clone();
        let driver = tokio::spawn(LinuxHotspotBackend::drive(fake.clone(), standing, receiver));
        Harness {
            backend,
            fake,
            events,
            driver,
        }
    }

    fn sent(h: &Harness) -> Vec<AddRequest> {
        h.fake.adds_sent.lock().clone()
    }

    fn deactivates(h: &Harness) -> Vec<String> {
        h.fake.deactivates.lock().clone()
    }

    fn band_of(adds: &[AddRequest], index: usize) -> Option<Band> {
        match adds.get(index)? {
            AddRequest::Host { band, .. } => Some(*band),
            AddRequest::Join { .. } => None,
        }
    }

    fn activated_event(events: &mpsc::UnboundedSender<NmEvent>) {
        events
            .send(NmEvent::StateChanged {
                active: ACTIVE_PATH.to_string(),
                state: STATE_ACTIVATED,
                reason: 0,
            })
            .expect("the event goes in");
    }

    fn deactivated_event(events: &mpsc::UnboundedSender<NmEvent>, reason: u32) {
        events
            .send(NmEvent::StateChanged {
                active: ACTIVE_PATH.to_string(),
                state: STATE_DEACTIVATING,
                reason,
            })
            .expect("the event goes in");
    }

    async fn pump_until(mut condition: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !condition() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the standing did not reach"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// One look for the thread, a bounded step of the virtual clock far
    /// inside the `5 GHz` bound.
    async fn pump() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The host table.

    #[tokio::test]
    async fn host_request_without_a_wifi_device() {
        tokio::time::pause();
        let h = harness(Vec::new(), granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Err(HotspotError::Unsupported));
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn host_request_without_the_access_point_flag() {
        tokio::time::pause();
        let h = harness(vec![device(0)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Err(HotspotError::Incompatible));
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn host_request_with_wifi_disabled() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            false,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Err(HotspotError::Disallowed));
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn host_request_without_the_share_permission() {
        tokio::time::pause();
        let mut permissions = granted_permissions();
        permissions.remove(WIFI_SHARE_PROTECTED);
        let h = harness(vec![device(AP_FLAG | FIVE_FLAG)], permissions, true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend.request_host(),
            Err(HotspotError::MissingPermission(
                WIFI_SHARE_PROTECTED.to_string()
            ))
        );
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn host_request_while_the_join_requests() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        assert_eq!(h.backend.request_host(), Err(HotspotError::Joined));
    }

    #[tokio::test]
    async fn host_request_while_joined() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        h.fake.ipv4.lock().insert(
            ACTIVE_PATH.to_string(),
            ipv4_standing(Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))),
        );
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Available { .. })).await;
        assert_eq!(h.backend.request_host(), Err(HotspotError::Joined));
    }

    #[tokio::test]
    async fn host_request_starts_on_five_ghz() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        let adds = sent(&h);
        let AddRequest::Host {
            device,
            band,
            ssid,
            passphrase,
        } = &adds[0]
        else {
            panic!("the request is the host's");
        };
        assert_eq!(device, DEVICE_PATH);
        assert_eq!(*band, Band::Five);
        assert!(ssid.starts_with(SSID_PREFIX));
        assert_eq!(ssid.len(), SSID_PREFIX.len() + 4);
        assert!(
            ssid[SSID_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        );
        assert_eq!(passphrase.len(), PASSPHRASE_LEN);
        assert!(matches!(h.backend.host_status(), HostStatus::Pending));
    }

    #[tokio::test]
    async fn host_request_without_the_five_ghz_capability() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        assert_eq!(band_of(&sent(&h), 0), Some(Band::Two));
    }

    #[tokio::test]
    async fn host_request_remembers_the_five_ghz_failure() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        h.fake
            .adds
            .lock()
            .push_back(Err(AddError::Failed("the refusal".to_string())));
        assert_eq!(h.backend.request_host(), Ok(()));
        // The `5 GHz` request's D-Bus error: the device remembered, band
        // `bg` sent, the refusal's row carrying no deactivate.
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(band_of(&sent(&h), 0), Some(Band::Five));
        assert_eq!(band_of(&sent(&h), 1), Some(Band::Two));
        assert_eq!(deactivates(&h), Vec::<String>::new());
        // The stop, the memory kept for the life of the process.
        h.backend.stop_host();
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Pending)).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 3).await;
        assert_eq!(band_of(&sent(&h), 2), Some(Band::Two));
    }

    #[tokio::test]
    async fn host_request_permission_denied() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        h.fake
            .adds
            .lock()
            .push_back(Err(AddError::PermissionDenied));
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Failed(_))).await;
        assert_eq!(
            h.backend.host_status(),
            HostStatus::Failed(HotspotError::MissingPermission(
                WIFI_SHARE_PROTECTED.to_string()
            ))
        );
        // The row's answer, no band-`bg` attempt.
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn host_activated_stands_started() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        let AddRequest::Host {
            ssid: asked_ssid,
            passphrase: asked_passphrase,
            ..
        } = &sent(&h)[0]
        else {
            panic!("the request is the host's");
        };
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
        let HostStatus::Started {
            ssid,
            passphrase,
            security,
        } = h.backend.host_status()
        else {
            panic!("the host side stands started");
        };
        assert_eq!(&ssid, asked_ssid);
        assert_eq!(&passphrase, asked_passphrase);
        assert_eq!(security, HotspotSecurity::Wpa2);
    }

    #[tokio::test]
    async fn host_credentials_are_fresh_per_hotspot() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        let first = match &sent(&h)[0] {
            AddRequest::Host { ssid, .. } => ssid.clone(),
            AddRequest::Join { .. } => panic!("the request is the host's"),
        };
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
        h.backend.stop_host();
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Pending)).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 2).await;
        let second = match &sent(&h)[1] {
            AddRequest::Host { ssid, .. } => ssid.clone(),
            AddRequest::Join { .. } => panic!("the request is the host's"),
        };
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn host_request_while_activating_is_a_no_op() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        // The machine already waits, so the request stands the column.
        assert_eq!(h.backend.request_host(), Ok(()));
        pump().await;
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn host_dbus_error_ends_the_two_ghz() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake
            .adds
            .lock()
            .push_back(Err(AddError::Failed("the refusal".to_string())));
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Failed(_))).await;
        assert_eq!(
            h.backend.host_status(),
            HostStatus::Failed(HotspotError::Failed)
        );
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn host_deactivated_falls_back_to_two_ghz() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        deactivated_event(&h.events, 13);
        // The row: the device remembered, band `bg` under the same
        // credentials, the connection already gone and not deactivated.
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(band_of(&sent(&h), 1), Some(Band::Two));
        assert_eq!(deactivates(&h), Vec::<String>::new());
        h.backend.stop_host();
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Pending)).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 3).await;
        assert_eq!(band_of(&sent(&h), 2), Some(Band::Two));
    }

    #[tokio::test]
    async fn host_deactivated_ends_the_two_ghz() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        deactivated_event(&h.events, 13);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Failed(_))).await;
        assert_eq!(
            h.backend.host_status(),
            HostStatus::Failed(HotspotError::Failed)
        );
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn host_deactivated_stops_the_hosting() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
        deactivated_event(&h.events, 13);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Stopped)).await;
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn host_five_ghz_bound_falls_back() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        // The bound's run: deactivate, remember, band `bg` under the same
        // credentials.
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(band_of(&sent(&h), 1), Some(Band::Two));
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        // The `2.4 GHz` attempt's activation stands the hotspot.
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
    }

    #[tokio::test]
    async fn host_stop_cancels_the_activating() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.stop_host();
        // The drain answers Stopped to the machine's look.
        assert!(matches!(h.backend.host_status(), HostStatus::Stopped));
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Pending)).await;
    }

    #[tokio::test]
    async fn host_stop_does_nothing_while_idle() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        h.backend.stop_host();
        pump().await;
        assert!(sent(&h).is_empty());
        assert_eq!(deactivates(&h), Vec::<String>::new());
        assert!(matches!(h.backend.host_status(), HostStatus::Pending));
    }

    #[tokio::test]
    async fn host_stale_add_after_stop_is_released() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        let gate = h.fake.hold_add();
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.stop_host();
        assert!(matches!(h.backend.host_status(), HostStatus::Stopped));
        gate.send(()).expect("the gate opens");
        // The request's column moved, so the activated connection
        // deactivates as the stop's.
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Pending)).await;
    }

    #[tokio::test]
    async fn host_request_after_the_stop_starts_fresh() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.stop_host();
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
    }

    #[test]
    fn personal_host_is_unsupported() {
        let (backend, _receiver) = LinuxHotspotBackend::unstarted();
        assert_eq!(
            backend.request_personal_host("the-ssid", "the-passphrase"),
            Err(HotspotError::Unsupported)
        );
        assert!(!backend.personal_landed());
    }

    // The join table.

    #[tokio::test]
    async fn join_request_without_a_wifi_device() {
        tokio::time::pause();
        let h = harness(Vec::new(), granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::Unsupported)
        );
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn join_request_with_wifi_disabled() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), false);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::Failed)
        );
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn join_request_without_network_control() {
        tokio::time::pause();
        let mut permissions = granted_permissions();
        permissions.remove(NETWORK_CONTROL);
        let h = harness(vec![device(AP_FLAG)], permissions, true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::MissingPermission(NETWORK_CONTROL.to_string()))
        );
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn join_request_without_settings_modify_own() {
        tokio::time::pause();
        let mut permissions = granted_permissions();
        permissions.remove(SETTINGS_MODIFY_OWN);
        let h = harness(vec![device(AP_FLAG)], permissions, true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::MissingPermission(
                SETTINGS_MODIFY_OWN.to_string()
            ))
        );
        assert!(sent(&h).is_empty());
    }

    #[tokio::test]
    async fn join_request_while_hosting() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        // The host side's activating column refuses the join.
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::Hosting)
        );
        // The active column refuses it too.
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.host_status(), HostStatus::Started { .. })).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::Hosting)
        );
    }

    #[tokio::test]
    async fn join_request_while_the_host_stop_drains() {
        tokio::time::pause();
        let h = harness(
            vec![device(AP_FLAG | FIVE_FLAG)],
            granted_permissions(),
            true,
        );
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.stop_host();
        // The stop's drain refuses the join, the device never losing its
        // network as a side effect.
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::Hosting)
        );
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
    }

    #[tokio::test]
    async fn join_request_prefers_the_missing_permission() {
        tokio::time::pause();
        let mut permissions = granted_permissions();
        permissions.remove(NETWORK_CONTROL);
        let h = harness(vec![device(AP_FLAG | FIVE_FLAG)], permissions, true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(h.backend.request_host(), Ok(()));
        pump_until(|| sent(&h).len() == 1).await;
        // The table's order: the missing right before the busy device.
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Err(JoinError::MissingPermission(NETWORK_CONTROL.to_string()))
        );
    }

    #[tokio::test]
    async fn join_request_sends_the_offer() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-first", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        let AddRequest::Join {
            device,
            ssid,
            passphrase,
            security,
        } = &sent(&h)[0]
        else {
            panic!("the request is the join's");
        };
        assert_eq!(device, DEVICE_PATH);
        assert_eq!(ssid, "the-first");
        assert_eq!(passphrase, "the-passphrase");
        assert_eq!(*security, Security::Wpa2);
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
        // The Wpa3 offer's security, the earlier request released.
        h.backend.leave_join();
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-second", HotspotSecurity::Wpa3)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 2).await;
        let AddRequest::Join { security, .. } = &sent(&h)[1] else {
            panic!("the request is the join's");
        };
        assert_eq!(*security, Security::Wpa3);
    }

    #[tokio::test]
    async fn join_activated_stands_available() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake.ipv4.lock().insert(
            ACTIVE_PATH.to_string(),
            ipv4_standing(Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))),
        );
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Available { .. })).await;
        let JoinStatus::Available {
            address,
            prefix,
            gateway,
        } = h.backend.join_status()
        else {
            panic!("the join side stands available");
        };
        assert_eq!(address, Ipv4Addr::new(10, 42, 0, 2));
        assert_eq!(prefix, 24);
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)));
    }

    #[tokio::test]
    async fn join_gateway_stands_when_it_arrives() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake
            .ipv4
            .lock()
            .insert(ACTIVE_PATH.to_string(), ipv4_standing(None));
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        // The row stays Requesting, Pending, for the machine's bound.
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Pending)).await;
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
        // The gateway arrives.
        h.fake.ipv4.lock().insert(
            ACTIVE_PATH.to_string(),
            ipv4_standing(Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))),
        );
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Available { .. })).await;
    }

    #[tokio::test]
    async fn join_request_permission_denied() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake
            .adds
            .lock()
            .push_back(Err(AddError::PermissionDenied));
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Unavailable)).await;
        assert_eq!(sent(&h).len(), 1);
    }

    #[tokio::test]
    async fn join_deactivated_ends_the_requesting() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        deactivated_event(&h.events, 13);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Unavailable)).await;
    }

    #[tokio::test]
    async fn join_deactivated_ends_the_joined() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake.ipv4.lock().insert(
            ACTIVE_PATH.to_string(),
            ipv4_standing(Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))),
        );
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Available { .. })).await;
        deactivated_event(&h.events, 13);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Lost)).await;
    }

    #[tokio::test]
    async fn join_request_replaces_the_requesting() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-first", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        // The new offer: the earlier deactivated, the new one sent.
        assert_eq!(
            h.backend
                .request_join(&offer("the-second", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        let AddRequest::Join { ssid, .. } = &sent(&h)[1] else {
            panic!("the request is the join's");
        };
        assert_eq!(ssid, "the-second");
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
    }

    #[tokio::test]
    async fn join_request_replaces_the_joined() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.fake.ipv4.lock().insert(
            ACTIVE_PATH.to_string(),
            ipv4_standing(Some(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)))),
        );
        assert_eq!(
            h.backend
                .request_join(&offer("the-first", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        activated_event(&h.events);
        pump_until(|| matches!(h.backend.join_status(), JoinStatus::Available { .. })).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-second", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 2).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
    }

    #[tokio::test]
    async fn join_leave_cancels_the_requesting() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.leave_join();
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
    }

    #[tokio::test]
    async fn join_leave_does_nothing_while_idle() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        h.backend.leave_join();
        pump().await;
        assert!(sent(&h).is_empty());
        assert_eq!(deactivates(&h), Vec::<String>::new());
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
    }

    #[tokio::test]
    async fn join_stale_add_after_leave_is_released() {
        tokio::time::pause();
        let h = harness(vec![device(AP_FLAG)], granted_permissions(), true);
        pump_until(|| h.fake.env_ready()).await;
        let gate = h.fake.hold_add();
        assert_eq!(
            h.backend
                .request_join(&offer("the-offer", HotspotSecurity::Wpa2)),
            Ok(())
        );
        pump_until(|| sent(&h).len() == 1).await;
        h.backend.leave_join();
        // The column moved without an active connection yet, so the
        // leave carries no deactivate.
        assert_eq!(deactivates(&h), Vec::<String>::new());
        gate.send(()).expect("the gate opens");
        // The activated connection deactivates as the leave's.
        pump_until(|| deactivates(&h).len() == 1).await;
        assert_eq!(deactivates(&h), vec![ACTIVE_PATH.to_string()]);
        assert!(matches!(h.backend.join_status(), JoinStatus::Pending));
    }
}
