//! The `NetworkManager` I/O the hotspot backend drives over the system bus
//! (R76 slice 9b).
//!
//! The backend asks `NetworkManager` to host and to join hotspots through
//! `AddAndActivateConnection2`, with a volatile profile bound to this
//! client's D-Bus connection, and reads the joined network's address and
//! gateway from the active connection's `IPv4` config.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use futures_util::StreamExt;
use parking_lot::Mutex;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

/// How long a single `NetworkManager` call gets, on the monotonic clock.
const CALL_BOUND: Duration = Duration::from_secs(5);

/// The permission that lets a user host a protected Wi-Fi.
pub const WIFI_SHARE_PROTECTED: &str = "org.freedesktop.NetworkManager.wifi.share.protected";
/// The permission that lets a user control the network.
pub const NETWORK_CONTROL: &str = "org.freedesktop.NetworkManager.network-control";
/// The permission that lets a user modify its own settings.
pub const SETTINGS_MODIFY_OWN: &str = "org.freedesktop.NetworkManager.settings.modify.own";

/// The capability that lets a Wi-Fi device host an access point.
pub const CAP_ACCESS_POINT: u32 = 0x40;
/// The capability that lets a Wi-Fi device host on the 5 `GHz` band.
pub const CAP_FREQ_5GHZ: u32 = 0x400;

/// The active connection's `state` value when it is activated
/// (`NM_ACTIVE_CONNECTION_STATE_ACTIVATED`).
pub const STATE_ACTIVATED: u32 = 2;
/// The active connection's `state` value when it is deactivating
/// (`NM_ACTIVE_CONNECTION_STATE_DEACTIVATING`).
pub const STATE_DEACTIVATING: u32 = 3;
/// The active connection's `state` value once it is deactivated
/// (`NM_ACTIVE_CONNECTION_STATE_DEACTIVATED`).
pub const STATE_DEACTIVATED: u32 = 4;

/// A Wi-Fi device `NetworkManager` manages.
#[derive(Clone, Debug)]
pub struct WifiDevice {
    /// The device's D-Bus object path.
    pub path: String,
    /// The hardware address, the process's 5 `GHz` memory's key.
    pub hw_address: String,
    /// The capability bits.
    pub capabilities: u32,
    /// Whether `NetworkManager` manages the device.
    pub managed: bool,
}

impl WifiDevice {
    /// Whether the device can host an access point.
    #[must_use]
    pub fn is_access_point(&self) -> bool {
        self.capabilities & CAP_ACCESS_POINT != 0
    }

    /// Whether the device hosts on the 5 `GHz` band.
    #[must_use]
    pub fn has_five_ghz(&self) -> bool {
        self.capabilities & CAP_FREQ_5GHZ != 0
    }
}

/// The band a hosted hotspot asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// The 5 `GHz` band.
    Five,
    /// The 2.4 `GHz` band.
    Two,
}

/// The security a joined network carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// WPA2 personal.
    Wpa2,
    /// WPA3 personal.
    Wpa3,
}

/// A host or join request for `NetworkManager` to activate.
#[derive(Clone, Debug)]
pub enum AddRequest {
    /// Host a hotspot on `device`, under `ssid` and `passphrase`.
    Host {
        /// The device's D-Bus object path.
        device: String,
        /// The band to host on.
        band: Band,
        /// The network name.
        ssid: String,
        /// The passphrase.
        passphrase: String,
    },
    /// Join the network on `device`, under `ssid` and `passphrase`.
    Join {
        /// The device's D-Bus object path.
        device: String,
        /// The network name.
        ssid: String,
        /// The passphrase.
        passphrase: String,
        /// The security the network carries.
        security: Security,
    },
}

/// The joined network's `IPv4` standing, once it activates.
#[derive(Clone, Debug)]
pub struct Ipv4Standing {
    /// The device's address on the network.
    pub address: Ipv4Addr,
    /// The subnet's prefix length.
    pub prefix: u8,
    /// The network's gateway, where it stands.
    pub gateway: Option<IpAddr>,
}

/// A `NetworkManager` signal the backend reacts to.
#[derive(Clone, Debug)]
pub enum NmEvent {
    /// The permission table changed, so re-read it.
    CheckPermissions,
    /// Wi-Fi got enabled or disabled.
    WirelessEnabled(bool),
    /// An active connection's state changed.
    StateChanged {
        /// The active connection's object path.
        active: String,
        /// The new state.
        state: u32,
        /// The state's reason.
        reason: u32,
    },
    /// A device was added or removed, so re-read the Wi-Fi devices.
    DevicesChanged,
}

/// Why a `NetworkManager` call failed.
#[derive(Debug, thiserror::Error)]
pub enum NmIoError {
    /// The call failed, with the reason.
    #[error("NetworkManager refused: {0}")]
    Failed(String),
}

/// Why `NetworkManager` refused a request.
#[derive(Debug, thiserror::Error)]
pub enum AddError {
    /// The caller lacks a permission the request needs.
    #[error("NetworkManager refused for lack of a permission")]
    PermissionDenied,
    /// `NetworkManager` refused the request for another reason.
    #[error("NetworkManager refused: {0}")]
    Failed(String),
}

/// The I/O the hotspot backend needs from `NetworkManager`.
#[expect(
    async_fn_in_trait,
    reason = "the backend runs its calls on its own thread's current-thread runtime, so the futures are consumed there"
)]
pub trait NmIo: Send + Sync {
    /// The permission table, by name.
    async fn permissions(&self) -> Result<HashMap<String, String>, NmIoError>;
    /// Whether Wi-Fi is enabled.
    async fn wifi_enabled(&self) -> Result<bool, NmIoError>;
    /// The Wi-Fi devices, in `NetworkManager`'s order.
    async fn wifi_devices(&self) -> Result<Vec<WifiDevice>, NmIoError>;
    /// Activate a host or join connection, answering the active connection's
    /// path.
    async fn add_and_activate(&self, req: &AddRequest) -> Result<String, AddError>;
    /// Deactivate the active connection.
    async fn deactivate(&self, active: &str) -> Result<(), NmIoError>;
    /// The joined network's `IPv4` standing, from the active connection.
    async fn ipv4(&self, active: &str) -> Result<Ipv4Standing, NmIoError>;
    /// The next `NetworkManager` signal, or `None` once the bus is gone.
    async fn next_event(&self) -> Option<NmEvent>;
}

/// The real `NetworkManager` I/O, over the system bus.
pub struct ZbusNm {
    bus: zbus::Connection,
    events: Mutex<tokio::sync::mpsc::Receiver<NmEvent>>,
}

impl ZbusNm {
    /// Connect to the system bus and subscribe to the signals.
    ///
    /// # Errors
    ///
    /// [`NmIoError`] when the system bus will not stand within its bound.
    pub async fn new() -> Result<Self, NmIoError> {
        let bus = tokio::time::timeout(CALL_BOUND, zbus::Connection::system())
            .await
            .map_err(|_| {
                NmIoError::Failed("the system bus did not answer within its bound".into())
            })?
            .map_err(|err| NmIoError::Failed(err.to_string()))?;
        Self::new_with_connection(bus).await
    }

    /// Subscribe on a given bus connection, the seam the proofs' private
    /// buses stand.
    ///
    /// # Errors
    ///
    /// [`NmIoError`] when the state subscription will not stand within its
    /// bound.
    pub async fn new_with_connection(bus: zbus::Connection) -> Result<Self, NmIoError> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        // Every active connection's state change, subscribed before the
        // constructor answers, so no activation can settle ahead of the
        // match rule.
        let states = active_states(&bus).await?;
        // The signals into the one event channel, the row ending when the
        // event receiver closes, so the bus connection's lifetime ends with
        // the backend.
        let signal_bus = bus.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = tx.closed() => {}
                () = async {
                    tokio::join!(
                        forward_check_permissions(signal_bus.clone(), tx.clone()),
                        forward_devices(signal_bus.clone(), tx.clone()),
                        forward_wireless(signal_bus, tx.clone()),
                        forward_active_states(states, tx.clone()),
                    );
                } => {}
            }
        });
        Ok(Self {
            bus,
            events: Mutex::new(rx),
        })
    }
}

/// A bounded call, the timeout and a D-Bus refusal both `Failed`.
async fn call<T, F>(fut: F) -> Result<T, NmIoError>
where
    F: Future<Output = zbus::Result<T>>,
{
    match tokio::time::timeout(CALL_BOUND, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(NmIoError::Failed(err.to_string())),
        Err(_) => Err(NmIoError::Failed("the call timed out".into())),
    }
}

/// Whether a D-Bus refusal's name is the polkit permission's.
fn denied_name(name: &str) -> bool {
    name.ends_with("AccessDenied") || name.ends_with("PermissionDenied")
}

/// Whether a D-Bus refusal is the polkit permission's.
fn is_permission_denied(err: &zbus::Error) -> bool {
    match err {
        zbus::Error::MethodError(name, _, _) => denied_name(name.as_str()),
        other => other.to_string().contains("AccessDenied"),
    }
}

/// Forward the `CheckPermissions` signal to the event channel.
async fn forward_check_permissions(
    bus: zbus::Connection,
    events: tokio::sync::mpsc::Sender<NmEvent>,
) {
    let Ok(proxy) = NmProxy::new(&bus).await else {
        return;
    };
    let Ok(mut stream) = proxy.receive_check_permissions().await else {
        return;
    };
    while let Some(_signal) = stream.next().await {
        if events.send(NmEvent::CheckPermissions).await.is_err() {
            break;
        }
    }
}

/// Forward the `DeviceAdded` and `DeviceRemoved` signals to the event
/// channel as one device change.
async fn forward_devices(bus: zbus::Connection, events: tokio::sync::mpsc::Sender<NmEvent>) {
    let Ok(proxy) = NmProxy::new(&bus).await else {
        return;
    };
    let (Ok(added), Ok(removed)) = (
        proxy.receive_device_added().await,
        proxy.receive_device_removed().await,
    ) else {
        return;
    };
    let mut changes = futures_util::stream::select(added.map(|_| ()), removed.map(|_| ()));
    while changes.next().await.is_some() {
        if events.send(NmEvent::DevicesChanged).await.is_err() {
            break;
        }
    }
}

/// Forward the `wireless-enabled` property changes to the event channel.
async fn forward_wireless(bus: zbus::Connection, events: tokio::sync::mpsc::Sender<NmEvent>) {
    let Ok(proxy) = PropertiesProxy::new(&bus).await else {
        return;
    };
    let Ok(mut stream) = proxy.receive_properties_changed().await else {
        return;
    };
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else {
            continue;
        };
        if args.interface != "org.freedesktop.NetworkManager" {
            continue;
        }
        let Some(enabled) = args
            .properties
            .get("WirelessEnabled")
            .and_then(|value| value.downcast_ref::<bool>().ok())
        else {
            continue;
        };
        if events
            .send(NmEvent::WirelessEnabled(enabled))
            .await
            .is_err()
        {
            break;
        }
    }
}

/// The stream of `StateChanged` signals from every active connection under
/// `NetworkManager`'s active connection path.
async fn active_states(bus: &zbus::Connection) -> Result<zbus::MessageStream, NmIoError> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.NetworkManager.Connection.Active")
        .and_then(|rule| rule.member("StateChanged"))
        .and_then(|rule| rule.path_namespace("/org/freedesktop/NetworkManager/ActiveConnection"))
        .map_err(|err| NmIoError::Failed(err.to_string()))?
        .build();
    tokio::time::timeout(
        CALL_BOUND,
        zbus::MessageStream::for_match_rule(rule, bus, Some(64)),
    )
    .await
    .map_err(|_| {
        NmIoError::Failed("the state subscription did not answer within its bound".into())
    })?
    .map_err(|err| NmIoError::Failed(err.to_string()))
}

/// Forward each active connection's `StateChanged` to the channel, keyed by
/// the connection's path.
async fn forward_active_states(
    mut states: zbus::MessageStream,
    events: tokio::sync::mpsc::Sender<NmEvent>,
) {
    while let Some(message) = states.next().await {
        let Ok(message) = message else {
            continue;
        };
        let header = message.header();
        let Some(path) = header.path() else {
            continue;
        };
        let Ok((state, reason)) = message.body().deserialize::<(u32, u32)>() else {
            continue;
        };
        let event = NmEvent::StateChanged {
            active: path.as_str().to_owned(),
            state,
            reason,
        };
        if events.send(event).await.is_err() {
            break;
        }
    }
}

impl NmIo for ZbusNm {
    async fn permissions(&self) -> Result<HashMap<String, String>, NmIoError> {
        let proxy = NmProxy::new(&self.bus).await.map_err(dbus_error)?;
        call(proxy.get_permissions()).await
    }

    async fn wifi_enabled(&self) -> Result<bool, NmIoError> {
        let proxy = NmProxy::new(&self.bus).await.map_err(dbus_error)?;
        call(proxy.wireless_enabled()).await
    }

    async fn wifi_devices(&self) -> Result<Vec<WifiDevice>, NmIoError> {
        let proxy = NmProxy::new(&self.bus).await.map_err(dbus_error)?;
        let paths = call(proxy.get_devices()).await?;
        let mut out = Vec::new();
        for path in paths {
            let path_str = path.as_str().to_owned();
            let Ok(dev_builder) = DeviceProxy::builder(&self.bus).path(path) else {
                return Err(NmIoError::Failed("the device path is invalid".into()));
            };
            let dev = dev_builder.build().await.map_err(dbus_error)?;
            if call(dev.device_type()).await? != 2 {
                continue;
            }
            let hw = call(dev.hw_address()).await?;
            let managed = call(dev.managed()).await?;
            let Ok(wire_builder) = WirelessProxy::builder(&self.bus).path(path_str.as_str()) else {
                return Err(NmIoError::Failed("the device path is invalid".into()));
            };
            let wire = wire_builder.build().await.map_err(dbus_error)?;
            let caps = call(wire.wireless_capabilities()).await?;
            out.push(WifiDevice {
                path: path_str,
                hw_address: hw,
                capabilities: caps,
                managed,
            });
        }
        Ok(out)
    }

    async fn add_and_activate(&self, req: &AddRequest) -> Result<String, AddError> {
        let proxy = NmProxy::new(&self.bus)
            .await
            .map_err(|err| AddError::Failed(err.to_string()))?;
        let (settings, device) = match req {
            AddRequest::Host {
                device,
                band,
                ssid,
                passphrase,
            } => (host_settings(ssid, passphrase, *band), device),
            AddRequest::Join {
                device,
                ssid,
                passphrase,
                security,
            } => (join_settings(ssid, passphrase, *security), device),
        };
        let device_path: ObjectPath = device
            .as_str()
            .try_into()
            .map_err(|_| AddError::Failed("the device path is not a valid object path".into()))?;
        let root: ObjectPath = ObjectPath::try_from("/")
            .map_err(|_| AddError::Failed("the root object path is invalid".into()))?;
        let result = tokio::time::timeout(
            CALL_BOUND,
            proxy.add_and_activate_connection2(settings, device_path, root, options()),
        )
        .await;
        match result {
            // `AddAndActivateConnection2` answers the saved connection's path
            // first and the active connection's second.
            Ok(Ok((_connection, active, _result))) => Ok(active.as_str().to_owned()),
            Ok(Err(err)) => {
                if is_permission_denied(&err) {
                    Err(AddError::PermissionDenied)
                } else {
                    Err(AddError::Failed(err.to_string()))
                }
            }
            Err(_) => Err(AddError::Failed("the call timed out".into())),
        }
    }

    async fn deactivate(&self, active: &str) -> Result<(), NmIoError> {
        let proxy = NmProxy::new(&self.bus).await.map_err(dbus_error)?;
        let path: ObjectPath = active.try_into().map_err(|_| {
            NmIoError::Failed("the active connection is not a valid object path".into())
        })?;
        call(proxy.deactivate_connection(path)).await
    }

    async fn ipv4(&self, active: &str) -> Result<Ipv4Standing, NmIoError> {
        let Ok(active_builder) = ActiveProxy::builder(&self.bus).path(active) else {
            return Err(NmIoError::Failed(
                "the active connection is not a valid object path".into(),
            ));
        };
        let active_proxy = active_builder.build().await.map_err(dbus_error)?;
        let ip4_path = call(active_proxy.ip4_config()).await?;
        let Ok(ip4_builder) = Ip4Proxy::builder(&self.bus).path(ip4_path.as_str()) else {
            return Err(NmIoError::Failed("the IP4 config path is invalid".into()));
        };
        let ip4 = ip4_builder.build().await.map_err(dbus_error)?;
        let entries = call(ip4.address_data()).await?;
        let Some(first) = entries.first() else {
            return Err(NmIoError::Failed("the network has no address".into()));
        };
        let address = first
            .get("address")
            .and_then(|value| value.downcast_ref::<String>().ok())
            .and_then(|text| text.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| NmIoError::Failed("the network's address is not IPv4".into()))?;
        let prefix = prefix_of(first)?;
        let gateway = call(ip4.gateway()).await?;
        let routers = dhcp4_routers(&self.bus, &active_proxy).await;
        Ok(Ipv4Standing {
            address,
            prefix,
            gateway: pick_gateway(&gateway, routers),
        })
    }

    #[expect(
        clippy::await_holding_lock,
        reason = "the receiver's guard is held only across its own bounded recv"
    )]
    async fn next_event(&self) -> Option<NmEvent> {
        self.events.lock().recv().await
    }
}

/// The D-Bus refusal to the I/O's failure.
#[expect(
    clippy::needless_pass_by_value,
    reason = "map_err hands the error by value, so the function pointer takes it by value too"
)]
fn dbus_error(err: zbus::Error) -> NmIoError {
    NmIoError::Failed(err.to_string())
}

/// The joined network's gateway: the `IP4Config`'s where it stands, the
/// DHCP4 `routers`' first entry otherwise.
fn pick_gateway(config: &str, routers: Option<IpAddr>) -> Option<IpAddr> {
    config.parse::<IpAddr>().ok().or(routers)
}

/// The first router of a DHCP4 `routers` option, its entries separated by
/// whitespace.
fn first_router(routers: &str) -> Option<IpAddr> {
    routers
        .split_whitespace()
        .next()
        .and_then(|router| router.parse::<IpAddr>().ok())
}

/// Read the DHCP4 `routers` option, the gateway's fallback.
async fn dhcp4_routers(bus: &zbus::Connection, active: &ActiveProxy<'_>) -> Option<IpAddr> {
    let Ok(path) = call(active.dhcp4_config()).await else {
        return None;
    };
    let Ok(builder) = Dhcp4Proxy::builder(bus).path(path.as_str()) else {
        return None;
    };
    let Ok(dhcp4) = builder.build().await else {
        return None;
    };
    let Ok(options) = call(dhcp4.options()).await else {
        return None;
    };
    let routers = options
        .get("routers")
        .and_then(|value| value.downcast_ref::<String>().ok())?;
    first_router(&routers)
}

type Settings = HashMap<String, HashMap<String, Value<'static>>>;
type Options = HashMap<String, Value<'static>>;
/// `NetworkManager`'s D-Bus name for the Wi-Fi settings group.
const WIRELESS: &str = "802-11-wireless";
/// `NetworkManager`'s D-Bus name for the Wi-Fi security settings group.
const WIRELESS_SECURITY: &str = "802-11-wireless-security";

/// The host's settings groups.
fn host_settings(ssid: &str, passphrase: &str, band: Band) -> Settings {
    let band = match band {
        Band::Five => "a",
        Band::Two => "bg",
    };
    let mut connection = HashMap::new();
    connection.insert("id".to_owned(), Value::from("connetto-host"));
    connection.insert(
        "permissions".to_owned(),
        Value::from(vec![format!("user:{}:", login())]),
    );
    connection.insert("type".to_owned(), Value::from("802-11-wireless"));

    let mut wifi = HashMap::new();
    wifi.insert("ssid".to_owned(), Value::from(ssid.as_bytes().to_vec()));
    wifi.insert("mode".to_owned(), Value::from("ap"));
    wifi.insert("band".to_owned(), Value::from(band));

    let mut security = HashMap::new();
    security.insert("key-mgmt".to_owned(), Value::from("wpa-psk"));
    security.insert("psk".to_owned(), Value::Str(passphrase.to_string().into()));
    for (key, value) in [("proto", "rsn"), ("pairwise", "ccmp"), ("group", "ccmp")] {
        security.insert(key.to_owned(), Value::from(vec![value.to_owned()]));
    }

    let mut ipv4 = HashMap::new();
    ipv4.insert("method".to_owned(), Value::from("shared"));

    let mut ipv6 = HashMap::new();
    ipv6.insert("method".to_owned(), Value::from("disabled"));

    let mut settings = HashMap::new();
    settings.insert("connection".to_owned(), connection);
    settings.insert(WIRELESS.to_owned(), wifi);
    settings.insert(WIRELESS_SECURITY.to_owned(), security);
    settings.insert("ipv4".to_owned(), ipv4);
    settings.insert("ipv6".to_owned(), ipv6);
    settings
}

/// The join's settings groups.
fn join_settings(ssid: &str, passphrase: &str, security: Security) -> Settings {
    let key_mgmt = match security {
        Security::Wpa2 => "wpa-psk",
        Security::Wpa3 => "sae",
    };
    let mut connection = HashMap::new();
    connection.insert("id".to_owned(), Value::from("connetto-join"));
    connection.insert(
        "permissions".to_owned(),
        Value::from(vec![format!("user:{}:", login())]),
    );
    connection.insert("type".to_owned(), Value::from("802-11-wireless"));

    let mut wifi = HashMap::new();
    wifi.insert("ssid".to_owned(), Value::from(ssid.as_bytes().to_vec()));
    wifi.insert("mode".to_owned(), Value::from("infrastructure"));

    let mut sec = HashMap::new();
    sec.insert("key-mgmt".to_owned(), Value::from(key_mgmt));
    sec.insert("psk".to_owned(), Value::Str(passphrase.to_string().into()));

    let mut ipv4 = HashMap::new();
    ipv4.insert("method".to_owned(), Value::from("auto"));
    ipv4.insert("never-default".to_owned(), Value::from(true));

    let mut ipv6 = HashMap::new();
    ipv6.insert("method".to_owned(), Value::from("disabled"));

    let mut settings = HashMap::new();
    settings.insert("connection".to_owned(), connection);
    settings.insert(WIRELESS.to_owned(), wifi);
    settings.insert(WIRELESS_SECURITY.to_owned(), sec);
    settings.insert("ipv4".to_owned(), ipv4);
    settings.insert("ipv6".to_owned(), ipv6);
    settings
}

/// The volatile, client-bound options.
fn options() -> Options {
    let mut options = HashMap::new();
    options.insert("persist".to_owned(), Value::from("volatile"));
    options.insert("bind-activation".to_owned(), Value::from("dbus-client"));
    options
}

/// The login the connection is restricted to, the name the system's user
/// database (NSS) gives the process's real uid, as `NetworkManager` resolves
/// it, the `USER` environment never read.
fn login() -> String {
    let uid = nix::unistd::getuid();
    login_name(uid, nix::unistd::User::from_uid(uid))
}

/// The login name from the user database's answer, the numeric uid where
/// the database names no user.
fn login_name(
    uid: nix::unistd::Uid,
    user: Result<Option<nix::unistd::User>, nix::Error>,
) -> String {
    match user {
        Ok(Some(user)) => user.name,
        Ok(None) => {
            tracing::warn!(%uid, "the uid has no user name, the profile names the uid");
            uid.to_string()
        }
        Err(err) => {
            tracing::warn!(%uid, %err, "the user database did not answer, the profile names the uid");
            uid.to_string()
        }
    }
}

/// The address data entry's `prefix` field, a valid length.
fn prefix_of(entry: &HashMap<String, OwnedValue>) -> Result<u8, NmIoError> {
    entry
        .get("prefix")
        .and_then(|value| value.downcast_ref::<u32>().ok())
        .and_then(|prefix| u8::try_from(prefix).ok())
        .ok_or_else(|| NmIoError::Failed("the network's prefix is invalid".into()))
}

/// The `NetworkManager`'s main interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait Nm {
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    fn get_permissions(&self) -> zbus::Result<HashMap<String, String>>;
    #[zbus(property)]
    fn wireless_enabled(&self) -> zbus::Result<bool>;
    fn add_and_activate_connection2(
        &self,
        settings: Settings,
        device: ObjectPath<'_>,
        connection: ObjectPath<'_>,
        options: Options,
    ) -> zbus::Result<(
        OwnedObjectPath,
        OwnedObjectPath,
        HashMap<String, OwnedValue>,
    )>;
    fn deactivate_connection(&self, connection: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    fn check_permissions(&self) -> zbus::Result<()>;
    #[zbus(signal)]
    fn device_added(&self, device: OwnedObjectPath) -> zbus::Result<()>;
    #[zbus(signal)]
    fn device_removed(&self, device: OwnedObjectPath) -> zbus::Result<()>;
}

/// The `Properties` interface the signal forwarding subscribes to.
#[zbus::proxy(
    interface = "org.freedesktop.DBus.Properties",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait Properties {
    #[zbus(signal)]
    fn properties_changed(
        &self,
        interface: String,
        properties: HashMap<String, OwnedValue>,
        invalidated_properties: Vec<String>,
    ) -> zbus::Result<()>;
}

/// The active connection's interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Active {
    #[zbus(signal)]
    fn state_changed(&self, state: u32, reason: u32) -> zbus::Result<()>;
    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<ObjectPath<'static>>;
    #[zbus(property)]
    fn dhcp4_config(&self) -> zbus::Result<ObjectPath<'static>>;
}

/// The IP4 config's interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.IP4Config",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Ip4 {
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;
    #[zbus(property)]
    fn gateway(&self) -> zbus::Result<String>;
}

/// The DHCP4 config's interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.DHCP4Config",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Dhcp4 {
    #[zbus(property)]
    fn options(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
}

/// The device's interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Device {
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;
    #[zbus(property)]
    fn hw_address(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn managed(&self) -> zbus::Result<bool>;
}

/// The wireless device's interface.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
trait Wireless {
    #[zbus(property)]
    fn wireless_capabilities(&self) -> zbus::Result<u32>;
}

#[cfg(test)]
mod tests {
    use super::{
        AddError, AddRequest, Band, CAP_ACCESS_POINT, CAP_FREQ_5GHZ, Ipv4Standing, NmEvent, NmIo,
        NmIoError, Security, WIRELESS, WIRELESS_SECURITY, WifiDevice, ZbusNm, first_router,
        host_settings, join_settings, options, pick_gateway,
    };
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    type Group = HashMap<String, Value<'static>>;

    /// The settings and options as the bus answers them, owned values.
    type OwnedSettings = HashMap<String, HashMap<String, OwnedValue>>;
    type OwnedOptions = HashMap<String, OwnedValue>;

    /// One recorded `AddAndActivateConnection2` call, settings, device,
    /// saved connection and options.
    type Call = (
        OwnedSettings,
        OwnedObjectPath,
        OwnedObjectPath,
        OwnedOptions,
    );

    #[test]
    fn capability_bits() {
        let device = WifiDevice {
            path: "/org/freedesktop/NetworkManager/devices/wifi_0".into(),
            hw_address: "42:91:88:6f:0a:10".into(),
            capabilities: 0x40 | 0x400,
            managed: true,
        };
        assert!(device.is_access_point());
        assert!(device.has_five_ghz());

        let station = WifiDevice {
            path: "/org/freedesktop/NetworkManager/devices/wifi_1".into(),
            hw_address: "42:91:88:6f:0a:11".into(),
            capabilities: 0,
            managed: true,
        };
        assert!(!station.is_access_point());
        assert!(!station.has_five_ghz());
    }

    fn group<'a>(
        settings: &'a HashMap<String, Group>,
        name: &str,
    ) -> &'a HashMap<String, Value<'static>> {
        settings
            .get(name)
            .unwrap_or_else(|| panic!("the settings lack the {name} group"))
    }

    fn str_of(value: &Value, group: &str, key: &str) -> String {
        value
            .downcast_ref::<String>()
            .unwrap_or_else(|_| panic!("the {group} {key} value is not a string"))
    }

    /// The `Value`'s owned copy, for a downcast that consumes.
    fn owned(value: &Value<'static>) -> Value<'static> {
        (*value).clone()
    }

    /// The `String` of an owned wire value, the `None` the downcast's
    /// refusal.
    fn owned_str(value: &OwnedValue) -> Option<String> {
        value.downcast_ref::<String>().ok()
    }

    #[test]
    fn the_profile_names_the_process_identity() {
        // `id -un` resolves the real uid through the same user database.
        let id = std::process::Command::new("id")
            .arg("-un")
            .output()
            .expect("id runs");
        let expected = String::from_utf8(id.stdout).expect("the name is UTF-8");
        assert_eq!(super::login(), expected.trim());
    }

    #[test]
    fn the_prefix_stands_the_u32_wire_value() {
        let mut entry = HashMap::new();
        entry.insert("prefix".to_owned(), OwnedValue::from(24u32));
        assert!(matches!(super::prefix_of(&entry), Ok(prefix) if prefix == 24));
        let mut wide = HashMap::new();
        wide.insert("prefix".to_owned(), OwnedValue::from(256u32));
        assert!(matches!(super::prefix_of(&wide), Err(NmIoError::Failed(_))));

        let mut narrow = HashMap::new();
        narrow.insert("prefix".to_owned(), OwnedValue::from(24u8));
        assert!(matches!(
            super::prefix_of(&narrow),
            Err(NmIoError::Failed(_))
        ));

        let none = HashMap::new();
        assert!(matches!(super::prefix_of(&none), Err(NmIoError::Failed(_))));
    }

    #[test]
    fn the_permission_names_map_to_the_permission() {
        assert!(super::denied_name(
            "org.freedesktop.NetworkManager.PermissionDenied"
        ));
        assert!(super::denied_name(
            "org.freedesktop.DBus.Error.AccessDenied"
        ));
        assert!(!super::denied_name(
            "org.freedesktop.NetworkManager.PermissionsDenied"
        ));
        assert!(!super::denied_name("org.freedesktop.NetworkManager.Failed"));
    }

    #[test]
    fn host_settings_carry_the_plan() {
        let settings = host_settings("connetto-1a2b", "supersecret123", Band::Five);
        let connection = group(&settings, "connection");
        assert_eq!(
            str_of(&connection["id"], "connection", "id"),
            "connetto-host"
        );
        assert_eq!(
            owned(&connection["permissions"])
                .downcast::<Vec<String>>()
                .unwrap(),
            vec![format!("user:{}:", super::login())]
        );
        assert_eq!(
            str_of(&connection["type"], "connection", "type"),
            "802-11-wireless"
        );

        let wifi = group(&settings, WIRELESS);
        assert_eq!(
            owned(&wifi["ssid"]).downcast::<Vec<u8>>().unwrap(),
            b"connetto-1a2b".to_vec()
        );
        assert_eq!(str_of(&wifi["mode"], WIRELESS, "mode"), "ap");
        assert_eq!(str_of(&wifi["band"], WIRELESS, "band"), "a");

        let security = group(&settings, WIRELESS_SECURITY);
        assert_eq!(
            str_of(&security["key-mgmt"], WIRELESS_SECURITY, "key-mgmt"),
            "wpa-psk"
        );
        assert_eq!(
            str_of(&security["psk"], WIRELESS_SECURITY, "psk"),
            "supersecret123"
        );
        for (key, expected) in [("proto", "rsn"), ("pairwise", "ccmp"), ("group", "ccmp")] {
            assert_eq!(
                owned(&security[key]).downcast::<Vec<String>>().unwrap(),
                vec![expected.to_owned()],
                "{key} is a list of strings"
            );
        }
        assert_eq!(
            settings.len(),
            5,
            "no group under a name NetworkManager does not know"
        );

        let ipv4 = group(&settings, "ipv4");
        assert_eq!(str_of(&ipv4["method"], "ipv4", "method"), "shared");
        let ipv6 = group(&settings, "ipv6");
        assert_eq!(str_of(&ipv6["method"], "ipv6", "method"), "disabled");
    }

    #[test]
    fn host_settings_band_two_dot_four() {
        let settings = host_settings("connetto-1a2b", "supersecret123", Band::Two);
        assert_eq!(
            str_of(&group(&settings, WIRELESS)["band"], WIRELESS, "band"),
            "bg"
        );
    }

    #[test]
    fn join_settings_carry_the_plan() {
        let settings = join_settings("hostnet", "hostpass", Security::Wpa2);
        let connection = group(&settings, "connection");
        assert_eq!(
            str_of(&connection["id"], "connection", "id"),
            "connetto-join"
        );
        assert_eq!(
            owned(&connection["permissions"])
                .downcast::<Vec<String>>()
                .unwrap(),
            vec![format!("user:{}:", super::login())]
        );

        let wifi = group(&settings, WIRELESS);
        assert_eq!(
            owned(&wifi["ssid"]).downcast::<Vec<u8>>().unwrap(),
            b"hostnet".to_vec()
        );
        assert_eq!(str_of(&wifi["mode"], WIRELESS, "mode"), "infrastructure");

        let security = group(&settings, WIRELESS_SECURITY);
        assert_eq!(
            str_of(&security["key-mgmt"], WIRELESS_SECURITY, "key-mgmt"),
            "wpa-psk"
        );
        assert_eq!(
            str_of(&security["psk"], WIRELESS_SECURITY, "psk"),
            "hostpass"
        );
        assert!(
            !security.contains_key("pairwise"),
            "the join leaves the cipher to the host's offer"
        );
        assert_eq!(
            settings.len(),
            5,
            "no group under a name NetworkManager does not know"
        );

        let ipv4 = group(&settings, "ipv4");
        assert_eq!(str_of(&ipv4["method"], "ipv4", "method"), "auto");
        assert!(ipv4["never-default"].downcast_ref::<bool>().unwrap());
        let ipv6 = group(&settings, "ipv6");
        assert_eq!(str_of(&ipv6["method"], "ipv6", "method"), "disabled");
    }

    #[test]
    fn join_settings_sae_for_wpa3() {
        let settings = join_settings("hostnet", "hostpass", Security::Wpa3);
        assert_eq!(
            str_of(
                &group(&settings, WIRELESS_SECURITY)["key-mgmt"],
                WIRELESS_SECURITY,
                "key-mgmt"
            ),
            "sae"
        );
    }

    #[test]
    fn options_are_volatile_and_client_bound() {
        let options = options();
        assert_eq!(
            str_of(&options["persist"], "options", "persist"),
            "volatile"
        );
        assert_eq!(
            str_of(&options["bind-activation"], "options", "bind-activation"),
            "dbus-client"
        );
    }

    #[test]
    fn gateway_falls_back_to_the_routers() {
        let router = IpAddr::from(Ipv4Addr::new(10, 42, 0, 1));
        assert_eq!(
            pick_gateway("192.168.43.1", Some(router)),
            Some(IpAddr::from(Ipv4Addr::new(192, 168, 43, 1)))
        );
        assert_eq!(pick_gateway("", Some(router)), Some(router));
        assert_eq!(
            pick_gateway("10.42.0.1", None),
            Some(IpAddr::from(Ipv4Addr::new(10, 42, 0, 1)))
        );
        assert_eq!(pick_gateway("", None), None);
    }

    #[test]
    fn the_first_router_of_the_option() {
        assert_eq!(
            first_router("10.42.0.1 10.42.0.2"),
            Some(IpAddr::from(Ipv4Addr::new(10, 42, 0, 1)))
        );
        assert_eq!(first_router(""), None);
        assert_eq!(first_router("not-an-ip"), None);
        assert_eq!(
            first_router("  192.168.1.254 "),
            Some(IpAddr::from(Ipv4Addr::new(192, 168, 1, 254)))
        );
    }

    #[test]
    fn the_host_request_carries_the_offer() {
        let req = AddRequest::Host {
            device: "/org/freedesktop/NetworkManager/devices/wifi_0".into(),
            band: Band::Five,
            ssid: "connetto-1a2b".into(),
            passphrase: "supersecret123".into(),
        };
        match req {
            AddRequest::Host { band, ssid, .. } => {
                assert!(matches!(band, Band::Five));
                assert_eq!(ssid, "connetto-1a2b");
            }
            other @ AddRequest::Join { .. } => panic!("the request is not a host, {other:?}"),
        }
    }

    #[test]
    fn the_standing_carries_the_network() {
        let standing = Ipv4Standing {
            address: Ipv4Addr::new(10, 42, 0, 10),
            prefix: 24,
            gateway: Some(IpAddr::from(Ipv4Addr::new(10, 42, 0, 1))),
        };
        assert_eq!(standing.prefix, 24);
        assert_eq!(standing.address, Ipv4Addr::new(10, 42, 0, 10));
    }

    #[test]
    fn the_share_right_is_named() {
        assert_eq!(
            super::WIFI_SHARE_PROTECTED,
            "org.freedesktop.NetworkManager.wifi.share.protected"
        );
        assert_eq!(
            super::NETWORK_CONTROL,
            "org.freedesktop.NetworkManager.network-control"
        );
        assert_eq!(
            super::SETTINGS_MODIFY_OWN,
            "org.freedesktop.NetworkManager.settings.modify.own"
        );
    }

    #[test]
    fn the_state_event_carries_the_reason() {
        let event = NmEvent::StateChanged {
            active: "/org/freedesktop/NetworkManager/ActiveConnection/1".into(),
            state: 3,
            reason: 0,
        };
        match event {
            NmEvent::StateChanged { state, reason, .. } => {
                assert_eq!(state, 3);
                assert_eq!(reason, 0);
            }
            other => panic!("the event is not a state change, {other:?}"),
        }
    }

    async fn bus_names(names: &zbus::fdo::DBusProxy<'_>) -> std::collections::BTreeSet<String> {
        names
            .list_names()
            .await
            .expect("the bus's names")
            .into_iter()
            .map(|name| name.to_string())
            .collect()
    }

    /// Poll the bus's names until at least one name beyond `baseline`
    /// stands, or `bound` stands, the standing names returned.
    async fn names_stand(
        names: &zbus::fdo::DBusProxy<'_>,
        baseline: &std::collections::BTreeSet<String>,
        bound: std::time::Duration,
    ) -> std::collections::BTreeSet<String> {
        let deadline = std::time::Instant::now() + bound;
        loop {
            let standing = bus_names(names).await;
            if standing.difference(baseline).count() > 0 {
                return standing;
            }
            if std::time::Instant::now() >= deadline {
                return standing;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    /// Poll the bus's names until `gone` are all free, or `bound` stands.
    async fn names_free(
        names: &zbus::fdo::DBusProxy<'_>,
        gone: &std::collections::BTreeSet<String>,
        bound: std::time::Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + bound;
        loop {
            let standing = bus_names(names).await;
            if gone.iter().all(|name| !standing.contains(name)) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// A dropped client releases its bus connection, the daemon keeping the
    /// client's unique name free, the runtime standing.
    #[tokio::test]
    async fn a_dropped_client_releases_its_bus_connection() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let observer = bus.connect().await;
        let names = zbus::fdo::DBusProxy::new(&observer)
            .await
            .expect("the bus proxy");
        let baseline = bus_names(&names).await;
        let client = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        let standing = names_stand(&names, &baseline, std::time::Duration::from_secs(5)).await;
        let created: std::collections::BTreeSet<String> =
            standing.difference(&baseline).cloned().collect();
        assert_ne!(
            created.len(),
            0,
            "the client's connection did not stand within its bound"
        );
        drop(client);
        assert!(
            names_free(&names, &created, std::time::Duration::from_secs(5)).await,
            "the dropped client retained its bus connection"
        );
    }

    const WIFI_DEVICE: &str = "/org/freedesktop/NetworkManager/devices/wifi_0";
    const ETH_DEVICE: &str = "/org/freedesktop/NetworkManager/devices/eth_0";
    const ACTIVE_CONNECTION: &str = "/org/freedesktop/NetworkManager/ActiveConnection/1";
    const IP4_CONFIG: &str = "/org/freedesktop/NetworkManager/IP4Config/1";
    const DHCP4_CONFIG: &str = "/org/freedesktop/NetworkManager/DHCP4Config/1";

    const MODE_OK: u8 = 0;
    const MODE_PERMISSION_DENIED: u8 = 1;
    const MODE_FAILED: u8 = 2;

    /// The manager's refusal, its names the polkit permission's and the
    /// other failure's.
    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.freedesktop.NetworkManager")]
    enum FakeRefusal {
        /// The manager refuses for lack of a permission.
        PermissionDenied,
        /// The manager refuses for another reason.
        Failed(String),
    }

    /// The fake `NetworkManager` the proofs answer on a private bus, the
    /// `AddAndActivateConnection2` requests, the refusal mode and the
    /// deactivated connections kept.
    struct FakeNm {
        /// The requests, settings and options kept.
        calls: Arc<Mutex<Vec<Call>>>,
        /// The refusal mode, the proofs' switch.
        mode: Arc<AtomicU8>,
        /// The `DeactivateConnection` calls kept.
        deactivated: Arc<Mutex<Vec<OwnedObjectPath>>>,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager")]
    impl FakeNm {
        #[zbus(property)]
        #[expect(
            clippy::unused_self,
            reason = "the zbus property signature keeps the manager reference"
        )]
        fn wireless_enabled(&self) -> bool {
            true
        }

        #[expect(
            clippy::unused_self,
            reason = "the zbus method signature keeps the manager reference"
        )]
        fn get_devices(&self) -> Vec<OwnedObjectPath> {
            [WIFI_DEVICE, ETH_DEVICE]
                .iter()
                .map(|path| OwnedObjectPath::try_from(*path).expect("the device path"))
                .collect()
        }

        fn add_and_activate_connection2(
            &self,
            settings: OwnedSettings,
            device: OwnedObjectPath,
            saved: OwnedObjectPath,
            options: OwnedOptions,
        ) -> Result<
            (
                OwnedObjectPath,
                OwnedObjectPath,
                HashMap<String, OwnedValue>,
            ),
            FakeRefusal,
        > {
            let mode = self.mode.load(Ordering::Relaxed);
            if mode == MODE_PERMISSION_DENIED {
                return Err(FakeRefusal::PermissionDenied);
            }
            if mode == MODE_FAILED {
                return Err(FakeRefusal::Failed("another refusal".into()));
            }
            self.calls.lock().push((settings, device, saved, options));
            let saved = OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Connection/1")
                .expect("the saved connection path");
            let active = OwnedObjectPath::try_from(ACTIVE_CONNECTION).expect("the active path");
            Ok((saved, active, HashMap::new()))
        }

        fn deactivate_connection(&self, active: OwnedObjectPath) {
            self.deactivated.lock().push(active);
        }
    }

    /// A `NetworkManager` device the proofs list, its `Device` interface
    /// answering the type, the address and the managed flag.
    struct FakeDevice {
        device_type: u32,
        hw_address: String,
        managed: bool,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
    impl FakeDevice {
        #[zbus(property)]
        fn device_type(&self) -> u32 {
            self.device_type
        }

        #[zbus(property)]
        fn hw_address(&self) -> String {
            self.hw_address.clone()
        }

        #[zbus(property)]
        fn managed(&self) -> bool {
            self.managed
        }
    }

    /// The wireless interface the proofs read the capability bits from.
    struct FakeWireless {
        capabilities: u32,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.Device.Wireless")]
    impl FakeWireless {
        #[zbus(property)]
        fn wireless_capabilities(&self) -> u32 {
            self.capabilities
        }
    }

    /// The active connection the proofs read the standing from, the
    /// `IP4Config` and `DHCP4Config` paths named.
    struct FakeActive {
        ip4_config: String,
        dhcp4_config: String,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
    impl FakeActive {
        #[zbus(property)]
        fn ip4_config(&self) -> OwnedObjectPath {
            OwnedObjectPath::try_from(self.ip4_config.as_str()).expect("the IP4 config path")
        }

        #[zbus(property)]
        fn dhcp4_config(&self) -> OwnedObjectPath {
            OwnedObjectPath::try_from(self.dhcp4_config.as_str()).expect("the DHCP4 config path")
        }
    }

    /// The `IP4Config` the proofs read the address and the gateway from.
    struct FakeIp4 {
        address_data: Vec<HashMap<String, OwnedValue>>,
        gateway: String,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.IP4Config")]
    impl FakeIp4 {
        #[zbus(property)]
        fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
            self.address_data.clone()
        }

        #[zbus(property)]
        fn gateway(&self) -> String {
            self.gateway.clone()
        }
    }

    /// The `DHCP4Config` the proofs read the routers from.
    struct FakeDhcp4 {
        routers: String,
    }

    #[zbus::interface(name = "org.freedesktop.NetworkManager.DHCP4Config")]
    impl FakeDhcp4 {
        #[zbus(property)]
        fn options(&self) -> HashMap<String, OwnedValue> {
            let mut options = HashMap::new();
            options.insert(
                "routers".to_owned(),
                OwnedValue::from(zbus::zvariant::Str::from(self.routers.clone())),
            );
            options
        }
    }

    /// A `NetworkManager` whose answer sleeps past the client's bound, for
    /// the timeout's proof.
    struct SlowNm;

    #[zbus::interface(name = "org.freedesktop.NetworkManager")]
    impl SlowNm {
        async fn get_devices(&self) -> Vec<OwnedObjectPath> {
            tokio::time::sleep(Duration::from_secs(6)).await;
            Vec::new()
        }

        async fn add_and_activate_connection2(
            &self,
            settings: OwnedSettings,
            device: OwnedObjectPath,
            saved: OwnedObjectPath,
            options: OwnedOptions,
        ) -> (
            OwnedObjectPath,
            OwnedObjectPath,
            HashMap<String, OwnedValue>,
        ) {
            let _ = (settings, device, saved, options);
            tokio::time::sleep(Duration::from_secs(6)).await;
            (
                OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Connection/1")
                    .expect("the saved connection path"),
                OwnedObjectPath::try_from(ACTIVE_CONNECTION).expect("the active path"),
                HashMap::new(),
            )
        }
    }

    /// Stand the fake `NetworkManager` on a private bus, the service
    /// connection kept by the caller, the requests, the refusal mode and
    /// the deactivated connections shared back.
    async fn serve_fake_nm(
        bus: &crate::linux::test_bus::PrivateBus,
    ) -> (
        zbus::Connection,
        Arc<Mutex<Vec<Call>>>,
        Arc<AtomicU8>,
        Arc<Mutex<Vec<OwnedObjectPath>>>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(AtomicU8::new(MODE_OK));
        let deactivated = Arc::new(Mutex::new(Vec::new()));
        let server = zbus::connection::Builder::address(bus.address.as_str())
            .expect("the bus address")
            .name("org.freedesktop.NetworkManager")
            .expect("the service name")
            .serve_at(
                "/org/freedesktop/NetworkManager",
                FakeNm {
                    calls: calls.clone(),
                    mode: mode.clone(),
                    deactivated: deactivated.clone(),
                },
            )
            .expect("the manager")
            .serve_at(
                WIFI_DEVICE,
                FakeDevice {
                    device_type: 2,
                    hw_address: "42:91:88:6f:0a:10".into(),
                    managed: true,
                },
            )
            .expect("the Wi-Fi device")
            .serve_at(
                WIFI_DEVICE,
                FakeWireless {
                    capabilities: CAP_ACCESS_POINT | CAP_FREQ_5GHZ,
                },
            )
            .expect("the Wi-Fi capability")
            .serve_at(
                ETH_DEVICE,
                FakeDevice {
                    device_type: 1,
                    hw_address: "42:91:88:6f:0a:11".into(),
                    managed: true,
                },
            )
            .expect("the Ethernet device")
            .build()
            .await
            .expect("the fake manager");
        (server, calls, mode, deactivated)
    }

    /// One `AddressData` entry, the address string and the prefix kept.
    fn address_entry(address: &str, prefix: u32) -> HashMap<String, OwnedValue> {
        let mut entry = HashMap::new();
        entry.insert(
            "address".to_owned(),
            OwnedValue::from(zbus::zvariant::Str::from(address.to_owned())),
        );
        entry.insert("prefix".to_owned(), OwnedValue::from(prefix));
        entry
    }

    /// Stand the active connection's standing on a private bus, the
    /// service connection kept by the caller, the address entries, the
    /// `IP4Config` gateway and the `DHCP4Config` routers where they stand.
    async fn serve_standing(
        bus: &crate::linux::test_bus::PrivateBus,
        entries: Vec<HashMap<String, OwnedValue>>,
        gateway: &str,
        routers: Option<&str>,
    ) -> zbus::Connection {
        let builder = zbus::connection::Builder::address(bus.address.as_str())
            .expect("the bus address")
            .name("org.freedesktop.NetworkManager")
            .expect("the service name")
            .serve_at(
                ACTIVE_CONNECTION,
                FakeActive {
                    ip4_config: IP4_CONFIG.to_owned(),
                    dhcp4_config: DHCP4_CONFIG.to_owned(),
                },
            )
            .expect("the active connection")
            .serve_at(
                IP4_CONFIG,
                FakeIp4 {
                    address_data: entries,
                    gateway: gateway.to_owned(),
                },
            )
            .expect("the IP4 config");
        match routers {
            Some(routers) => builder
                .serve_at(
                    DHCP4_CONFIG,
                    FakeDhcp4 {
                        routers: routers.to_owned(),
                    },
                )
                .expect("the DHCP4 config")
                .build()
                .await
                .expect("the standing service"),
            None => builder.build().await.expect("the standing service"),
        }
    }

    /// Emit a signal on the fake's service connection, the client's match
    /// rules its receiver.
    async fn emit_signal(
        bus: &zbus::Connection,
        path: &str,
        interface: &str,
        member: &str,
        body: &(impl serde::Serialize + zbus::zvariant::DynamicType),
    ) {
        let message = zbus::Message::signal(path, interface, member)
            .expect("the signal stands")
            .build(body)
            .expect("the signal body serializes");
        bus.send(&message)
            .await
            .expect("the signal reaches the bus");
    }

    /// The device listing keeps the Wi-Fi device and its fields, the
    /// non-Wi-Fi device filtered out, over a fake `NetworkManager` on a
    /// private bus.
    #[tokio::test]
    async fn the_listing_keeps_only_the_wifi_devices() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let _server = serve_fake_nm(&bus).await.0;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        assert!(
            io.wifi_enabled().await.expect("the read stands"),
            "the manager says Wi-Fi is enabled"
        );
        let devices = io.wifi_devices().await.expect("the listing stands");
        assert_eq!(devices.len(), 1, "the non-Wi-Fi device is filtered out");
        let device = &devices[0];
        assert_eq!(device.path, WIFI_DEVICE);
        assert_eq!(device.hw_address, "42:91:88:6f:0a:10");
        assert!(device.managed, "the device is managed");
        assert!(device.is_access_point());
        assert!(device.has_five_ghz());
    }

    /// The host and join requests reach the manager with their settings,
    /// the answer the active connection's path, over a fake
    /// `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_requests_reach_the_manager_and_answer_the_active_path() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (_server, calls, _mode, _deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        let active = io
            .add_and_activate(&AddRequest::Host {
                device: WIFI_DEVICE.to_owned(),
                band: Band::Five,
                ssid: "connetto-1a2b".into(),
                passphrase: "supersecret123".into(),
            })
            .await
            .expect("the host request stands");
        assert_eq!(active, ACTIVE_CONNECTION);

        let (settings, device, _saved, opts) =
            calls.lock().first().expect("the host call stands").clone();
        assert_eq!(device.as_str(), WIFI_DEVICE);
        let wifi = &settings[WIRELESS];
        assert_eq!(
            owned(&wifi["ssid"]).downcast::<Vec<u8>>().unwrap(),
            b"connetto-1a2b".to_vec()
        );
        assert_eq!(owned_str(&wifi["mode"]), Some("ap".to_owned()));
        assert_eq!(owned_str(&wifi["band"]), Some("a".to_owned()));
        assert_eq!(
            owned_str(&settings["connection"]["id"]),
            Some("connetto-host".to_owned())
        );
        assert_eq!(owned_str(&opts["persist"]), Some("volatile".to_owned()));

        let active = io
            .add_and_activate(&AddRequest::Join {
                device: WIFI_DEVICE.to_owned(),
                ssid: "hostnet".into(),
                passphrase: "hostpass".into(),
                security: Security::Wpa3,
            })
            .await
            .expect("the join request stands");
        assert_eq!(active, ACTIVE_CONNECTION);

        let (settings, device, _saved, _opts) =
            calls.lock().last().expect("the join call stands").clone();
        assert_eq!(device.as_str(), WIFI_DEVICE);
        assert_eq!(
            owned_str(&settings["connection"]["id"]),
            Some("connetto-join".to_owned())
        );
        assert_eq!(
            owned_str(&settings[WIRELESS]["mode"]),
            Some("infrastructure".to_owned())
        );
        assert_eq!(
            owned_str(&settings[WIRELESS_SECURITY]["key-mgmt"]),
            Some("sae".to_owned())
        );
    }

    /// A permission refusal maps to the missing permission, another
    /// refusal to the failed reason, over a fake `NetworkManager` on a
    /// private bus.
    #[tokio::test]
    async fn a_refusal_maps_to_its_reason() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (_server, _calls, mode, _deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        let request = AddRequest::Host {
            device: WIFI_DEVICE.to_owned(),
            band: Band::Five,
            ssid: "connetto-1a2b".into(),
            passphrase: "supersecret123".into(),
        };
        mode.store(MODE_PERMISSION_DENIED, Ordering::Relaxed);
        let err = io
            .add_and_activate(&request)
            .await
            .expect_err("the refusal stands");
        assert!(
            matches!(err, AddError::PermissionDenied),
            "the refusal is the missing permission, {err:?}"
        );
        mode.store(MODE_FAILED, Ordering::Relaxed);
        let err = io
            .add_and_activate(&request)
            .await
            .expect_err("the refusal stands");
        assert!(
            matches!(err, AddError::Failed(_)),
            "the refusal is the failed reason, {err:?}"
        );
    }

    /// A device `NetworkManager` adds or removes arrives as the one
    /// `DevicesChanged` event.
    #[tokio::test]
    async fn the_device_signals_arrive_as_a_device_change() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (server, _calls, _mode, _deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        let device =
            zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/NetworkManager/Devices/7")
                .expect("the device path");
        for member in ["DeviceAdded", "DeviceRemoved"] {
            let event = event_after(
                &io,
                || {
                    let device = device.clone();
                    let server = &server;
                    async move {
                        emit_signal(
                            server,
                            "/org/freedesktop/NetworkManager",
                            "org.freedesktop.NetworkManager",
                            member,
                            &(device,),
                        )
                        .await;
                    }
                },
                |event| matches!(event, NmEvent::DevicesChanged),
            )
            .await;
            assert!(matches!(event, NmEvent::DevicesChanged), "{member}");
        }
    }

    /// Each `NetworkManager` signal arrives as its event, over a fake
    /// `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_signals_arrive_as_their_events() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (server, _calls, _mode, _deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        // The forwarders register their match rules on a spawned task, so
        // each signal is emitted again until its event arrives, bounded.
        let event = event_after(
            &io,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.NetworkManager",
                    "CheckPermissions",
                    &(),
                )
            },
            |event| matches!(event, NmEvent::CheckPermissions),
        )
        .await;
        assert!(matches!(event, NmEvent::CheckPermissions));

        let mut properties = HashMap::new();
        properties.insert("WirelessEnabled".to_owned(), OwnedValue::from(false));
        let invalidated: Vec<String> = Vec::new();
        let changed = ("org.freedesktop.NetworkManager", &properties, &invalidated);
        let event = event_after(
            &io,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &changed,
                )
            },
            |event| matches!(event, NmEvent::WirelessEnabled(_)),
        )
        .await;
        assert!(
            matches!(event, NmEvent::WirelessEnabled(false)),
            "the wireless change is its event, {event:?}"
        );

        let event = event_after(
            &io,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager/ActiveConnection/7",
                    "org.freedesktop.NetworkManager.Connection.Active",
                    "StateChanged",
                    &(3u32, 1u32),
                )
            },
            |event| matches!(event, NmEvent::StateChanged { .. }),
        )
        .await;
        assert!(
            matches!(
                &event,
                NmEvent::StateChanged { active, state, reason }
                    if active == "/org/freedesktop/NetworkManager/ActiveConnection/7"
                        && *state == 3
                        && *reason == 1
            ),
            "the state change is its event, {event:?}"
        );
    }

    /// The first event of the kind `wanted` names, `emit` sent again until
    /// it arrives within ten seconds, events of other kinds passed over.
    async fn event_after<F: Future<Output = ()>>(
        io: &ZbusNm,
        emit: impl Fn() -> F,
        wanted: impl Fn(&NmEvent) -> bool,
    ) -> NmEvent {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the event did not arrive within its bound"
            );
            emit().await;
            while let Ok(event) =
                tokio::time::timeout(Duration::from_millis(200), io.next_event()).await
            {
                let event = event.expect("the event channel closed");
                if wanted(&event) {
                    return event;
                }
            }
        }
    }

    /// The first event of the kind `wanted` names, `emit` sent again until
    /// it arrives within ten seconds, over a bare event receiver.
    async fn event_after_rx<F: Future<Output = ()>>(
        rx: &mut tokio::sync::mpsc::Receiver<NmEvent>,
        emit: impl Fn() -> F,
        wanted: impl Fn(&NmEvent) -> bool,
    ) -> NmEvent {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the event did not arrive within its bound"
            );
            emit().await;
            while let Ok(event) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await
            {
                let event = event.expect("the event channel closed");
                if wanted(&event) {
                    return event;
                }
            }
        }
    }

    /// An answer past the bound is the timeout's failure, over a slow
    /// fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn a_slow_answer_times_out_on_the_call_bound() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let _server = zbus::connection::Builder::address(bus.address.as_str())
            .expect("the bus address")
            .name("org.freedesktop.NetworkManager")
            .expect("the service name")
            .serve_at("/org/freedesktop/NetworkManager", SlowNm)
            .expect("the slow manager")
            .build()
            .await
            .expect("the slow manager service");
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        let err = io
            .wifi_devices()
            .await
            .expect_err("the slow answer must time out");
        assert!(
            matches!(&err, NmIoError::Failed(text) if text.contains("timed out")),
            "the failure is the timeout, {err:?}"
        );
    }

    /// The joined network's standing stands the address, the prefix and
    /// the gateway, the empty gateway answered by the `DHCP4Config`
    /// routers, over a fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_standing_stands_the_address_the_prefix_and_the_gateway() {
        // The `IP4Config` gateway stands, the `DHCP4Config` routers behind it.
        {
            let bus = crate::linux::test_bus::PrivateBus::start();
            let _server = serve_standing(
                &bus,
                vec![address_entry("10.42.0.10", 24)],
                "192.168.43.1",
                Some("10.42.0.1 10.42.0.2"),
            )
            .await;
            let io = ZbusNm::new_with_connection(bus.connect().await)
                .await
                .expect("the network manager client");
            let standing = io
                .ipv4(ACTIVE_CONNECTION)
                .await
                .expect("the standing stands");
            assert_eq!(standing.address, Ipv4Addr::new(10, 42, 0, 10));
            assert_eq!(standing.prefix, 24);
            assert_eq!(
                standing.gateway,
                Some(IpAddr::from(Ipv4Addr::new(192, 168, 43, 1))),
                "the IP4Config gateway stands"
            );
        }
        // The empty gateway stands the first router.
        {
            let bus = crate::linux::test_bus::PrivateBus::start();
            let _server = serve_standing(
                &bus,
                vec![address_entry("10.42.0.10", 24)],
                "",
                Some("10.42.0.1 10.42.0.2"),
            )
            .await;
            let io = ZbusNm::new_with_connection(bus.connect().await)
                .await
                .expect("the network manager client");
            let standing = io
                .ipv4(ACTIVE_CONNECTION)
                .await
                .expect("the standing stands");
            assert_eq!(
                standing.gateway,
                Some(IpAddr::from(Ipv4Addr::new(10, 42, 0, 1))),
                "the first router stands the empty gateway"
            );
        }
        // A missing `DHCP4Config` leaves the gateway to the `IP4Config`.
        {
            let bus = crate::linux::test_bus::PrivateBus::start();
            let _server = serve_standing(
                &bus,
                vec![address_entry("10.42.0.10", 24)],
                "192.168.43.1",
                None,
            )
            .await;
            let io = ZbusNm::new_with_connection(bus.connect().await)
                .await
                .expect("the network manager client");
            let standing = io
                .ipv4(ACTIVE_CONNECTION)
                .await
                .expect("the standing stands");
            assert_eq!(
                standing.gateway,
                Some(IpAddr::from(Ipv4Addr::new(192, 168, 43, 1))),
                "the IP4Config gateway stands"
            );
        }
    }

    /// The standing is refused on a network with no address and on an
    /// address that is not `IPv4`, over a fake `NetworkManager` on a
    /// private bus.
    #[tokio::test]
    async fn the_standing_refuses_a_network_without_an_ipv4_address() {
        {
            let bus = crate::linux::test_bus::PrivateBus::start();
            let _server = serve_standing(&bus, Vec::new(), "192.168.43.1", Some("10.42.0.1")).await;
            let io = ZbusNm::new_with_connection(bus.connect().await)
                .await
                .expect("the network manager client");
            let err = io
                .ipv4(ACTIVE_CONNECTION)
                .await
                .expect_err("the refusal stands");
            assert!(
                matches!(&err, NmIoError::Failed(text) if text.contains("no address")),
                "the network has no address, {err:?}"
            );
        }
        {
            let bus = crate::linux::test_bus::PrivateBus::start();
            let _server = serve_standing(
                &bus,
                vec![address_entry("not-an-ip", 24)],
                "192.168.43.1",
                Some("10.42.0.1"),
            )
            .await;
            let io = ZbusNm::new_with_connection(bus.connect().await)
                .await
                .expect("the network manager client");
            let err = io
                .ipv4(ACTIVE_CONNECTION)
                .await
                .expect_err("the refusal stands");
            assert!(
                matches!(&err, NmIoError::Failed(text) if text.contains("not IPv4")),
                "the address is not IPv4, {err:?}"
            );
        }
    }

    /// The deactivation reaches the manager with the active connection's
    /// path, over a fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_deactivation_reaches_the_manager() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (_server, _calls, _mode, deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        io.deactivate(ACTIVE_CONNECTION)
            .await
            .expect("the deactivation stands");
        let kept = deactivated.lock().clone();
        assert_eq!(kept.len(), 1, "the manager kept the one deactivation");
        assert_eq!(kept[0].as_str(), ACTIVE_CONNECTION);
    }

    /// An invalid object path is refused before it reaches the manager,
    /// over an absent fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn an_invalid_object_path_is_refused() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        let err = io
            .ipv4("not a path")
            .await
            .expect_err("the path is refused");
        assert!(
            matches!(&err, NmIoError::Failed(text) if text.contains("not a valid object path")),
            "the refusal is the invalid path, {err:?}"
        );
        let err = io
            .deactivate("not a path")
            .await
            .expect_err("the path is refused");
        assert!(
            matches!(&err, NmIoError::Failed(text) if text.contains("not a valid object path")),
            "the refusal is the invalid path, {err:?}"
        );
    }

    /// The signals of the wrong shape, the unrelated interface and the
    /// wrong path are passed over, the expected one arrives, over a fake
    /// `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_unrelated_and_malformed_signals_produce_no_event() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (server, _calls, _mode, _deactivated) = serve_fake_nm(&bus).await;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        // Each kind lands once, so the match rules are registered before
        // the filtered signals are sent.
        land_each_signal_kind(&io, &server).await;

        // The wrong shapes, the unrelated interface and the wrong path,
        // then the queue must stand empty.
        emit_filtered_signals(&server).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), io.next_event())
                .await
                .is_err(),
            "the filtered signals must produce no event"
        );

        let properties = wireless_change(false);
        let invalidated: Vec<String> = Vec::new();
        let changed = ("org.freedesktop.NetworkManager", &properties, &invalidated);
        let event = event_after(
            &io,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &changed,
                )
            },
            |event| matches!(event, NmEvent::WirelessEnabled(_)),
        )
        .await;
        assert!(matches!(event, NmEvent::WirelessEnabled(false)));
    }

    /// The `PropertiesChanged` body the wireless proof sends, the
    /// `WirelessEnabled` value kept.
    fn wireless_change(on: bool) -> HashMap<String, OwnedValue> {
        let mut properties = HashMap::new();
        properties.insert("WirelessEnabled".to_owned(), OwnedValue::from(on));
        properties
    }

    /// Land each signal kind once, the forwarders' match rules standing
    /// before the filtered signals are sent.
    async fn land_each_signal_kind(io: &ZbusNm, server: &zbus::Connection) {
        let _ = event_after(
            io,
            || {
                emit_signal(
                    server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.NetworkManager",
                    "CheckPermissions",
                    &(),
                )
            },
            |event| matches!(event, NmEvent::CheckPermissions),
        )
        .await;

        let properties = wireless_change(true);
        let invalidated: Vec<String> = Vec::new();
        let changed = ("org.freedesktop.NetworkManager", &properties, &invalidated);
        let _ = event_after(
            io,
            || {
                emit_signal(
                    server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &changed,
                )
            },
            |event| matches!(event, NmEvent::WirelessEnabled(_)),
        )
        .await;

        let _ = event_after(
            io,
            || {
                emit_signal(
                    server,
                    "/org/freedesktop/NetworkManager/ActiveConnection/9",
                    "org.freedesktop.NetworkManager.Connection.Active",
                    "StateChanged",
                    &(1u32, 0u32),
                )
            },
            |event| matches!(event, NmEvent::StateChanged { .. }),
        )
        .await;
    }

    /// The signals the forwarders must pass over, the wrong shapes, the
    /// unrelated interface and the wrong path.
    async fn emit_filtered_signals(server: &zbus::Connection) {
        emit_signal(
            server,
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &"the body is not a change",
        )
        .await;
        emit_signal(
            server,
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                "org.freedesktop.WiFi",
                &HashMap::<String, OwnedValue>::new(),
                &Vec::<String>::new(),
            ),
        )
        .await;
        emit_signal(
            server,
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                "org.freedesktop.NetworkManager",
                &HashMap::<String, OwnedValue>::new(),
                &Vec::<String>::new(),
            ),
        )
        .await;
        emit_signal(
            server,
            "/org/freedesktop/NetworkManager/ActiveConnection/9",
            "org.freedesktop.NetworkManager.Connection.Active",
            "StateChanged",
            &"the body is not a state",
        )
        .await;
        emit_signal(
            server,
            "/org/freedesktop/NetworkManager/devices/wifi_0",
            "org.freedesktop.NetworkManager.Connection.Active",
            "StateChanged",
            &(1u32, 0u32),
        )
        .await;
    }

    /// Wait for the forwarder task to stand down, within its bound.
    async fn forwarder_ends(forwarder: tokio::task::JoinHandle<()>) {
        assert!(
            tokio::time::timeout(Duration::from_secs(10), forwarder)
                .await
                .expect("the forwarder ends within its bound")
                .is_ok(),
            "the forwarder task stands"
        );
    }

    /// The signal forwarders break once their event receiver is gone, over
    /// a fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_forwarders_end_when_their_receiver_is_gone() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let (server, _calls, _mode, _deactivated) = serve_fake_nm(&bus).await;

        // The `CheckPermissions` signal lands once, the receiver goes, and
        // the next signal breaks the loop.
        let check_permissions = || {
            emit_signal(
                &server,
                "/org/freedesktop/NetworkManager",
                "org.freedesktop.NetworkManager",
                "CheckPermissions",
                &(),
            )
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let forwarder = tokio::spawn(super::forward_check_permissions(
            bus.connect().await,
            tx.clone(),
        ));
        event_after_rx(&mut rx, &check_permissions, |event| {
            matches!(event, NmEvent::CheckPermissions)
        })
        .await;
        drop(rx);
        check_permissions().await;
        forwarder_ends(forwarder).await;

        // The same over the wireless forwarder and `PropertiesChanged`.
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let forwarder = tokio::spawn(super::forward_wireless(bus.connect().await, tx.clone()));
        let on_properties = wireless_change(true);
        let off_properties = wireless_change(false);
        let invalidated: Vec<String> = Vec::new();
        let wireless_on = (
            "org.freedesktop.NetworkManager",
            &on_properties,
            &invalidated,
        );
        let wireless_off = (
            "org.freedesktop.NetworkManager",
            &off_properties,
            &invalidated,
        );
        event_after_rx(
            &mut rx,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &wireless_on,
                )
            },
            |event| matches!(event, NmEvent::WirelessEnabled(_)),
        )
        .await;
        drop(rx);
        emit_signal(
            &server,
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &wireless_off,
        )
        .await;
        forwarder_ends(forwarder).await;

        // The same over the active states forwarder and `StateChanged`.
        let conn = bus.connect().await;
        let states = super::active_states(&conn)
            .await
            .expect("the state subscription stands");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let forwarder = tokio::spawn(super::forward_active_states(states, tx.clone()));
        event_after_rx(
            &mut rx,
            || {
                emit_signal(
                    &server,
                    "/org/freedesktop/NetworkManager/ActiveConnection/8",
                    "org.freedesktop.NetworkManager.Connection.Active",
                    "StateChanged",
                    &(2u32, 0u32),
                )
            },
            |event| matches!(event, NmEvent::StateChanged { .. }),
        )
        .await;
        drop(rx);
        emit_signal(
            &server,
            "/org/freedesktop/NetworkManager/ActiveConnection/8",
            "org.freedesktop.NetworkManager.Connection.Active",
            "StateChanged",
            &(3u32, 0u32),
        )
        .await;
        forwarder_ends(forwarder).await;
    }

    /// The event stream ends once the bus is closed, over a fake
    /// `NetworkManager` on a private bus.
    #[tokio::test]
    async fn the_events_end_when_the_bus_is_closed() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let _server = serve_fake_nm(&bus).await.0;
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");

        drop(bus);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let ended = loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break false;
            }
            match tokio::time::timeout(left, io.next_event()).await {
                Ok(None) => break true,
                Err(_) => break false,
                Ok(Some(_)) => {}
            }
        };
        assert!(ended, "the events did not end within their bound");
    }

    /// A slow `AddAndActivateConnection2` is the timeout's failure, over a
    /// slow fake `NetworkManager` on a private bus.
    #[tokio::test]
    async fn a_slow_activation_times_out_on_the_call_bound() {
        let bus = crate::linux::test_bus::PrivateBus::start();
        let _server = zbus::connection::Builder::address(bus.address.as_str())
            .expect("the bus address")
            .name("org.freedesktop.NetworkManager")
            .expect("the service name")
            .serve_at("/org/freedesktop/NetworkManager", SlowNm)
            .expect("the slow manager")
            .build()
            .await
            .expect("the slow manager service");
        let io = ZbusNm::new_with_connection(bus.connect().await)
            .await
            .expect("the network manager client");
        let err = io
            .add_and_activate(&AddRequest::Host {
                device: WIFI_DEVICE.to_owned(),
                band: Band::Five,
                ssid: "connetto-1a2b".into(),
                passphrase: "supersecret123".into(),
            })
            .await
            .expect_err("the slow answer must time out");
        assert!(
            matches!(&err, AddError::Failed(text) if text.contains("timed out")),
            "the failure is the timeout, {err:?}"
        );
    }

    #[test]
    fn the_login_name_falls_back_to_the_numeric_uid() {
        let uid = nix::unistd::Uid::from_raw(1000);
        let user = nix::unistd::User {
            name: "luca".to_owned(),
            passwd: std::ffi::CString::new("").expect("the empty password stands"),
            uid,
            gid: nix::unistd::Gid::from_raw(1000),
            dir: std::path::PathBuf::new(),
            gecos: std::ffi::CString::new("").expect("the empty gecos stands"),
            shell: std::path::PathBuf::new(),
        };
        assert_eq!(super::login_name(uid, Ok(Some(user))), "luca");
        assert_eq!(
            super::login_name(uid, Ok(None)),
            "1000",
            "the nameless uid names itself"
        );
        assert_eq!(
            super::login_name(uid, Err(nix::Error::EACCES)),
            "1000",
            "the refused lookup names the uid"
        );
    }

    #[test]
    fn a_denial_outside_a_method_error_reads_the_error_text() {
        assert!(
            super::is_permission_denied(&zbus::Error::Failure(
                "org.freedesktop.DBus.Error.AccessDenied: no access".to_owned(),
            )),
            "the denial in the text is the denial"
        );
        assert!(
            !super::is_permission_denied(&zbus::Error::Failure("another failure".to_owned(),)),
            "the other failure is not the denial"
        );
    }

    #[test]
    fn a_dbus_failure_maps_to_the_io_failure() {
        let err = super::dbus_error(zbus::Error::Failure("the bus went away".to_owned()));
        assert!(
            matches!(&err, NmIoError::Failed(text) if text.contains("the bus went away")),
            "the failure keeps the reason, {err:?}"
        );
    }

    const NEW_PROBE_NAME: &str = "linux::nm::tests::new_reports_an_unreachable_system_bus";

    /// The constructor reports an unreachable system bus. The `zbus`
    /// system bus address reads the process's environment, so the
    /// scenario runs in a re-executed child with the address pointed at
    /// an absent socket, the child's environment the only one changed.
    #[tokio::test]
    async fn new_reports_an_unreachable_system_bus() {
        if std::env::var_os("CONNETTO_NM_NEW_PROBE").is_some() {
            let err = ZbusNm::new()
                .await
                .err()
                .expect("the system bus is unreachable");
            assert!(
                matches!(err, NmIoError::Failed(_)),
                "the failure is the failed reason, {err:?}"
            );
            return;
        }
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", NEW_PROBE_NAME])
                .env("CONNETTO_NM_NEW_PROBE", "1")
                .env(
                    "DBUS_SYSTEM_BUS_ADDRESS",
                    "unix:path=/run/connetto-proof/absent-socket",
                )
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }
}
