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

/// The login the connection is restricted to, the process's real uid and
/// its passwd name, the `USER` environment never read.
fn login() -> String {
    // The bus authenticates the process's real uid, so the profile stands
    // the caller's identity.
    let status = std::fs::read_to_string("/proc/self/status").ok();
    let Some(uid) = status.as_deref().and_then(real_uid_of) else {
        // The uid is unreadable, so the profile names no login and the
        // activation fails cleanly.
        tracing::warn!("the process's uid is unreadable, the profile names no login");
        return "unknown".to_owned();
    };
    let passwd = std::fs::read_to_string("/etc/passwd").ok();
    if let Some(name) = passwd.as_deref().and_then(|text| name_of_uid(text, uid)) {
        return name;
    }
    tracing::warn!(%uid, "the uid has no passwd name, the profile names the uid");
    uid.to_string()
}

/// The status text's `Uid:` field, the real uid.
fn real_uid_of(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_whitespace().next())
        .and_then(|uid| uid.parse::<u32>().ok())
}

/// The passwd text's line for the uid, the name field.
fn name_of_uid(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.splitn(4, ':');
        let name = fields.next()?;
        fields.next()?;
        let uid_field = fields.next()?;
        (uid_field == uid.to_string()).then(|| name.to_owned())
    })
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
        AddRequest, Band, Ipv4Standing, NmEvent, NmIoError, Security, WIRELESS, WIRELESS_SECURITY,
        WifiDevice, ZbusNm, first_router, host_settings, join_settings, options, pick_gateway,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use zbus::zvariant::{OwnedValue, Value};

    type Group = HashMap<String, Value<'static>>;

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

    #[test]
    fn the_status_uid_field_parses() {
        let status = "Name:\tnm\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(super::real_uid_of(status), Some(1000));
        assert_eq!(
            super::real_uid_of("Name:\tnm\nGid:\t1000\t1000\t1000\t1000\n"),
            None
        );
    }

    #[test]
    fn the_passwd_name_stands_the_uid_line() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nluca:x:1000:1000:Luca:/home/luca:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
        assert_eq!(super::name_of_uid(passwd, 0), Some("root".to_owned()));
        assert_eq!(super::name_of_uid(passwd, 1000), Some("luca".to_owned()));
        assert_eq!(super::name_of_uid(passwd, 1234), None);
    }

    #[test]
    fn the_profile_names_the_process_identity() {
        let status = std::fs::read_to_string("/proc/self/status").expect("the status stands");
        let uid = super::real_uid_of(&status).expect("the uid field stands");
        let passwd = std::fs::read_to_string("/etc/passwd").expect("the passwd stands");
        let expected = super::name_of_uid(&passwd, uid).unwrap_or_else(|| uid.to_string());
        assert_eq!(super::login(), expected);
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
}
