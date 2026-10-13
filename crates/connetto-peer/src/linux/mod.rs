//! The Linux platform I/O the peer link's hotspot and Bluetooth backends
//! drive (R76 slice 9b).
//!
//! The `NetworkManager` calls over the system bus and the `BlueZ` peripheral
//! daemon sit behind two small I/O traits, so the backends' decision logic
//! runs against a fake in its proofs. The real implementations reach the
//! daemons with one D-Bus connection each, bounded on the monotonic clock.

#[cfg(target_os = "linux")]
mod bluez;
#[cfg(target_os = "linux")]
mod nm;

#[cfg(target_os = "linux")]
pub use bluez::{AdapterStanding, BluerBluez, BluezError, BluezIo, DeviceKey, PeripheralAnswer};
#[cfg(target_os = "linux")]
pub use nm::{
    AddError, AddRequest, Band, CAP_ACCESS_POINT, CAP_FREQ_5GHZ, Ipv4Standing, NETWORK_CONTROL,
    NmEvent, NmIo, NmIoError, SETTINGS_MODIFY_OWN, STATE_ACTIVATED, STATE_DEACTIVATED,
    STATE_DEACTIVATING, Security, WIFI_SHARE_PROTECTED, WifiDevice, ZbusNm,
};
