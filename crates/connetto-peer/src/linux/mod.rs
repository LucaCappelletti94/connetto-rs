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

#[cfg(test)]
mod test_bus {
    /// A private session bus, stopped on drop.
    pub struct PrivateBus {
        daemon: std::process::Child,
        pub address: String,
    }

    impl PrivateBus {
        /// Start the daemon, the missing binary a clear test failure.
        pub fn start() -> Self {
            use std::io::BufRead as _;
            let mut daemon = std::process::Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap_or_else(|err| {
                    panic!("the private-bus tests need a dbus-daemon on the PATH: {err}")
                });
            let mut address = String::new();
            std::io::BufReader::new(daemon.stdout.take().expect("the daemon's stdout"))
                .read_line(&mut address)
                .expect("the daemon's address");
            Self {
                daemon,
                address: address.trim().to_owned(),
            }
        }

        /// Connect a client to the private bus.
        pub async fn connect(&self) -> zbus::Connection {
            zbus::connection::Builder::address(self.address.as_str())
                .expect("the bus address")
                .build()
                .await
                .expect("connect to the private bus")
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.daemon.kill();
            let _ = self.daemon.wait();
        }
    }
}
