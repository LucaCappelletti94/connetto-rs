//! The Apple hotspot backend, over the system's join (R76).
//!
//! The join side asks the platform to join the offered network, the Network
//! Extension's on iOS and `CoreWLAN`'s on the Mac, and reads the joined
//! network's address, subnet and gateway from the system. The host side
//! stands on the user's own Personal Hotspot, which the app can only
//! describe, never start, and the Mac refuses it, since it never hosts
//! (R76 decision 1).

use parking_lot::RwLock;

use connetto_peer_apple as apple;
#[cfg(target_os = "ios")]
use connetto_peer_apple::Idiom;

use super::{
    HostStatus, HotspotBackend, HotspotError, HotspotOffer, HotspotSecurity, JoinError, JoinStatus,
};

/// The personal hotspot's lane, the platform's bridge for it.
#[cfg(target_os = "ios")]
const PERSONAL_LANE: &str = "bridge100";

/// The permission a Mac's join names when Location Services access is
/// missing (R76 slice 9c).
#[cfg(target_os = "macos")]
const LOCATION_PERMISSION: &str = "Location Services";

/// The Apple hotspot backend, over `connetto-peer-apple` (R76).
pub(crate) struct AppleHotspotBackend {
    /// The typed personal offer, where the device stands one.
    personal: RwLock<Option<(String, String)>>,
    /// The SSID the join side last asked for, for its release.
    joined_ssid: RwLock<Option<String>>,
    /// The join side has stood available once.
    was_available: RwLock<bool>,
    /// The interface's address when the join was asked, which a joined
    /// network replaces.
    before: RwLock<Option<std::net::Ipv4Addr>>,
    /// The offer the join side last asked for, when, and whether it was
    /// asked once more (R76 decision 28).
    asked: RwLock<Option<(HotspotOffer, tokio::time::Instant, bool)>>,
}

impl AppleHotspotBackend {
    /// Ask the system for the network once more where decision 28's rule
    /// says the first ask landed nowhere.
    fn rejoin_if_due(&self, answered: bool, landed: bool) {
        let mut asked = self.asked.write();
        let Some((offer, at, again)) = asked.as_mut() else {
            return;
        };
        if !super::rejoin_due(answered, landed, at.elapsed(), *again) {
            return;
        }
        *again = true;
        tracing::debug!(ssid = %offer.ssid, "the joined network never landed, asking once more");
        if let Err(err) =
            apple::hotspot::join(&offer.ssid, &offer.passphrase, security(offer.security))
        {
            tracing::debug!(?err, "the second ask for the network was refused");
        }
    }

    /// The backend's new.
    pub(crate) fn new() -> Self {
        Self {
            personal: RwLock::new(None),
            joined_ssid: RwLock::new(None),
            was_available: RwLock::new(false),
            before: RwLock::new(None),
            asked: RwLock::new(None),
        }
    }
}

/// Map the client's security to the platform's.
fn security(security: HotspotSecurity) -> apple::hotspot::Security {
    match security {
        HotspotSecurity::Wpa2 => apple::hotspot::Security::Wpa2,
        HotspotSecurity::Wpa3 => apple::hotspot::Security::Wpa3,
    }
}

/// The platform's join refusal as the client's.
fn join_refusal(error: &apple::Error) -> JoinError {
    match error {
        apple::Error::Unsupported => JoinError::Unsupported,
        // A WPA3 setter absent at run time is a refusal for this join, not
        // for the system's joins as a whole.
        _ => JoinError::Failed,
    }
}

/// Whether the personal hotspot's network has landed.
fn personal_landed() -> bool {
    // The Mac's bridge100 is its virtualisation bridge, and the Mac never
    // hosts, so the landed read stands false there (R76 decision 1).
    #[cfg(target_os = "macos")]
    {
        false
    }
    #[cfg(target_os = "ios")]
    if_addrs::get_if_addrs().is_ok_and(|interfaces| {
        interfaces.iter().any(|interface| {
            interface.name == PERSONAL_LANE && matches!(interface.addr, if_addrs::IfAddr::V4(_))
        })
    })
}

impl HotspotBackend for AppleHotspotBackend {
    fn request_host(&self) -> Result<(), HotspotError> {
        // The app cannot start the platform's hotspot, so the request stands
        // refused (R76 decision 26).
        Err(HotspotError::Unsupported)
    }

    fn stop_host(&self) {
        *self.personal.write() = None;
    }

    fn host_status(&self) -> HostStatus {
        // The personal offer stands on the user's own hotspot, which the
        // machine's landing bound confirms through `personal_landed`.
        HostStatus::Pending
    }

    fn request_join(&self, offer: &HotspotOffer) -> Result<(), JoinError> {
        // macOS refuses to join a network by name for a process without
        // Location Services access, so the join names the permission and
        // the application asks for it (R76 slice 9c).
        #[cfg(target_os = "macos")]
        if apple::hotspot::location_access() != apple::hotspot::LocationAccess::Granted {
            return Err(JoinError::MissingPermission(LOCATION_PERMISSION.to_owned()));
        }
        *self.before.write() = apple::hotspot::joined().map(|joined| joined.address);
        match apple::hotspot::join(&offer.ssid, &offer.passphrase, security(offer.security)) {
            Ok(()) => {
                *self.asked.write() = Some((offer.clone(), tokio::time::Instant::now(), false));
                *self.joined_ssid.write() = Some(offer.ssid.clone());
                *self.was_available.write() = false;
                Ok(())
            }
            Err(error) => {
                tracing::debug!(?error, "the join was refused at once");
                Err(join_refusal(&error))
            }
        }
    }

    fn leave_join(&self) {
        *self.asked.write() = None;
        let ssid = self.joined_ssid.write().take();
        if let Some(ssid) = ssid {
            let _ = apple::hotspot::leave(&ssid);
        }
        *self.was_available.write() = false;
    }

    fn join_status(&self) -> JoinStatus {
        // The network stands joined only once the system answered the join,
        // and either moved the interface off the address it stood on before
        // or found it already on the network, since a failed join leaves the
        // device on its previous network.
        let joining = match apple::hotspot::completion() {
            // The system will not give the network, or the user declined its
            // join dialog (R76).
            Some(Err(error)) => {
                tracing::debug!(%error, "the system refused the join");
                return JoinStatus::Unavailable;
            }
            Some(Ok(joining)) => Some(joining),
            None => None,
        };
        let joined = apple::hotspot::joined();
        let landed = match joining {
            Some(apple::hotspot::Joining::AlreadyThere) => true,
            Some(apple::hotspot::Joining::Joined) => {
                joined.map(|joined| joined.address) != *self.before.read()
            }
            None => false,
        };
        self.rejoin_if_due(joining.is_some(), landed);
        match joined {
            // The network is up once its address and its gateway stand. A
            // missing gateway stays pending for the machine's bound.
            Some(apple::hotspot::Joined {
                address,
                prefix,
                gateway: Some(gateway),
            }) if landed => {
                *self.was_available.write() = true;
                JoinStatus::Available {
                    address,
                    prefix,
                    gateway,
                }
            }
            _ if *self.was_available.read() => {
                tracing::debug!(?joined, "the joined network reads lost");
                JoinStatus::Lost
            }
            _ => JoinStatus::Pending,
        }
    }

    #[cfg(target_os = "macos")]
    fn request_personal_host(&self, _ssid: &str, _passphrase: &str) -> Result<(), HotspotError> {
        // The Mac never hosts (R76 decision 1).
        Err(HotspotError::Unsupported)
    }
    #[cfg(target_os = "ios")]
    fn request_personal_host(&self, ssid: &str, passphrase: &str) -> Result<(), HotspotError> {
        // Only a phone hosts a Personal Hotspot, so anything but a phone
        // stands refused (R76 decision 27).
        if apple::device_idiom() != Idiom::Phone {
            return Err(HotspotError::Incompatible);
        }
        *self.personal.write() = Some((ssid.to_owned(), passphrase.to_owned()));
        Ok(())
    }

    fn personal_landed(&self) -> bool {
        personal_landed()
    }
}
