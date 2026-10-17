//! The macOS side of the system's join, over `CoreWLAN`'s directed scan and
//! its association (R76).

use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2_core_wlan::{CWInterface, CWNetwork, CWWiFiClient};
use objc2_foundation::{NSError, NSString};
use parking_lot::Mutex;

use crate::Error;
use crate::hotspot::{Joining, Security};

/// How long the worker keeps scanning for the offered network. An iPhone's
/// Personal Hotspot answers a directed scan only now and then, even with its
/// settings pane open, and a scan soon after another can fail with
/// `tmpErr` (both measured 2026-10-14), so one empty or failed scan proves
/// nothing.
const SCAN_BOUND: Duration = Duration::from_secs(30);

/// The pause between two scans for the offered network.
const SCAN_PAUSE: Duration = Duration::from_secs(5);

/// What the system's join stands at.
#[derive(Default)]
struct Standing {
    /// The system's answer to the last join, once it answers.
    completion: Option<Result<Joining, Error>>,
    /// The generation the standing stands at, one per join and leave.
    generation: u64,
}

/// What a landed association does.
#[derive(Debug, PartialEq, Eq)]
enum Landed {
    /// Its join still stands, so it answers the join.
    Stands,
    /// A leave or a newer join stood in, so the interface leaves its network.
    Unwind,
}

impl Standing {
    /// A new join, whose worker carries the returned generation.
    fn begin_join(&mut self) -> u64 {
        self.completion = None;
        self.generation += 1;
        self.generation
    }

    /// A leave, `true` when an association stands to disassociate. A worker
    /// still running loses its generation, so its late association unwinds.
    fn leave(&mut self) -> bool {
        // Only an association the join made gets undone, so a network the
        // Mac already stood on stays the user's.
        match self.completion.take() {
            Some(Ok(Joining::Joined)) => return true,
            Some(Ok(Joining::AlreadyThere)) => return false,
            other => self.completion = other,
        }
        if self.completion.is_none() && self.generation > 0 {
            self.generation += 1;
        }
        false
    }

    /// The worker of `generation` associated, as `joined`.
    fn landed(&mut self, generation: u64, joined: Joining) -> Landed {
        if self.generation == generation {
            self.completion = Some(Ok(joined));
            Landed::Stands
        } else {
            Landed::Unwind
        }
    }
}

static STANDING: LazyLock<Mutex<Standing>> = LazyLock::new(|| Mutex::new(Standing::default()));

/// The turn an association holds, so a stale one lands before a newer one
/// runs.
static ASSOCIATION: Mutex<()> = Mutex::new(());

/// Ask the system to join a network.
///
/// A worker thread runs the directed scan for the SSID and the association,
/// and records its answer in the standing, read with [`completion`]. A
/// `leave` or a newer join standing in drops the worker's answer, and its
/// late association gets disassociated (R76).
pub(crate) fn join(ssid: &str, passphrase: &str, _security: Security) -> Result<(), Error> {
    // The handle is not `Send`, so the worker re-reads it. This read reports
    // the absence to the caller at call time.
    interface()?;
    let generation = STANDING.lock().begin_join();
    let ssid = ssid.to_owned();
    let passphrase = passphrase.to_owned();
    thread::spawn(move || {
        worker(generation, &ssid, &passphrase);
    });
    Ok(())
}

/// The system's answer to the last join, once it answers.
pub(crate) fn completion() -> Option<Result<Joining, Error>> {
    STANDING.lock().completion.clone()
}

/// Release the system's standing for a network.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the release is synchronous and answers no error"
)]
pub(crate) fn leave(_ssid: &str) -> Result<(), Error> {
    if STANDING.lock().leave()
        && let Ok(interface) = interface()
    {
        // SAFETY: the platform's disassociate answers nothing to return.
        unsafe { interface.disassociate() };
    }
    Ok(())
}

/// The Mac's default Wi-Fi interface, whatever its BSD name.
fn interface() -> Result<Retained<CWInterface>, Error> {
    // SAFETY: the class method answers the shared client the platform owns
    // for the process.
    let client = unsafe { CWWiFiClient::sharedWiFiClient() };
    // SAFETY: the call answers the default Wi-Fi interface the caller owns,
    // or none.
    unsafe { client.interface() }.ok_or_else(|| Error::Missing("the Wi-Fi interface".to_owned()))
}

/// The BSD name of the Mac's default Wi-Fi interface, which the joined
/// network's address and gateway are read on.
pub(crate) fn wifi_name() -> Option<String> {
    let interface = interface().ok()?;
    // SAFETY: the platform answers the interface's BSD name, or none.
    unsafe { interface.interfaceName() }.map(|name| name.to_string())
}

/// The worker's work, the directed scan for the SSID and its association.
fn worker(generation: u64, ssid: &str, passphrase: &str) {
    // The interface handle is not `Send`, so the worker re-reads it on its
    // own thread.
    let Ok(interface) = interface() else {
        answer(
            generation,
            Err(Error::Missing("the Wi-Fi interface".to_owned())),
        );
        return;
    };
    let name = NSString::from_str(ssid);
    // SAFETY: the platform answers the joined network's name, or none.
    let current = unsafe { interface.ssid() };
    if current.is_some_and(|current| *current == *name) {
        STANDING.lock().landed(generation, Joining::AlreadyThere);
        return;
    }
    let deadline = Instant::now() + SCAN_BOUND;
    let mut failed = None;
    let network = loop {
        match strongest(&interface, &name) {
            Ok(Some(network)) => break network,
            Ok(None) => {}
            Err(error) => failed = Some(error),
        }
        // A newer join or a leave stood in, so the scan stops.
        if STANDING.lock().generation != generation {
            return;
        }
        // No scan within the bound found the name, so the offer stands
        // missing, or the last scan's failure stands.
        if Instant::now() >= deadline {
            let error = failed.unwrap_or_else(|| Error::Missing("the offered network".to_owned()));
            answer(generation, Err(error));
            return;
        }
        thread::sleep(SCAN_PAUSE);
    };
    let _turn = ASSOCIATION.lock();
    // A newer join or a leave stood in after the scan, so the association
    // stands skipped.
    if STANDING.lock().generation != generation {
        return;
    }
    let key = NSString::from_str(passphrase);
    // SAFETY: the network is the scan's, the key is a valid string the
    // platform copies, and the call answers nothing on success.
    let association = unsafe { interface.associateToNetwork_password_error(&network, Some(&key)) };
    match association {
        Ok(()) => {
            if STANDING.lock().landed(generation, Joining::Joined) == Landed::Unwind {
                // SAFETY: the platform's disassociate answers nothing to
                // return.
                unsafe { interface.disassociate() };
            }
        }
        Err(error) => {
            answer(generation, Err(refuse(&error)));
        }
    }
}

/// One directed scan for `name`, answering the strongest network found by
/// RSSI, or `None` when the scan found nothing of the name.
fn strongest(
    interface: &CWInterface,
    name: &NSString,
) -> Result<Option<Retained<CWNetwork>>, Error> {
    // SAFETY: the name is a valid string the platform only reads, and the
    // call answers the scan's networks or an error it owns.
    let networks = unsafe { interface.scanForNetworksWithName_error(Some(name)) }
        .map_err(|error| refuse(&error))?;
    // A set is unordered, so read it as an array and walk the members.
    let members = networks.allObjects();
    let mut strongest: Option<(Retained<CWNetwork>, isize)> = None;
    for index in 0..members.count() {
        let candidate = members.objectAtIndex(index);
        // SAFETY: the platform answers the network's RSSI as a plain
        // integer.
        let rssi = unsafe { candidate.rssiValue() };
        if strongest.as_ref().is_none_or(|(_, best)| rssi > *best) {
            strongest = Some((candidate, rssi));
        }
    }
    Ok(strongest.map(|(network, _)| network))
}

/// Set the standing's answer when the worker's generation still stands.
fn answer(generation: u64, answer: Result<Joining, Error>) {
    let mut standing = STANDING.lock();
    if standing.generation == generation {
        standing.completion = Some(answer);
    }
}

/// A framework error as the crate's.
fn refuse(error: &NSError) -> Error {
    Error::Apple {
        domain: error.domain().to_string(),
        code: error.code(),
        description: error.localizedDescription().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Landed, Standing};
    use crate::hotspot::Joining;

    #[test]
    fn a_current_association_stands_as_the_answer() {
        let mut standing = Standing::default();
        let generation = standing.begin_join();
        assert_eq!(standing.landed(generation, Joining::Joined), Landed::Stands);
        assert!(matches!(standing.completion, Some(Ok(Joining::Joined))));
    }

    #[test]
    fn a_leave_while_associating_unwinds_the_late_association() {
        let mut standing = Standing::default();
        let generation = standing.begin_join();
        assert!(!standing.leave());
        assert_eq!(standing.landed(generation, Joining::Joined), Landed::Unwind);
        assert!(standing.completion.is_none());
    }

    #[test]
    fn a_newer_join_unwinds_the_older_association() {
        let mut standing = Standing::default();
        let older = standing.begin_join();
        let newer = standing.begin_join();
        assert_eq!(standing.landed(older, Joining::Joined), Landed::Unwind);
        assert!(standing.completion.is_none());
        assert_eq!(standing.landed(newer, Joining::Joined), Landed::Stands);
    }

    #[test]
    fn a_leave_after_the_join_disassociates_once() {
        let mut standing = Standing::default();
        let generation = standing.begin_join();
        standing.landed(generation, Joining::Joined);
        assert!(standing.leave());
        assert!(!standing.leave());
    }

    #[test]
    fn a_leave_keeps_a_network_the_mac_already_stood_on() {
        let mut standing = Standing::default();
        let generation = standing.begin_join();
        standing.landed(generation, Joining::AlreadyThere);
        assert!(!standing.leave());
        assert!(standing.completion.is_none());
    }
}
