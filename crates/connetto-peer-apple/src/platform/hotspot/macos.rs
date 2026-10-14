//! The macOS side of the system's join, over `CoreWLAN`'s directed scan and
//! its association (R76).

use std::sync::LazyLock;
use std::thread;

use objc2::rc::Retained;
use objc2_core_wlan::{CWInterface, CWNetwork, CWWiFiClient};
use objc2_foundation::{NSError, NSString};
use parking_lot::Mutex;

use crate::Error;
use crate::hotspot::{Joining, Security};

/// What the system's join stands at.
#[derive(Default)]
struct Standing {
    /// The system's answer to the last join, once it answers.
    completion: Option<Result<Joining, Error>>,
    /// The generation the standing stands at, one per join and leave.
    generation: u64,
    /// The generation a leave stands to unwind, whose worker's late
    /// association gets disassociated.
    unwind_generation: Option<u64>,
}

static STANDING: LazyLock<Mutex<Standing>> = LazyLock::new(|| Mutex::new(Standing::default()));

/// Ask the system to join a network.
///
/// A worker thread runs the directed scan for the SSID and the association,
/// and records its answer in the standing, read with [`completion`]. A
/// `leave` standing in between drops the worker's answer, and a worker whose
/// association stands late to it gets disassociated (R76).
pub(crate) fn join(ssid: &str, passphrase: &str, _security: Security) -> Result<(), Error> {
    // The handle is not `Send`, so the worker re-reads it. This read reports
    // the absence to the caller at call time.
    interface()?;
    let generation = {
        let mut standing = STANDING.lock();
        standing.completion = None;
        standing.unwind_generation = None;
        standing.generation += 1;
        standing.generation
    };
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
    let mut standing = STANDING.lock();
    if matches!(standing.completion, Some(Ok(_))) {
        // An associated interface leaves its network.
        standing.completion = None;
        if let Ok(interface) = interface() {
            // SAFETY: the platform's disassociate answers nothing to return.
            unsafe { interface.disassociate() };
        }
    } else if standing.completion.is_none() && standing.generation > 0 {
        // An association still running has its answer dropped, and its late
        // join gets unwound.
        standing.unwind_generation = Some(standing.generation);
        standing.generation += 1;
    }
    Ok(())
}

/// The Mac's Wi-Fi interface, read by its BSD name.
fn interface() -> Result<Retained<CWInterface>, Error> {
    // SAFETY: the class method answers the shared client the platform owns
    // for the process.
    let client = unsafe { CWWiFiClient::sharedWiFiClient() };
    let name = NSString::from_str(super::WIFI.to_str().unwrap_or("en0"));
    // SAFETY: the name is a valid string the platform only reads, and the
    // call answers the interface the caller owns.
    unsafe { client.interfaceWithName(Some(&name)) }
        .ok_or_else(|| Error::Missing("the Wi-Fi interface".to_owned()))
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
    // SAFETY: the name is a valid string the platform only reads, and the
    // call answers the scan's networks or an error it owns.
    let scan = unsafe { interface.scanForNetworksWithName_error(Some(&name)) };
    let networks = match scan {
        Ok(networks) => networks,
        Err(error) => {
            answer(generation, Err(refuse(&error)));
            return;
        }
    };
    // A set is unordered, so read it as an array and walk the members,
    // keeping the strongest answer by RSSI.
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
    // The scan found nothing of the name, so the offer stands missing.
    let Some((network, _)) = strongest else {
        answer(
            generation,
            Err(Error::Missing("the offered network".to_owned())),
        );
        return;
    };
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
            let mut standing = STANDING.lock();
            if standing.generation == generation {
                standing.completion = Some(Ok(Joining::Joined));
            } else if standing.unwind_generation == Some(generation) {
                // The leave stood in after the scan, so the late join gets
                // unwound.
                standing.unwind_generation = None;
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
