//! The iOS side of the system's join, over the Network Extension's shared
//! manager (R76).

use std::sync::LazyLock;

use block2::RcBlock;
use objc2::{AnyThread, msg_send, rc::Retained, sel};
use objc2_foundation::{NSError, NSObjectProtocol, NSString};
use objc2_network_extension::{NEHotspotConfiguration, NEHotspotConfigurationManager};
use parking_lot::Mutex;

use crate::hotspot::{Joining, Security};
use crate::{Error, join_already_associated};

/// What the system's join stands at.
#[derive(Default)]
struct Standing {
    /// The system's answer to the last join, once it answers.
    completion: Option<Result<Joining, Error>>,
}

static STANDING: LazyLock<Mutex<Standing>> = LazyLock::new(|| Mutex::new(Standing::default()));

/// Ask the system to join a network.
pub(crate) fn join(ssid: &str, passphrase: &str, security: Security) -> Result<(), Error> {
    let configuration = configuration(ssid, passphrase, security)?;
    // SAFETY: the framework answers the process-wide manager with nothing
    // else to return.
    let manager = unsafe { NEHotspotConfigurationManager::sharedManager() };
    // The answer is cleared before the join, since the system may answer
    // before the call returns.
    STANDING.lock().completion = None;
    let handler: RcBlock<dyn Fn(*mut NSError)> = RcBlock::new(move |error: *mut NSError| {
        // SAFETY: the system passes either null or an error it owns for the
        // duration of this call, and the error is copied before the call
        // returns.
        let error = unsafe { error.as_ref() };
        let answer = match error {
            // The device already stands on the network, so the join's goal
            // stands reached.
            Some(error) if join_already_associated(&error.domain().to_string(), error.code()) => {
                Ok(Joining::AlreadyThere)
            }
            Some(error) => Err(Error::Apple {
                domain: error.domain().to_string(),
                code: error.code(),
                description: error.localizedDescription().to_string(),
            }),
            None => Ok(Joining::Joined),
        };
        STANDING.lock().completion = Some(answer);
    });
    // SAFETY: the system copies the block before returning, so dropping ours
    // after the call is sound.
    unsafe {
        manager.applyConfiguration_completionHandler(&configuration, Some(&handler));
    }
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
pub(crate) fn leave(ssid: &str) -> Result<(), Error> {
    // SAFETY: the framework answers the process-wide manager with nothing
    // else to return.
    let manager = unsafe { NEHotspotConfigurationManager::sharedManager() };
    // SAFETY: the release is synchronous and answers no error.
    unsafe { manager.removeConfigurationForSSID(&NSString::from_str(ssid)) };
    STANDING.lock().completion = None;
    Ok(())
}

/// The system's join configuration, WPA2 typed and WPA3 by its raw selector.
fn configuration(
    ssid: &str,
    passphrase: &str,
    security: Security,
) -> Result<Retained<NEHotspotConfiguration>, Error> {
    let ssid = NSString::from_str(ssid);
    let passphrase = NSString::from_str(passphrase);
    let configuration = match security {
        Security::Wpa2 => {
            // SAFETY: the init answers a configuration the caller owns, from
            // valid strings the platform copies.
            unsafe {
                NEHotspotConfiguration::initWithSSID_passphrase_isWEP(
                    NEHotspotConfiguration::alloc(),
                    &ssid,
                    &passphrase,
                    false,
                )
            }
        }
        Security::Wpa3 => {
            // SAFETY: the init answers a configuration the caller owns, from
            // a valid string the platform copies.
            let configuration = unsafe {
                NEHotspotConfiguration::initWithSSID(NEHotspotConfiguration::alloc(), &ssid)
            };
            set_wpa3_passphrase(&configuration, &passphrase)?;
            configuration
        }
    };
    // A Personal Hotspot shows its name only while its pane is open, so the
    // system asks for the network by name rather than waiting to see it.
    // SAFETY: the setter takes a plain flag on a configuration the caller
    // owns.
    unsafe { configuration.setHidden(true) };
    Ok(configuration)
}

/// The WPA3 personal passphrase setter, which the typed bindings keep raw.
///
/// The platform's `NEHotspotConfiguration` answers the setter as a raw
/// selector, so this asks for it and answers `Missing` where the platform
/// does not (R76).
fn set_wpa3_passphrase(
    configuration: &NEHotspotConfiguration,
    passphrase: &NSString,
) -> Result<(), Error> {
    let selector = sel!(setWPA3PersonalPassphrase:);
    if configuration.respondsToSelector(selector) {
        // SAFETY: the platform answers the setter, and the passphrase is a
        // valid string the platform copies.
        let _answer: () =
            unsafe { msg_send![configuration, setWPA3PersonalPassphrase: passphrase] };
        Ok(())
    } else {
        Err(Error::Missing("setWPA3PersonalPassphrase:".to_owned()))
    }
}
