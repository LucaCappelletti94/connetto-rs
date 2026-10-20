//! How far two machines' wall clocks may disagree when one checks a deadline
//! the other wrote. Chapter 21 holds the rule each timer follows.

use core::time::Duration;

/// The skew allowed when a device or peer clock is on either side of a check,
/// such as a certificate window or a revocation list's reach.
pub const DEVICE_SKEW: Duration = Duration::from_mins(5);

/// The skew allowed when deployment servers both sign and check, such as an
/// access token's `exp` or a content ticket's expiry.
pub const SERVER_SKEW: Duration = Duration::from_secs(60);
