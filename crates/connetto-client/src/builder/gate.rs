//! The away-and-return gate a durable build can carry.

use core::time::Duration;

/// Whether a durable build locks the protected secret on away, and how a
/// return is re-checked.
///
/// The default is on with no re-check, so a build locks on the first away
/// and re-checks once when it returns, then never again. `with_recheck`
/// tightens the return side, `None` re-checking once per launch and
/// `Some(DURATION)` re-checking a return whose time away exceeded the
/// bound.
///
/// The away input is not set here. It is fed by the application through
/// [`ConnettoClient::away`](crate::ConnettoClient::away) and
/// [`ConnettoClient::back`](crate::ConnettoClient::back), which the
/// dioxus-desktop hook feeds from the window's focus state and the browser
/// worker feeds from its tabs' visibility.
#[derive(Clone, Copy, Debug)]
pub struct Gate {
    on: bool,
    recheck: Option<Duration>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            on: true,
            recheck: None,
        }
    }
}

impl Gate {
    /// A build with no lock on away.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            on: false,
            recheck: None,
        }
    }

    /// The return re-check grace. `None` re-checks once per launch and
    /// `Some(ZERO)` re-checks every return.
    #[must_use]
    pub const fn with_recheck(mut self, recheck: Option<Duration>) -> Self {
        self.recheck = recheck;
        self
    }

    /// Whether the build locks the protected secret on away.
    #[must_use]
    pub const fn on(&self) -> bool {
        self.on
    }

    /// The return re-check grace.
    #[must_use]
    pub const fn recheck(&self) -> Option<Duration> {
        self.recheck
    }
}
