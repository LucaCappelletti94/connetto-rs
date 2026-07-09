//! Subscription registration, cancellation, and snapshot delimiters.
//!
//! The subscription language is SQL `WHERE` clause text handed to `subql` for
//! parsing (Q4.1). Priority tiers control delivery ordering (Q4.3): tier 0
//! completes before tier 1 begins. Row-level and aggregate subscriptions share
//! this envelope. The `kind` discriminant selects which materializer path runs
//! server-side.

use serde::{Deserialize, Serialize};

use crate::cursor::Cursor;

/// Subscription flavour. Row-level subscriptions produce `SQLite` patchsets,
/// aggregate subscriptions produce JSON result envelopes (Q5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionKind {
    /// Row-level `SELECT`. Server pushes patchsets against the client's local mirror.
    Row,
    /// Aggregate. Server pushes `AggregateUpdate` values keyed by group.
    Aggregate,
}

/// Delivery priority tier. Lower values are delivered first.
///
/// Clamped to `0..=3` per Q4.3. Tier 0 is reserved for immediately visible UX,
/// tier 3 for background data the user tolerates catching up on. Within a tier,
/// deliveries interleave freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriptionPriority(u8);

impl SubscriptionPriority {
    /// Highest priority (delivered first).
    pub const HIGHEST: Self = Self(0);
    /// Lowest priority (delivered last).
    pub const LOWEST: Self = Self(3);

    /// Build a priority, clamping the raw byte into the valid `0..=3` range.
    #[inline]
    pub const fn new(raw: u8) -> Self {
        Self(if raw > 3 { 3 } else { raw })
    }

    /// Raw priority byte.
    #[inline]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for SubscriptionPriority {
    fn default() -> Self {
        // Default sits in the middle of the range: not blocking UX-critical
        // deliveries, not deferred to the background.
        Self(1)
    }
}

/// The observation contract handed to `subql` at registration time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionSpec {
    /// Which materializer path this subscription rides.
    pub kind: SubscriptionKind,
    /// Delivery priority tier.
    #[serde(default)]
    pub priority: SubscriptionPriority,
    /// SQL text handed to `subql`. For [`SubscriptionKind::Row`] this is a full
    /// `SELECT` statement. For [`SubscriptionKind::Aggregate`] this is a full
    /// aggregate query. `subql` rejects unsupported syntax at registration time.
    pub query: String,
}

impl SubscriptionSpec {
    /// Build a row-level subscription with the default priority.
    pub fn row(query: impl Into<String>) -> Self {
        Self {
            kind: SubscriptionKind::Row,
            priority: SubscriptionPriority::default(),
            query: query.into(),
        }
    }

    /// Build an aggregate subscription with the default priority.
    pub fn aggregate(query: impl Into<String>) -> Self {
        Self {
            kind: SubscriptionKind::Aggregate,
            priority: SubscriptionPriority::default(),
            query: query.into(),
        }
    }

    /// Override the priority tier.
    #[must_use]
    pub fn with_priority(mut self, priority: SubscriptionPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// Client registers a new subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscribe {
    /// Client-chosen id, unique per session. Correlates snapshot and update messages.
    pub sub_id: String,
    /// What the client wants to observe.
    pub spec: SubscriptionSpec,
}

/// Client cancels a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unsubscribe {
    /// Id of the subscription being cancelled. Server tolerates unknown ids
    /// silently (idempotent).
    pub sub_id: String,
}

/// Server marks the start of an initial snapshot for a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBegin {
    /// Subscription this snapshot belongs to.
    pub sub_id: String,
    /// Tier that scheduled this snapshot. Informational, matches the value
    /// registered in the spec.
    #[serde(default)]
    pub priority: SubscriptionPriority,
}

/// Server marks the end of an initial snapshot and pins the resume point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnd {
    /// Subscription this snapshot belongs to.
    pub sub_id: String,
    /// Cursor at which the snapshot was read. Row updates with a strictly
    /// greater cursor apply on top. Updates at or below this point are already
    /// reflected in the snapshot and are dropped by the client.
    pub cursor: Cursor,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_clamps_to_lowest() {
        assert_eq!(SubscriptionPriority::new(9).get(), 3);
        assert_eq!(SubscriptionPriority::new(3).get(), 3);
        assert_eq!(SubscriptionPriority::new(0).get(), 0);
    }

    #[test]
    fn priority_default_is_middle() {
        assert_eq!(SubscriptionPriority::default().get(), 1);
    }

    #[test]
    fn priority_ordering_prefers_lower_numbers() {
        assert!(SubscriptionPriority::HIGHEST < SubscriptionPriority::LOWEST);
    }

    #[test]
    fn spec_row_helper_sets_kind() {
        let spec = SubscriptionSpec::row("SELECT * FROM orders WHERE user_id = 1");
        assert_eq!(spec.kind, SubscriptionKind::Row);
    }

    #[test]
    fn spec_aggregate_helper_sets_kind() {
        let spec =
            SubscriptionSpec::aggregate("SELECT region, COUNT(*) FROM orders GROUP BY region");
        assert_eq!(spec.kind, SubscriptionKind::Aggregate);
    }
}
