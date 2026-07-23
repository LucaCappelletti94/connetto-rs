//! Subscription registration, cancellation, and snapshot delimiters.
//!
//! The subscription language is a SQLite-dialect `SELECT`, the same dialect the
//! client runs against its local replica, with `?` placeholders accompanied by
//! typed [`BindValue`]s in placeholder order. The server substitutes the binds
//! into the parsed statement, reverse-translates it to Postgres, and hands that
//! to `subql` for parsing (Q4.1). Priority tiers control delivery ordering
//! (Q4.3): tier 0 completes before tier 1 begins. Row-level and aggregate
//! subscriptions share this envelope. The server classifies each subscription
//! from its SQL, so the envelope carries no kind discriminant.

use serde::{Deserialize, Serialize};

use crate::cursor::Cursor;

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

/// One value bound to a `?` placeholder in a subscription query, in placeholder
/// order. The five SQLite storage classes, which is exactly what a diesel query
/// rendered against the client's replica can produce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BindValue {
    /// SQL `NULL`.
    Null,
    /// An `INTEGER` value.
    Integer(i64),
    /// A `REAL` value.
    Real(f64),
    /// A `TEXT` value.
    Text(String),
    /// A `BLOB` value.
    Blob(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// The observation contract handed to `subql` at registration time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionSpec {
    /// Delivery priority tier.
    #[serde(default)]
    pub priority: SubscriptionPriority,
    /// Full `SELECT` in the client's SQLite dialect, either a row projection or
    /// a single scalar aggregate. The server reverse-translates it to Postgres,
    /// classifies it from the SQL, and rejects untranslatable or unsupported
    /// syntax at registration time.
    pub query: String,
    /// Values for the `?` placeholders in `query`, in placeholder order. Empty
    /// when the query has no placeholders.
    #[serde(default)]
    pub binds: Vec<BindValue>,
}

impl SubscriptionSpec {
    /// Build a subscription with the default priority. The server decides from
    /// the query whether it is a row or an aggregate subscription.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            priority: SubscriptionPriority::default(),
            query: query.into(),
            binds: Vec::new(),
        }
    }

    /// Override the priority tier.
    #[must_use]
    pub fn with_priority(mut self, priority: SubscriptionPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Attach the values for the query's `?` placeholders, in placeholder order.
    #[must_use]
    pub fn with_binds(mut self, binds: Vec<BindValue>) -> Self {
        self.binds = binds;
        self
    }
}

/// Client registers a new subscription.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    fn spec_new_defaults_priority_and_keeps_query() {
        let spec = SubscriptionSpec::new("SELECT * FROM orders WHERE user_id = 1");
        assert_eq!(spec.query, "SELECT * FROM orders WHERE user_id = 1");
        assert_eq!(spec.priority, SubscriptionPriority::default());
    }

    #[test]
    fn spec_with_priority_overrides() {
        let spec = SubscriptionSpec::new("SELECT COUNT(*) FROM orders")
            .with_priority(SubscriptionPriority::HIGHEST);
        assert_eq!(spec.priority, SubscriptionPriority::HIGHEST);
    }
}
