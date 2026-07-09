//! Aggregate subscription result delivery.
//!
//! `subql` maintains aggregate accumulators server-side (Q5.1). When a group's
//! value changes, or when a re-execution replaces the result set, the server
//! delivers the result as a JSON envelope keyed by opaque group bytes (Q5.7).
//! JSON is used only here (and in [`crate::messages::mutation::MutationConflict`])
//! because the shape is not known at compile time. Q2.1 reserves JSON for
//! shape-unknown data.

use serde::{Deserialize, Serialize};

/// Update for one aggregate subscription group.
///
/// The `group_key` bytes are opaque to connetto. `subql` chooses the encoding
/// and the client's local aggregate table uses them verbatim as a primary key
/// (see the `_connetto_aggregates` schema in Q5.7). `None` means "single-group"
/// aggregate: no `GROUP BY`, so there is exactly one row to maintain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateUpdate {
    /// Which subscription this update belongs to.
    pub sub_id: String,
    /// Opaque group key, or `None` for a single-group aggregate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_bytes_option")]
    pub group_key: Option<Vec<u8>>,
    /// JSON-encoded result. Deserialised by the client into its
    /// application-defined result struct.
    pub result_json: String,
    /// Whether this update replaces the entire result set (true) or upserts a
    /// single group (false). Full replacement is produced by re-execution.
    /// Per-group upserts are produced by the IVM fast path (Q5.6).
    #[serde(default)]
    pub is_full_result: bool,
}

// serde_bytes support for `Option<Vec<u8>>`. serde_bytes ships helpers only for
// the direct `Vec<u8>` and `[u8]` cases, so provide a light wrapper for the
// optional field so it still rides as a `MessagePack` `bin` on the wire.
#[allow(clippy::ref_option)] // serde `with = "..."` calls serialize(&self, ..).
mod serde_bytes_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteBuf;

    pub(super) fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serde_bytes::Bytes::new(bytes).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<ByteBuf>::deserialize(deserializer).map(|opt| opt.map(ByteBuf::into_vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_group_default_is_delta() {
        let u = AggregateUpdate {
            sub_id: "s1".into(),
            group_key: None,
            result_json: "{\"count\":10}".into(),
            is_full_result: false,
        };
        assert!(!u.is_full_result);
        assert!(u.group_key.is_none());
    }

    #[test]
    fn grouped_update_carries_key() {
        let u = AggregateUpdate {
            sub_id: "s2".into(),
            group_key: Some(b"region=eu".to_vec()),
            result_json: "{\"count\":3}".into(),
            is_full_result: false,
        };
        assert_eq!(u.group_key.as_deref(), Some(&b"region=eu"[..]));
    }
}
