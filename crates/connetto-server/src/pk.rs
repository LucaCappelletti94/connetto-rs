//! Canonical primary-key codec.
//!
//! A subscription row's primary key is identified the same way whether it
//! arrives on the read path (a CDC event's `Value<Postgres>` cells) or the
//! write path (an uploaded sqlite-diff row image). Both encode the key columns,
//! in key order, into one self-describing byte string that authorization
//! policies treat as opaque and that [`decode`] turns back into typed values.
//!
//! The canonical value type is subql's own [`Value<Postgres>`], the richest of
//! the value shapes and already what the read path produces. The write path's
//! sqlite-diff [`WireValue`] maps into it, so a key uploaded by a client and the
//! same key observed on replication encode to identical bytes. Encoding is
//! `MessagePack` over `Vec<Value<Postgres>>`.

use sqlite_diff_rs::Value as WireValue;
use subql::backend::{Postgres, Value};

/// The sqlite-diff value shape carried by an uploaded row image.
type Wire = WireValue<String, Vec<u8>>;

/// Map one uploaded sqlite-diff cell to the canonical [`Value<Postgres>`].
///
/// sqlite-diff carries only SQLite's four storage classes plus NULL, so the
/// mapping is total and lossless: integers, reals, text, and blobs become the
/// corresponding Postgres scalar, and NULL stays NULL.
fn from_wire(value: &Wire) -> Value<Postgres> {
    match value {
        WireValue::Null => Value::Null,
        WireValue::Integer(int) => Value::Int(*int),
        WireValue::Real(real) => Value::Float(*real),
        WireValue::Text(text) => Value::String(text.clone()),
        WireValue::Blob(blob) => Value::Bytes(blob.clone()),
    }
}

/// Encode primary-key values observed on the read path.
///
/// Serialization of `Value<Postgres>` into an in-memory buffer cannot fail, so
/// this returns the bytes directly.
#[must_use]
pub fn encode(values: &[Value<Postgres>]) -> Vec<u8> {
    rmp_serde::to_vec(values).expect("encoding Vec<Value<Postgres>> into a Vec cannot fail")
}

/// Encode primary-key values taken from an uploaded row image.
///
/// The sqlite-diff cells map to canonical values before encoding, so the result
/// matches [`encode`] for the same logical key.
#[must_use]
pub fn encode_wire(values: &[Wire]) -> Vec<u8> {
    let mapped: Vec<Value<Postgres>> = values.iter().map(from_wire).collect();
    encode(&mapped)
}

/// Decode primary-key bytes produced by [`encode`] or [`encode_wire`].
///
/// # Errors
///
/// Returns the `MessagePack` decode error when `bytes` is not a valid encoding of
/// `Vec<Value<Postgres>>`.
pub fn decode(bytes: &[u8]) -> Result<Vec<Value<Postgres>>, rmp_serde::decode::Error> {
    rmp_serde::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_composite_key() {
        let key = vec![
            Value::<Postgres>::Int(42),
            Value::<Postgres>::String("tenant-a".to_owned()),
        ];
        let decoded = decode(&encode(&key)).expect("decode");
        assert_eq!(decoded, key);
    }

    #[test]
    fn wire_and_read_paths_agree() {
        let wire = vec![Wire::Integer(7), Wire::Text("x".to_owned())];
        let read = vec![
            Value::<Postgres>::Int(7),
            Value::<Postgres>::String("x".to_owned()),
        ];
        assert_eq!(encode_wire(&wire), encode(&read));
    }

    #[test]
    fn preserves_blob_and_null() {
        let wire = vec![Wire::Blob(vec![0, 1, 2, 255]), Wire::Null];
        let decoded = decode(&encode_wire(&wire)).expect("decode");
        assert_eq!(
            decoded,
            vec![
                Value::<Postgres>::Bytes(vec![0, 1, 2, 255]),
                Value::<Postgres>::Null
            ]
        );
    }
}
