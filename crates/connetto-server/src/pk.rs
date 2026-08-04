//! Canonical primary-key codec.
//!
//! The oplog stores each retained change under a stable identity for its row,
//! and that identity has to be the same byte string whether the key arrived as
//! a CDC event's `Value<Postgres>` cells or as an uploaded sqlite-diff row
//! image. Both encode the key columns, in key order, into one self-describing
//! byte string. Encoding is `MessagePack` over `Vec<Value<Postgres>>`.

use sqlite_diff_rs::Value as WireValue;
use subql::backend::{Postgres, Value};

/// The sqlite-diff value shape carried by an uploaded row image.
type Wire = WireValue<String, Vec<u8>>;

/// Map one uploaded sqlite-diff cell to the canonical [`Value<Postgres>`].
///
/// sqlite-diff carries only SQLite's four storage classes plus NULL, so the
/// mapping is total and lossless: integers, reals, text, and blobs become the
/// corresponding Postgres scalar, and NULL stays NULL.
pub(crate) fn from_wire(value: &Wire) -> Value<Postgres> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_composite_key_encodes_to_a_stable_string() {
        let key = vec![
            Value::<Postgres>::Int(42),
            Value::<Postgres>::String("tenant-a".to_owned()),
        ];
        assert_eq!(encode(&key), encode(&key.clone()));
        assert_ne!(encode(&key), encode(&key[..1]));
    }

    #[test]
    fn wire_and_read_paths_agree() {
        let wire = [Wire::Integer(7), Wire::Text("x".to_owned())];
        let read = [
            Value::<Postgres>::Int(7),
            Value::<Postgres>::String("x".to_owned()),
        ];
        let mapped: Vec<Value<Postgres>> = wire.iter().map(from_wire).collect();
        assert_eq!(encode(&mapped), encode(&read));
    }

    #[test]
    fn preserves_blob_and_null() {
        let wire = [Wire::Blob(vec![0, 1, 2, 255]), Wire::Null];
        let mapped: Vec<Value<Postgres>> = wire.iter().map(from_wire).collect();
        assert_eq!(
            mapped,
            vec![
                Value::<Postgres>::Bytes(vec![0, 1, 2, 255]),
                Value::<Postgres>::Null
            ]
        );
    }
}
