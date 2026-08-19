//! Canonical primary-key codec.
//!
//! The oplog stores each retained change under a stable identity for its row,
//! and that identity has to be the same byte string whether the key arrived as
//! a CDC event's `Value<Postgres>` cells or as an uploaded sqlite-diff row
//! image. Both encode the key columns, in key order, into one self-describing
//! byte string. Encoding is `MessagePack` over `Vec<Value<Postgres>>`.
//!
//! The wire mapping is directed by the catalog because the read path is: it
//! lifts each column to its declared type, so a `UUID` becomes
//! [`Value::Uuid`] rather than raw bytes. An upload carries that same key as a
//! sixteen-byte blob, so it has to lift the blob the same way. Otherwise the
//! two spellings of one row name it differently, and every identity comparison
//! spanning both (the authorization seam names a row by rendering its key)
//! misses.

use sqlite_diff_rs::Value as WireValue;
use subql::backend::{Postgres, ScalarKind, Value};
use subql::{ColumnId, DatabaseLike, TableId, catalog_helpers};

/// The sqlite-diff value shape carried by an uploaded row image.
type Wire = WireValue<String, Vec<u8>>;

/// Map one uploaded sqlite-diff cell to the canonical [`Value<Postgres>`],
/// directed by the column's declared scalar `kind`.
///
/// sqlite-diff carries only SQLite's four storage classes plus NULL. Integers,
/// reals, text, and blobs map straight across and NULL stays NULL, which is
/// exactly right whenever the storage class already matches the Postgres type.
/// The exception is a column whose type has no matching storage class: a
/// `UUID`, which pg2sqlite stores as a sixteen-byte blob and the read path
/// decodes to [`Value::Uuid`] from the catalog. A blob under a `UUID` column is
/// lifted the same way here so the two paths agree. A `kind` of [`None`], or a
/// blob that is not sixteen bytes, keeps the plain storage mapping.
pub(crate) fn from_wire(value: &Wire, kind: Option<ScalarKind>) -> Value<Postgres> {
    match (value, kind) {
        (WireValue::Blob(blob), Some(ScalarKind::Uuid)) => uuid_from_blob(blob),
        (WireValue::Null, _) => Value::Null,
        (WireValue::Integer(int), _) => Value::Int(*int),
        (WireValue::Real(real), _) => Value::Float(*real),
        (WireValue::Text(text), _) => Value::String(text.clone()),
        (WireValue::Blob(blob), _) => Value::Bytes(blob.clone()),
    }
}

/// Lift a sixteen-byte blob to [`Value::Uuid`], matching the read path. A blob
/// of any other length is not a UUID image, so it stays [`Value::Bytes`] rather
/// than being forced into a shape it is not.
fn uuid_from_blob(blob: &[u8]) -> Value<Postgres> {
    <[u8; 16]>::try_from(blob).map_or_else(
        |_| Value::Bytes(blob.to_vec()),
        |bytes| Value::Uuid(uuid::Uuid::from_bytes(bytes)),
    )
}

/// The declared scalar kind of the column at `ordinal` in `table_id`, or
/// [`None`] when the ordinal is past the table's columns.
pub(crate) fn scalar_kind<DB: DatabaseLike>(
    db: &DB,
    table_id: TableId,
    ordinal: usize,
) -> Option<ScalarKind> {
    catalog_helpers::column_scalar_kind(db, table_id, ColumnId::try_from(ordinal).ok()?)
}

/// Map a full uploaded row image to canonical values, directing each cell by
/// its column's catalog scalar kind. A cell's position is its column ordinal.
pub(crate) fn row_from_wire<DB: DatabaseLike>(
    db: &DB,
    table_id: TableId,
    values: &[Wire],
) -> Vec<Value<Postgres>> {
    values
        .iter()
        .enumerate()
        .map(|(ordinal, value)| from_wire(value, scalar_kind(db, table_id, ordinal)))
        .collect()
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
        // A UUID column is where the two paths used to disagree: the read path
        // types it from the catalog to `Value::Uuid`, while the upload carries
        // it as a sixteen-byte blob. Integer and text coincide on both paths.
        let id = uuid::Uuid::from_u128(0xab4a_f609_f3d2_5ebd_b482_fbe8_b7db_00c6);
        let wire = [
            Wire::Integer(7),
            Wire::Text("x".to_owned()),
            Wire::Blob(id.as_bytes().to_vec()),
        ];
        let kinds = [
            Some(ScalarKind::Int),
            Some(ScalarKind::String),
            Some(ScalarKind::Uuid),
        ];
        let read = [
            Value::<Postgres>::Int(7),
            Value::<Postgres>::String("x".to_owned()),
            Value::<Postgres>::Uuid(id),
        ];
        let mapped: Vec<Value<Postgres>> = wire
            .iter()
            .zip(kinds)
            .map(|(value, kind)| from_wire(value, kind))
            .collect();
        assert_eq!(encode(&mapped), encode(&read));
    }

    #[test]
    fn a_blob_under_a_uuid_column_lifts_to_a_uuid() {
        let id = uuid::Uuid::from_u128(1);
        assert_eq!(
            from_wire(&Wire::Blob(id.as_bytes().to_vec()), Some(ScalarKind::Uuid)),
            Value::<Postgres>::Uuid(id),
        );
        // A blob that is not sixteen bytes is not a UUID image, so it stays
        // bytes rather than being forced into one.
        assert_eq!(
            from_wire(&Wire::Blob(vec![0, 1, 2]), Some(ScalarKind::Uuid)),
            Value::<Postgres>::Bytes(vec![0, 1, 2]),
        );
    }

    #[test]
    fn preserves_blob_and_null() {
        // Without a UUID kind a blob stays bytes and NULL stays NULL.
        assert_eq!(
            from_wire(&Wire::Blob(vec![0, 1, 2, 255]), None),
            Value::<Postgres>::Bytes(vec![0, 1, 2, 255]),
        );
        assert_eq!(from_wire(&Wire::Null, None), Value::<Postgres>::Null);
    }
}
