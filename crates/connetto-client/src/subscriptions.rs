//! The declared subscription set, persisted in the replica.
//!
//! A subscription can be declared with no server reachable, so the set has to
//! outlive both the socket and the process. It lives in the replica rather than
//! in the optional device-private tier, because connetto's own bookkeeping must
//! not depend on a feature the application may never have asked for, which is
//! the same reason `_connetto_meta` lives there. See
//! `docs/architecture/15-replica-retention.md`.
//!
//! Normalised into three tables so a query shared by several subscriptions is
//! stored once. R15 reads this same set to decide which rows are still covered.

use connetto_core::messages::{BindValue, SubscriptionPriority, SubscriptionSpec};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::ClientError;

/// DDL for the persisted subscription set. Written only under capture
/// suspension, like the rest of `_connetto_*`, so it never rides a mutation
/// upload.
pub(crate) const SUBSCRIPTION_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_query \
    (id INTEGER PRIMARY KEY, sql TEXT NOT NULL UNIQUE); \
    CREATE TABLE IF NOT EXISTS _connetto_subscription \
    (id TEXT PRIMARY KEY, query_id INTEGER NOT NULL REFERENCES _connetto_query(id), \
    priority INTEGER NOT NULL); \
    CREATE TABLE IF NOT EXISTS _connetto_bind \
    (subscription_id TEXT NOT NULL REFERENCES _connetto_subscription(id) ON DELETE CASCADE, \
    position INTEGER NOT NULL, kind INTEGER NOT NULL, value BLOB, \
    PRIMARY KEY (subscription_id, position))";

diesel::table! {
    /// Subscription query text, shared by every subscription that declares it.
    #[sql_name = "_connetto_query"]
    query_text (id) {
        /// Surrogate key.
        id -> Integer,
        /// The full `SELECT` in the client's SQLite dialect.
        sql -> Text,
    }
}

diesel::table! {
    /// One declared subscription.
    #[sql_name = "_connetto_subscription"]
    subscription (id) {
        /// The client-assigned wire id, which is what the server is told.
        id -> Text,
        /// The query this subscription runs.
        query_id -> Integer,
        /// Delivery priority, as its raw byte.
        priority -> Integer,
    }
}

diesel::table! {
    /// One value bound to a `?` placeholder, in placeholder order.
    #[sql_name = "_connetto_bind"]
    bind (subscription_id, position) {
        /// Which subscription the value belongs to.
        subscription_id -> Text,
        /// Placeholder index, from zero.
        position -> Integer,
        /// Which [`BindValue`] variant `value` carries.
        kind -> Integer,
        /// The value's bytes, absent only for SQL `NULL`.
        value -> Nullable<Binary>,
    }
}

diesel::joinable!(subscription -> query_text (query_id));
diesel::joinable!(bind -> subscription (subscription_id));
diesel::allow_tables_to_appear_in_same_query!(query_text, subscription, bind);

/// Discriminants for [`BindValue`], stored beside the bytes so a value reads
/// back as the storage class it went in as. An integer that returned as text
/// would change what the server matches.
const KIND_NULL: i32 = 0;
const KIND_INTEGER: i32 = 1;
const KIND_REAL: i32 = 2;
const KIND_TEXT: i32 = 3;
const KIND_BLOB: i32 = 4;

/// Split a bind value into its stored discriminant and bytes.
fn encode_bind(value: &BindValue) -> (i32, Option<Vec<u8>>) {
    match value {
        BindValue::Null => (KIND_NULL, None),
        BindValue::Integer(n) => (KIND_INTEGER, Some(n.to_be_bytes().to_vec())),
        BindValue::Real(f) => (KIND_REAL, Some(f.to_be_bytes().to_vec())),
        BindValue::Text(s) => (KIND_TEXT, Some(s.as_bytes().to_vec())),
        BindValue::Blob(b) => (KIND_BLOB, Some(b.clone())),
    }
}

/// Rebuild a bind value from its stored discriminant and bytes.
fn decode_bind(kind: i32, value: Option<Vec<u8>>) -> Result<BindValue, ClientError> {
    let malformed = || ClientError::Session("a persisted bind value is malformed".to_owned());
    match kind {
        KIND_NULL => Ok(BindValue::Null),
        KIND_INTEGER => {
            let bytes = value.ok_or_else(malformed)?;
            Ok(BindValue::Integer(i64::from_be_bytes(
                bytes.try_into().map_err(|_| malformed())?,
            )))
        }
        KIND_REAL => {
            let bytes = value.ok_or_else(malformed)?;
            Ok(BindValue::Real(f64::from_be_bytes(
                bytes.try_into().map_err(|_| malformed())?,
            )))
        }
        KIND_TEXT => {
            let bytes = value.ok_or_else(malformed)?;
            Ok(BindValue::Text(
                String::from_utf8(bytes).map_err(|_| malformed())?,
            ))
        }
        KIND_BLOB => Ok(BindValue::Blob(value.ok_or_else(malformed)?)),
        _ => Err(malformed()),
    }
}

/// Record `spec` under `sub_id`, replacing any record already there.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn remember(
    db: &mut SqliteConnection,
    sub_id: &str,
    spec: &SubscriptionSpec,
) -> Result<(), ClientError> {
    db.transaction(|conn| {
        // Insert-or-ignore then select, rather than a returning clause, so the
        // shared row is reused when a second subscription declares the same
        // query text.
        diesel::insert_or_ignore_into(query_text::table)
            .values(query_text::sql.eq(&spec.query))
            .execute(conn)?;
        let query_id: i32 = query_text::table
            .filter(query_text::sql.eq(&spec.query))
            .select(query_text::id)
            .first(conn)?;

        diesel::replace_into(subscription::table)
            .values((
                subscription::id.eq(sub_id),
                subscription::query_id.eq(query_id),
                subscription::priority.eq(i32::from(spec.priority.get())),
            ))
            .execute(conn)?;

        // A redeclared id keeps no stale tail of binds from a longer previous
        // spec, which would change the query's meaning on replay.
        diesel::delete(bind::table.filter(bind::subscription_id.eq(sub_id))).execute(conn)?;
        for (position, value) in spec.binds.iter().enumerate() {
            let position = i32::try_from(position).map_err(|_| {
                diesel::result::Error::QueryBuilderError(
                    "a subscription cannot carry that many bind values".into(),
                )
            })?;
            let (kind, bytes) = encode_bind(value);
            diesel::insert_into(bind::table)
                .values((
                    bind::subscription_id.eq(sub_id),
                    bind::position.eq(position),
                    bind::kind.eq(kind),
                    bind::value.eq(bytes),
                ))
                .execute(conn)?;
        }
        Ok(())
    })
}

/// Drop the record for `sub_id`, and the query text with it once no
/// subscription refers to it.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn forget(db: &mut SqliteConnection, sub_id: &str) -> Result<(), ClientError> {
    db.transaction(|conn| {
        diesel::delete(bind::table.filter(bind::subscription_id.eq(sub_id))).execute(conn)?;
        diesel::delete(subscription::table.filter(subscription::id.eq(sub_id))).execute(conn)?;
        let orphans = query_text::table
            .left_join(subscription::table)
            .filter(subscription::id.nullable().is_null())
            .select(query_text::id)
            .load::<i32>(conn)?;
        diesel::delete(query_text::table.filter(query_text::id.eq_any(orphans))).execute(conn)?;
        Ok(())
    })
}

/// Every persisted subscription, in declaration order.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read, or when a stored
/// bind value does not decode.
pub(crate) fn declared(
    db: &mut SqliteConnection,
) -> Result<Vec<(String, SubscriptionSpec)>, ClientError> {
    let rows: Vec<(String, String, i32)> = subscription::table
        .inner_join(query_text::table)
        .select((subscription::id, query_text::sql, subscription::priority))
        .order(subscription::id)
        .load(db)?;

    let mut out = Vec::with_capacity(rows.len());
    for (sub_id, sql, priority) in rows {
        let stored: Vec<(i32, Option<Vec<u8>>)> = bind::table
            .filter(bind::subscription_id.eq(&sub_id))
            .order(bind::position)
            .select((bind::kind, bind::value))
            .load(db)?;
        let mut binds = Vec::with_capacity(stored.len());
        for (kind, value) in stored {
            binds.push(decode_bind(kind, value)?);
        }
        let raw = u8::try_from(priority).map_err(|_| {
            ClientError::Session(format!(
                "a persisted subscription priority is out of range: {priority}"
            ))
        })?;
        out.push((
            sub_id,
            SubscriptionSpec {
                priority: SubscriptionPriority::new(raw),
                query: sql,
                binds,
            },
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    fn replica() -> SqliteConnection {
        let mut db = SqliteConnection::establish(":memory:").expect("open");
        db.batch_execute(SUBSCRIPTION_DDL).expect("ddl");
        db
    }

    /// Every storage class survives the round trip as itself. A value that
    /// changed class would silently change which rows the server matches.
    #[test]
    fn every_bind_kind_round_trips() {
        let mut db = replica();
        let spec = SubscriptionSpec {
            priority: SubscriptionPriority::new(3),
            query: "SELECT * FROM orders WHERE a = ? AND b = ? AND c = ? AND d = ? AND e = ?"
                .to_owned(),
            binds: vec![
                BindValue::Null,
                BindValue::Integer(-9_007_199_254_740_993),
                BindValue::Real(0.1 + 0.2),
                BindValue::Text("caf\u{e9}".to_owned()),
                BindValue::Blob(vec![0, 255, 128]),
            ],
        };
        remember(&mut db, "wire-0", &spec).expect("remember");
        assert_eq!(
            declared(&mut db).expect("declared"),
            vec![("wire-0".to_owned(), spec)]
        );
    }

    /// Two subscriptions differing only in a bind value share one row of query
    /// text, which is the reason the schema is normalised at all.
    #[test]
    fn a_shared_query_is_stored_once() {
        let mut db = replica();
        let sql = "SELECT * FROM orders WHERE customer = ?";
        for (id, customer) in [("wire-0", 1_i64), ("wire-1", 2)] {
            let spec = SubscriptionSpec {
                priority: SubscriptionPriority::default(),
                query: sql.to_owned(),
                binds: vec![BindValue::Integer(customer)],
            };
            remember(&mut db, id, &spec).expect("remember");
        }
        let texts: i64 = query_text::table
            .count()
            .get_result(&mut db)
            .expect("count");
        assert_eq!(texts, 1, "one row of text for two subscriptions");
        assert_eq!(declared(&mut db).expect("declared").len(), 2);
    }

    /// Forgetting one subscription leaves a sibling over the same query intact,
    /// and reclaims the text only once nothing refers to it.
    #[test]
    fn forgetting_one_leaves_its_sibling_alone() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        remember(&mut db, "wire-0", &spec).expect("remember");
        remember(&mut db, "wire-1", &spec).expect("remember");

        forget(&mut db, "wire-0").expect("forget");
        assert_eq!(
            declared(&mut db).expect("declared"),
            vec![("wire-1".to_owned(), spec)]
        );
        let texts: i64 = query_text::table
            .count()
            .get_result(&mut db)
            .expect("count");
        assert_eq!(texts, 1, "the sibling still needs the text");

        forget(&mut db, "wire-1").expect("forget");
        assert!(declared(&mut db).expect("declared").is_empty());
        let texts: i64 = query_text::table
            .count()
            .get_result(&mut db)
            .expect("count");
        assert_eq!(texts, 0, "nothing refers to the text any more");
    }

    /// Redeclaring an id replaces its binds rather than appending to them.
    #[test]
    fn redeclaring_an_id_does_not_keep_a_stale_tail() {
        let mut db = replica();
        remember(
            &mut db,
            "wire-0",
            &SubscriptionSpec {
                priority: SubscriptionPriority::default(),
                query: "SELECT * FROM orders WHERE a = ? AND b = ?".to_owned(),
                binds: vec![BindValue::Integer(1), BindValue::Integer(2)],
            },
        )
        .expect("remember");
        let narrowed = SubscriptionSpec {
            priority: SubscriptionPriority::default(),
            query: "SELECT * FROM orders WHERE a = ?".to_owned(),
            binds: vec![BindValue::Integer(1)],
        };
        remember(&mut db, "wire-0", &narrowed).expect("remember");
        assert_eq!(
            declared(&mut db).expect("declared"),
            vec![("wire-0".to_owned(), narrowed)]
        );
    }
}
