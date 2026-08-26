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
use core::time::Duration;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::ClientError;
use crate::clock::now_secs;

/// DDL for the persisted subscription set. Written only under capture
/// suspension, like the rest of `_connetto_*`, so it never rides a mutation
/// upload.
pub(crate) const SUBSCRIPTION_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_query \
    (id INTEGER PRIMARY KEY, sql TEXT NOT NULL UNIQUE); \
    CREATE TABLE IF NOT EXISTS _connetto_subscription \
    (id TEXT PRIMARY KEY, query_id INTEGER NOT NULL REFERENCES _connetto_query(id), \
    priority INTEGER NOT NULL, pin_name TEXT UNIQUE, stopped_at INTEGER, \
    grace_secs INTEGER NOT NULL); \
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
        /// The application's name for a pin, and `NULL` for a watch. This is
        /// the only kind discriminant: a second one could disagree with it.
        pin_name -> Nullable<Text>,
        /// When the last handle dropped, in seconds since the epoch, and
        /// `NULL` while a handle still holds it or when it is a pin.
        stopped_at -> Nullable<BigInt>,
        /// How long after `stopped_at` the subscription stays live. Unused by
        /// a pin, which has no clock.
        grace_secs -> BigInt,
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

/// The canonical resting-table encoding of a bind list: every value in
/// placeholder order, each as its [`encode_bind`] discriminant byte followed
/// by a big-endian length and the value's bytes. This is the exact-identity
/// form R83 keys `_connetto_aggregates` rows on, so a restart finds the row a
/// live push wrote. One function so the upsert and the lookup share it.
pub(crate) fn encode_binds(binds: &[BindValue]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in binds {
        let (kind, bytes) = encode_bind(value);
        out.push(u8::try_from(kind).unwrap_or_default());
        let payload = bytes.as_deref().unwrap_or(&[]);
        let len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
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

/// How long a watch-backed subscription outlives its last handle by default.
/// Navigating away and back inside this window pays no fresh snapshot.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5 * 60);

/// The longest grace any watch may ask for. Wanting to outlive this is by
/// definition a pin, and the cap is what enforces that boundary mechanically
/// rather than by documentation.
pub const MAX_GRACE: Duration = Duration::from_secs(10 * 60);

/// One row of the join behind [`declared`]: id, query text, priority, pin
/// name, stop moment, grace.
type DeclaredRow = (String, String, i32, Option<String>, Option<i64>, i64);

/// One persisted subscription and what keeps it alive.
pub(crate) struct Declared {
    /// The client-assigned wire id.
    pub sub_id: String,
    /// What it subscribes to.
    pub spec: SubscriptionSpec,
    /// Whether the subscription still wants its rows: a pin always, a watch
    /// while held and until its grace runs out.
    pub live: bool,
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
    grace: Duration,
) -> Result<(), ClientError> {
    let grace_secs = i64::try_from(grace.min(MAX_GRACE).as_secs()).unwrap_or(0);
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

        // Declaring is also re-claiming: a record inside its grace goes back to
        // held rather than staying on a countdown nobody is waiting out. An
        // upsert rather than a replace, so a pin sharing this subscription
        // keeps its name: a watch declaring the same query must not silently
        // unpin it.
        diesel::insert_into(subscription::table)
            .values((
                subscription::id.eq(sub_id),
                subscription::query_id.eq(query_id),
                subscription::priority.eq(i32::from(spec.priority.get())),
                subscription::pin_name.eq(None::<String>),
                subscription::stopped_at.eq(None::<i64>),
                subscription::grace_secs.eq(grace_secs),
            ))
            .on_conflict(subscription::id)
            .do_update()
            .set((
                subscription::query_id.eq(query_id),
                subscription::priority.eq(i32::from(spec.priority.get())),
                subscription::stopped_at.eq(None::<i64>),
                subscription::grace_secs.eq(grace_secs),
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
        // A rested aggregate value keeps its query text alive past the
        // subscription that produced it: an aggregate carries zero grace, so
        // this sweep runs the moment its last handle drops, and deleting the
        // text would strand the resting row a later restart reads through.
        let referenced = crate::aggregates::aggregate::table
            .filter(crate::aggregates::aggregate::query_id.eq_any(&orphans))
            .select(crate::aggregates::aggregate::query_id)
            .distinct()
            .load::<i32>(conn)?;
        let deletable: Vec<i32> = orphans
            .into_iter()
            .filter(|id| !referenced.contains(id))
            .collect();
        diesel::delete(query_text::table.filter(query_text::id.eq_any(deletable))).execute(conn)?;
        Ok(())
    })
}

/// The query identity a subscription id names: the shared `_connetto_query`
/// row id and the binds in placeholder order, or `None` when no record names
/// it. The resting table keys server-computed values on this identity rather
/// than the run-local subscription id, so a value survives past its
/// subscription and is found again after a restart mints fresh ids (R83).
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read, or when a stored
/// bind value does not decode.
pub(crate) fn identity_of(
    db: &mut SqliteConnection,
    sub_id: &str,
) -> Result<Option<(i32, Vec<BindValue>)>, ClientError> {
    let query_id: Option<i32> = subscription::table
        .filter(subscription::id.eq(sub_id))
        .select(subscription::query_id)
        .first(db)
        .optional()?;
    let Some(query_id) = query_id else {
        return Ok(None);
    };
    Ok(Some((query_id, binds_of(db, sub_id)?)))
}

/// The (query id, canonical binds blob) of every subscription on record, the
/// set the resting cap must never evict: a statistic still subscribed is still
/// watched.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read, or when a stored
/// bind value does not decode.
pub(crate) fn live_identities(
    db: &mut SqliteConnection,
) -> Result<Vec<(i32, Vec<u8>)>, ClientError> {
    let subs: Vec<(String, i32)> = subscription::table
        .select((subscription::id, subscription::query_id))
        .load(db)?;
    let mut out = Vec::with_capacity(subs.len());
    for (sub_id, query_id) in subs {
        out.push((query_id, encode_binds(&binds_of(db, &sub_id)?)));
    }
    Ok(out)
}

/// The binds of one subscription, in placeholder order.
fn binds_of(db: &mut SqliteConnection, sub_id: &str) -> Result<Vec<BindValue>, ClientError> {
    let stored: Vec<(i32, Option<Vec<u8>>)> = bind::table
        .filter(bind::subscription_id.eq(sub_id))
        .order(bind::position)
        .select((bind::kind, bind::value))
        .load(db)?;
    let mut binds = Vec::with_capacity(stored.len());
    for (kind, value) in stored {
        binds.push(decode_bind(kind, value)?);
    }
    Ok(binds)
}

/// Every persisted subscription, in declaration order.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read, or when a stored
/// bind value does not decode.
pub(crate) fn declared(db: &mut SqliteConnection) -> Result<Vec<Declared>, ClientError> {
    let now = now_secs(db)?;
    let rows: Vec<DeclaredRow> = subscription::table
        .inner_join(query_text::table)
        .select((
            subscription::id,
            query_text::sql,
            subscription::priority,
            subscription::pin_name,
            subscription::stopped_at,
            subscription::grace_secs,
        ))
        .order(subscription::id)
        .load(db)?;

    let mut out = Vec::with_capacity(rows.len());
    for (sub_id, sql, priority, pin_name, stopped_at, grace_secs) in rows {
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
        // A pin has no clock. A watch is live while held, and after its last
        // handle drops until the grace runs out. Nothing runs to end it: the
        // comparison is the expiry, which is how ban expiry and provider token
        // refresh already work in this codebase.
        let live = pin_name.is_some()
            || stopped_at.is_none_or(|stopped| now.saturating_sub(stopped) < grace_secs);
        out.push(Declared {
            sub_id,
            spec: SubscriptionSpec {
                priority: SubscriptionPriority::new(raw),
                query: sql,
                binds,
            },
            live,
        });
    }
    Ok(out)
}

/// Start the grace countdown on `sub_id`, because its last handle dropped.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn release(db: &mut SqliteConnection, sub_id: &str) -> Result<(), ClientError> {
    let now = now_secs(db)?;
    diesel::update(subscription::table.filter(subscription::id.eq(sub_id)))
        .set(subscription::stopped_at.eq(Some(now)))
        .execute(db)?;
    Ok(())
}

/// Stop the grace countdown on `sub_id`, because a handle holds it again.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn hold(db: &mut SqliteConnection, sub_id: &str) -> Result<(), ClientError> {
    diesel::update(subscription::table.filter(subscription::id.eq(sub_id)))
        .set(subscription::stopped_at.eq(None::<i64>))
        .execute(db)?;
    Ok(())
}

/// Start the grace countdown on every watch a previous run died still holding,
/// so an abandoned one retires while a re-claimed one is free.
///
/// Such a record has no stop moment, because nothing released it. Left as it
/// is it reads live for ever and [`expired`] can never return it, so the
/// server keeps a subscription nobody asked for. Anchoring here rather than in
/// the in-memory seed is what makes the countdown outlive this run too.
///
/// A pin is excluded, and that exclusion is load-bearing: a pin's grace is
/// zero by design, so anchoring one would end it at the first pump.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn anchor_launch(db: &mut SqliteConnection) -> Result<(), ClientError> {
    let now = now_secs(db)?;
    diesel::update(
        subscription::table
            .filter(subscription::pin_name.is_null())
            .filter(subscription::stopped_at.is_null()),
    )
    .set(subscription::stopped_at.eq(Some(now)))
    .execute(db)?;
    Ok(())
}

/// Record `spec` as a pin under the application's `name`, replacing whatever
/// that name held. A pin has no grace and ends only by [`unpin`].
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn pin(
    db: &mut SqliteConnection,
    name: &str,
    sub_id: &str,
    spec: &SubscriptionSpec,
) -> Result<(), ClientError> {
    // Re-pinning a changed query under one name is the documented upgrade
    // path. The name moves rather than the old record being destroyed, because
    // a watch handle may still hold that subscription: released of its pin it
    // simply falls back to grace like any other watch.
    if let Some(previous) = pinned_id(db, name)?
        && previous != sub_id
    {
        release_pin(db, &previous)?;
    }
    // Zero grace, because a pin has no clock: what keeps it alive is its
    // name. Giving it a countdown it never consults would mean a released pin
    // survived for a reason that has nothing to do with being pinned.
    remember(db, sub_id, spec, Duration::ZERO)?;
    diesel::update(subscription::table.filter(subscription::id.eq(sub_id)))
        .set(subscription::pin_name.eq(Some(name)))
        .execute(db)?;
    Ok(())
}

/// The subscription id currently pinned under `name`, if any.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn pinned_id(
    db: &mut SqliteConnection,
    name: &str,
) -> Result<Option<String>, ClientError> {
    Ok(subscription::table
        .filter(subscription::pin_name.eq(name))
        .select(subscription::id)
        .first::<String>(db)
        .optional()?)
}

/// End the pin under `name` and start its rows down the ordinary grace path.
/// Unknown names are a no-op, so unpinning is idempotent.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica rejects the write.
pub(crate) fn unpin(db: &mut SqliteConnection, name: &str) -> Result<(), ClientError> {
    let Some(sub_id) = pinned_id(db, name)? else {
        return Ok(());
    };
    let now = now_secs(db)?;
    // Ended, not put on a countdown. The stated use for a pin is a dataset
    // downloaded deliberately and cleared explicitly, so leaving a grace tail
    // would keep the server streaming data the application just released. A
    // handle still holding this subscription is protected by the reference
    // count instead, which is where handles are tracked.
    diesel::update(subscription::table.filter(subscription::id.eq(&sub_id)))
        .set((
            subscription::pin_name.eq(None::<String>),
            subscription::stopped_at.eq(Some(now)),
            subscription::grace_secs.eq(0_i64),
        ))
        .execute(db)?;
    Ok(())
}

/// Take the pin off `sub_id`, leaving it an ordinary watch.
fn release_pin(db: &mut SqliteConnection, sub_id: &str) -> Result<(), ClientError> {
    diesel::update(subscription::table.filter(subscription::id.eq(sub_id)))
        .set(subscription::pin_name.eq(None::<String>))
        .execute(db)?;
    Ok(())
}

/// Every pin, as name and query, in name order.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn pins(db: &mut SqliteConnection) -> Result<Vec<(String, String)>, ClientError> {
    Ok(subscription::table
        .inner_join(query_text::table)
        .filter(subscription::pin_name.is_not_null())
        .select((subscription::pin_name.assume_not_null(), query_text::sql))
        .order(subscription::pin_name)
        .load(db)?)
}

/// Every watch whose grace has run out, so the caller can unsubscribe each and
/// drop its record. Reading this never deletes anything on its own.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn expired(db: &mut SqliteConnection) -> Result<Vec<String>, ClientError> {
    // One query returning ids, not a full load filtered in Rust: the pump asks
    // this on every step, and `declared` costs a further query per subscription
    // to rebuild its binds, which is work no expiry check needs.
    let now = now_secs(db)?;
    Ok(subscription::table
        .filter(subscription::pin_name.is_null())
        .filter((subscription::stopped_at.assume_not_null() + subscription::grace_secs).le(now))
        .select(subscription::id)
        .load(db)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::connection::SimpleConnection;

    fn replica() -> SqliteConnection {
        let mut db = SqliteConnection::establish(":memory:").expect("open");
        db.batch_execute(SUBSCRIPTION_DDL).expect("ddl");
        // `forget` reads `_connetto_aggregates` to spare a query row a rested
        // value references, so the fixture carries it like an open replica does.
        db.batch_execute(crate::aggregates::AGGREGATE_DDL)
            .expect("aggregate ddl");
        db
    }

    /// Ids and specs, which is what most of these assert on.
    fn listed(db: &mut SqliteConnection) -> Vec<(String, SubscriptionSpec)> {
        declared(db)
            .expect("declared")
            .into_iter()
            .map(|record| (record.sub_id, record.spec))
            .collect()
    }

    fn watch(db: &mut SqliteConnection, id: &str, spec: &SubscriptionSpec) {
        remember(db, id, spec, DEFAULT_GRACE).expect("remember");
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
        watch(&mut db, "wire-0", &spec);
        assert_eq!(listed(&mut db), vec![("wire-0".to_owned(), spec)]);
    }

    /// Two subscriptions differing only in a bind value share one row of query
    /// text, which is the reason the schema is normalised at all.
    #[test]
    fn a_shared_query_is_stored_once() {
        let mut db = replica();
        let sql = "SELECT * FROM orders WHERE customer = ?";
        for (id, customer) in [("wire-0", 1_i64), ("wire-1", 2)] {
            watch(
                &mut db,
                id,
                &SubscriptionSpec {
                    priority: SubscriptionPriority::default(),
                    query: sql.to_owned(),
                    binds: vec![BindValue::Integer(customer)],
                },
            );
        }
        let texts: i64 = query_text::table
            .count()
            .get_result(&mut db)
            .expect("count");
        assert_eq!(texts, 1, "one row of text for two subscriptions");
        assert_eq!(listed(&mut db).len(), 2);
    }

    /// Forgetting one subscription leaves a sibling over the same query intact,
    /// and reclaims the text only once nothing refers to it.
    #[test]
    fn forgetting_one_leaves_its_sibling_alone() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        watch(&mut db, "wire-0", &spec);
        watch(&mut db, "wire-1", &spec);

        forget(&mut db, "wire-0").expect("forget");
        assert_eq!(listed(&mut db), vec![("wire-1".to_owned(), spec)]);
        let texts: i64 = query_text::table
            .count()
            .get_result(&mut db)
            .expect("count");
        assert_eq!(texts, 1, "the sibling still needs the text");

        forget(&mut db, "wire-1").expect("forget");
        assert!(
            listed(&mut db).is_empty(),
            "forgetting the last sibling leaves no declared subscription"
        );
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
        watch(
            &mut db,
            "wire-0",
            &SubscriptionSpec {
                priority: SubscriptionPriority::default(),
                query: "SELECT * FROM orders WHERE a = ? AND b = ?".to_owned(),
                binds: vec![BindValue::Integer(1), BindValue::Integer(2)],
            },
        );
        let narrowed = SubscriptionSpec {
            priority: SubscriptionPriority::default(),
            query: "SELECT * FROM orders WHERE a = ?".to_owned(),
            binds: vec![BindValue::Integer(1)],
        };
        watch(&mut db, "wire-0", &narrowed);
        assert_eq!(listed(&mut db), vec![("wire-0".to_owned(), narrowed)]);
    }

    /// A held watch is live, a released one stays live inside its grace, and it
    /// expires once past it. The grace is measured by the replica's own clock,
    /// so a zero grace is the only value a test can assert on without waiting.
    #[test]
    fn a_watch_expires_only_once_its_grace_has_run_out() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");

        remember(&mut db, "wire-0", &spec, Duration::from_secs(600)).expect("remember");
        assert!(expired(&mut db).expect("expired").is_empty(), "held");

        release(&mut db, "wire-0").expect("release");
        assert!(
            expired(&mut db).expect("expired").is_empty(),
            "dropped, but well inside a ten minute grace"
        );

        remember(&mut db, "wire-1", &spec, Duration::ZERO).expect("remember");
        release(&mut db, "wire-1").expect("release");
        assert_eq!(
            expired(&mut db).expect("expired"),
            vec!["wire-1".to_owned()],
            "no grace at all, so dropping ends it at once"
        );
    }

    /// Re-declaring inside the grace re-claims the record rather than leaving
    /// it counting down, which is what makes navigating away and back free.
    #[test]
    fn redeclaring_inside_the_grace_reclaims_it() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        remember(&mut db, "wire-0", &spec, Duration::ZERO).expect("remember");
        release(&mut db, "wire-0").expect("release");
        assert_eq!(expired(&mut db).expect("expired").len(), 1);

        remember(&mut db, "wire-0", &spec, Duration::ZERO).expect("remember");
        assert!(
            expired(&mut db).expect("expired").is_empty(),
            "re-declaring clears the stop moment"
        );
    }

    /// A grace beyond the cap is clamped rather than refused, because the cap
    /// is what stops a grace becoming a second pin.
    #[test]
    fn a_grace_past_the_cap_is_clamped() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        remember(&mut db, "wire-0", &spec, Duration::from_secs(60 * 60 * 24)).expect("remember");
        let stored: i64 = subscription::table
            .filter(subscription::id.eq("wire-0"))
            .select(subscription::grace_secs)
            .first(&mut db)
            .expect("read grace");
        assert_eq!(
            stored,
            i64::try_from(MAX_GRACE.as_secs()).expect("cap fits")
        );
    }

    /// A pin has no clock: it survives a drop that would expire any watch, and
    /// ends only by name.
    #[test]
    fn a_pin_outlives_a_drop_and_ends_only_by_name() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders WHERE id = 1");
        pin(&mut db, "offline-pack", "wire-0", &spec).expect("pin");
        release(&mut db, "wire-0").expect("release");
        assert!(
            expired(&mut db).expect("expired").is_empty(),
            "a pin ignores the countdown a drop starts"
        );
        assert_eq!(
            pins(&mut db).expect("pins"),
            vec![("offline-pack".to_owned(), spec.query.clone())]
        );

        unpin(&mut db, "offline-pack").expect("unpin");
        assert!(
            pins(&mut db).expect("pins").is_empty(),
            "unpinning removes the pin itself"
        );
        assert_eq!(
            expired(&mut db).expect("expired"),
            vec!["wire-0".to_owned()],
            "unpinning puts it back on the grace path, and its grace has passed"
        );
    }

    /// Watching a pinned query must not silently unpin it. The upsert exists
    /// for this: a replace would drop the name.
    #[test]
    fn declaring_a_watch_over_a_pinned_query_keeps_the_pin() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        pin(&mut db, "keep", "wire-0", &spec).expect("pin");
        watch(&mut db, "wire-0", &spec);
        assert_eq!(
            pins(&mut db).expect("pins"),
            vec![("keep".to_owned(), spec.query)],
            "the pin survives a watch declaring the same subscription"
        );
    }

    /// Re-pinning a changed query under one name moves the name rather than
    /// leaving two, and the displaced subscription becomes an ordinary watch.
    #[test]
    fn repinning_a_name_moves_it() {
        let mut db = replica();
        pin(
            &mut db,
            "pack",
            "wire-0",
            &SubscriptionSpec::new("SELECT * FROM orders"),
        )
        .expect("pin");
        let upgraded = SubscriptionSpec::new("SELECT * FROM orders WHERE open = 1");
        pin(&mut db, "pack", "wire-1", &upgraded).expect("pin");
        assert_eq!(
            pins(&mut db).expect("pins"),
            vec![("pack".to_owned(), upgraded.query)],
            "one name, one subscription"
        );
        assert_eq!(
            listed(&mut db).len(),
            2,
            "the displaced one is still a watch"
        );
    }

    /// The launch anchor: a watch with no stop moment gets one, a pin does
    /// not, and a countdown already running is not restarted.
    ///
    /// The pin case is the load-bearing one. A pin's grace is zero, so
    /// anchoring it would leave a record that ends the moment its name is
    /// released for any reason.
    #[test]
    fn the_launch_anchor_starts_watches_and_spares_pins() {
        let mut db = replica();
        let spec = SubscriptionSpec::new("SELECT * FROM orders");
        remember(&mut db, "wire-0", &spec, Duration::ZERO).expect("remember");
        pin(&mut db, "pack", "wire-1", &spec).expect("pin");
        remember(&mut db, "wire-2", &spec, Duration::from_secs(300)).expect("remember");
        release(&mut db, "wire-2").expect("release");
        let released_at = stopped_at(&mut db, "wire-2");

        assert!(
            expired(&mut db).expect("expired").is_empty(),
            "control: nothing has a stop moment except the one just released, \
             whose grace has not run out"
        );
        anchor_launch(&mut db).expect("anchor");

        assert_eq!(
            expired(&mut db).expect("expired"),
            vec!["wire-0".to_owned()],
            "the zero-grace watch the run died holding is now past its grace"
        );
        assert_eq!(
            stopped_at(&mut db, "wire-1"),
            None,
            "the pin keeps no stop moment"
        );
        assert_eq!(
            stopped_at(&mut db, "wire-2"),
            released_at,
            "a countdown already running is left where it was"
        );
    }

    /// The stop moment recorded for `sub_id`.
    fn stopped_at(db: &mut SqliteConnection, sub_id: &str) -> Option<i64> {
        subscription::table
            .filter(subscription::id.eq(sub_id))
            .select(subscription::stopped_at)
            .first(db)
            .expect("read stop moment")
    }
}
