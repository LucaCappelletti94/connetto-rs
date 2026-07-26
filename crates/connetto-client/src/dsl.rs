//! The compile-time dispatched `live()` verb.
//!
//! [`Watchable`] gives every typed diesel query a postfix
//! `query.live(&client)` that returns the right live handle for the query's
//! shape, chosen by the type system: a row projection produces a
//! [`LiveQuery`], a scalar aggregate produces a [`LiveValue`]. A misrouted
//! query does not compile, and the aggregate's decoded value type is derived
//! from the selection's SQL type, so a wrong decode type does not compile
//! either.
//!
//! The dispatch projects diesel's own aggregation discriminator: a built
//! [`SelectStatement`]'s select clause exposes its expression through
//! [`SelectClauseExpression`], and that expression's
//! [`ValidGrouping`]`<()>::IsAggregate` names one of the [`is_aggregate`]
//! markers. [`SelectionMarker`] captures both, and [`WatchDispatch`] is keyed
//! on the marker as a type parameter so the row and scalar impls never
//! overlap.
//!
//! Aggregate values decode by the selection's SQL type through
//! [`AggregateWire`], whose decoders follow the wire rather than serde
//! strictness: `COUNT` is an exact integer, `SUM` over an integer column is
//! presented as `Option<i64>` even though the server's float accumulator
//! renders it as `"3.0"` (the decoder accepts integral floats), `AVG` and the
//! extremes are `null` over an empty set, and `NUMERIC` extremes arrive as
//! JSON strings. The family spans the standard diesel SQL types a custom
//! aggregate returns: the numeric and text types (nullable and not), `Bool`,
//! the temporal types, `Binary`, and `Json` or `Jsonb`. A custom aggregate
//! declared with diesel's function macros participates automatically as long
//! as its SQL type has a mapping.
//!
//! The orphan rule means only this crate can map a diesel SQL type. An
//! application that declares its own SQL type maps it by implementing
//! [`AggregateWire`] for that type, reusing the wire-lenient primitives in
//! [`wire`] so its decode follows the same rules as the built-in family.
//!
//! Boxed queries (`.into_boxed()`) erase their select clause into a trait
//! object, so no type-level marker survives boxing. Dynamic queries use the
//! explicit, runtime-guarded [`ConnettoClient::watch`],
//! [`ConnettoClient::watch_value`], and
//! [`ConnettoClient::watch_value_with`] instead.

use core::future::Future;

use connetto_core::traits::{MaybeSend, Transport};
use diesel::expression::{Expression, ValidGrouping, is_aggregate};
use diesel::query_builder::{AsQuery, QueryFragment, SelectClauseExpression, SelectStatement};
use diesel::query_dsl::methods::LoadQuery;
use diesel::sql_types;
use diesel::sqlite::Sqlite;

use crate::ClientError;
use crate::live::{ConnettoClient, LiveHandle, LiveQuery, LiveValue};

/// The selection expression and aggregation marker of a built select
/// statement, projected purely at the type level.
pub trait SelectionMarker {
    /// The select clause's expression type.
    type Selection;
    /// One of the [`is_aggregate`] marker types for that expression.
    type Marker;
}

impl<F, S, D, W, O, LOf, G, H, LC> SelectionMarker for SelectStatement<F, S, D, W, O, LOf, G, H, LC>
where
    S: SelectClauseExpression<F>,
    S::Selection: ValidGrouping<()>,
{
    type Selection = S::Selection;
    type Marker = <S::Selection as ValidGrouping<()>>::IsAggregate;
}

/// Wire-lenient decode primitives shared by every [`AggregateWire`] impl.
///
/// Exposed so an application implementing [`AggregateWire`] for its own SQL
/// type decodes under the same rules as the built-in family: integral floats
/// accepted for integer targets (the server's `SUM` accumulator renders `3`
/// as `"3.0"`), and numeric strings accepted for floats (`NUMERIC` extremes
/// arrive as JSON strings).
pub mod wire {
    use crate::ClientError;

    /// Parse one server push into a JSON value.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the text is not valid JSON.
    pub fn json_value(json: &str) -> Result<serde_json::Value, ClientError> {
        serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))
    }

    /// An integer from a JSON number or numeric string, tolerating the float
    /// rendering the server's `SUM` accumulator produces for integer columns
    /// (`"3.0"` for 3). Returns `None` when the value is not an integer.
    #[must_use]
    pub fn lenient_i64(value: &serde_json::Value) -> Option<i64> {
        if let Some(i) = value.as_i64() {
            return Some(i);
        }
        let f = match value {
            serde_json::Value::Number(n) => n.as_f64()?,
            serde_json::Value::String(s) => s.parse::<f64>().ok()?,
            _ => return None,
        };
        // 2^53 is the largest magnitude at which every integer is exactly
        // representable in an f64, so within it the cast below cannot truncate.
        if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_992.0 {
            // Intended conversion: integral and range-checked just above.
            #[allow(clippy::cast_possible_truncation)]
            return Some(f as i64);
        }
        None
    }

    /// A float from a JSON number or numeric string (`NUMERIC` extremes arrive
    /// as strings on the wire). Returns `None` when the value is neither.
    #[must_use]
    pub fn lenient_f64(value: &serde_json::Value) -> Option<f64> {
        match value {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }
}

/// Decode a non-null integer push, converting through `i64`.
fn decode_int<I: TryFrom<i64>>(json: &str) -> Result<I, ClientError> {
    wire::lenient_i64(&wire::json_value(json)?)
        .and_then(|i| I::try_from(i).ok())
        .ok_or_else(|| ClientError::Session(format!("expected an integer, got {json}")))
}

/// Decode a nullable integer push, converting through `i64`.
fn decode_nullable_int<I: TryFrom<i64>>(json: &str) -> Result<Option<I>, ClientError> {
    let value = wire::json_value(json)?;
    if value.is_null() {
        return Ok(None);
    }
    wire::lenient_i64(&value)
        .and_then(|i| I::try_from(i).ok())
        .map(Some)
        .ok_or_else(|| ClientError::Session(format!("expected an integer, got {json}")))
}

/// Decode a non-null float push.
fn decode_f64(json: &str) -> Result<f64, ClientError> {
    wire::lenient_f64(&wire::json_value(json)?)
        .ok_or_else(|| ClientError::Session(format!("expected a number, got {json}")))
}

/// Decode a nullable float push.
fn decode_nullable_f64(json: &str) -> Result<Option<f64>, ClientError> {
    let value = wire::json_value(json)?;
    if value.is_null() {
        return Ok(None);
    }
    wire::lenient_f64(&value)
        .map(Some)
        .ok_or_else(|| ClientError::Session(format!("expected a number, got {json}")))
}

/// Decode a non-null float push, narrowing to `f32`.
fn decode_f32(json: &str) -> Result<f32, ClientError> {
    // Intended narrowing: the column's declared SQL type is a 4-byte float,
    // so the app's own model already accepts this precision.
    #[allow(clippy::cast_possible_truncation)]
    Ok(decode_f64(json)? as f32)
}

/// Decode a nullable float push, narrowing to `f32`.
fn decode_nullable_f32(json: &str) -> Result<Option<f32>, ClientError> {
    // Intended narrowing: see [`decode_f32`].
    #[allow(clippy::cast_possible_truncation)]
    Ok(decode_nullable_f64(json)?.map(|f| f as f32))
}

/// Decode a boolean push. Accepts a JSON bool (the re-execution wire shape) or
/// the integer `0`/`1` a SQLite `json_quote` renders for a local-tier bool.
fn decode_bool(json: &str) -> Result<bool, ClientError> {
    bool_from_json(&wire::json_value(json)?)
        .ok_or_else(|| ClientError::Session(format!("expected a boolean, got {json}")))
}

/// Decode a nullable boolean push.
fn decode_nullable_bool(json: &str) -> Result<Option<bool>, ClientError> {
    let value = wire::json_value(json)?;
    if value.is_null() {
        return Ok(None);
    }
    bool_from_json(&value)
        .map(Some)
        .ok_or_else(|| ClientError::Session(format!("expected a boolean, got {json}")))
}

/// A boolean from a JSON bool or the integer `0`/`1`.
fn bool_from_json(value: &serde_json::Value) -> Option<bool> {
    match value.as_bool() {
        Some(b) => Some(b),
        None => match wire::lenient_i64(value)? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
    }
}

/// Decode a string push. The temporal types, `Uuid`, and `Binary` all arrive
/// as JSON strings (the server renders them through `to_string` or a lossy
/// UTF-8 conversion, never as numbers or base64), so they share this decoder.
fn decode_string(json: &str) -> Result<String, ClientError> {
    match wire::json_value(json)? {
        serde_json::Value::String(s) => Ok(s),
        other => Err(ClientError::Session(format!(
            "expected a string, got {other}"
        ))),
    }
}

/// Decode a nullable string push.
fn decode_nullable_string(json: &str) -> Result<Option<String>, ClientError> {
    match wire::json_value(json)? {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => Ok(Some(s)),
        other => Err(ClientError::Session(format!(
            "expected a string, got {other}"
        ))),
    }
}

/// Decode a `Json` or `Jsonb` push: the server passes the raw JSON value
/// through unquoted, so this returns it verbatim.
fn decode_json(json: &str) -> Result<serde_json::Value, ClientError> {
    wire::json_value(json)
}

/// Decode a nullable `Json` or `Jsonb` push, mapping a top-level JSON `null`
/// (a SQL null) to `None`.
fn decode_nullable_json(json: &str) -> Result<Option<serde_json::Value>, ClientError> {
    let value = wire::json_value(json)?;
    Ok(if value.is_null() { None } else { Some(value) })
}

/// Wire mapping for one aggregate selection's SQL type: the decoded value
/// type and the decoder that follows the server's JSON rendering rules.
///
/// Implemented for the standard diesel SQL types a scalar aggregate returns:
/// the numeric and text types (nullable and not), `Bool`, the temporal types
/// (`Date`, `Time`, `Timestamp`, and, behind the `postgres-types` feature,
/// `Timestamptz` and `Uuid`), `Binary`, and `Json` or `Jsonb`. The nullable
/// impls decode JSON `null` (the empty-set value of `AVG` and the extremes)
/// as `None`.
///
/// The orphan rule forbids an application from implementing this trait for a
/// diesel SQL type it does not own, so this crate maps every standard type. An
/// application maps its own SQL type by implementing this trait for it, reusing
/// the primitives in [`wire`].
pub trait AggregateWire {
    /// The decoded value type.
    type Value: Clone + PartialEq + Send + Sync + 'static;

    /// Decode one server push.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the JSON does not decode as this type.
    fn decode(json: &str) -> Result<Self::Value, ClientError>;
}

/// Implement [`AggregateWire`] for a SQL type by delegating to a decode helper.
macro_rules! aggregate_wire {
    ($sql:ty => $value:ty, $decode:path) => {
        impl AggregateWire for $sql {
            type Value = $value;

            fn decode(json: &str) -> Result<$value, ClientError> {
                $decode(json)
            }
        }
    };
}

aggregate_wire!(sql_types::Bool => bool, decode_bool);
aggregate_wire!(sql_types::SmallInt => i16, decode_int);
aggregate_wire!(sql_types::Integer => i32, decode_int);
aggregate_wire!(sql_types::BigInt => i64, decode_int);
aggregate_wire!(sql_types::Float => f32, decode_f32);
aggregate_wire!(sql_types::Double => f64, decode_f64);
aggregate_wire!(sql_types::Numeric => f64, decode_f64);
aggregate_wire!(sql_types::Text => String, decode_string);
aggregate_wire!(sql_types::Binary => String, decode_string);
aggregate_wire!(sql_types::Date => String, decode_string);
aggregate_wire!(sql_types::Time => String, decode_string);
aggregate_wire!(sql_types::Timestamp => String, decode_string);
aggregate_wire!(sql_types::Json => serde_json::Value, decode_json);
aggregate_wire!(sql_types::Jsonb => serde_json::Value, decode_json);

aggregate_wire!(sql_types::Nullable<sql_types::Bool> => Option<bool>, decode_nullable_bool);
aggregate_wire!(sql_types::Nullable<sql_types::SmallInt> => Option<i16>, decode_nullable_int);
aggregate_wire!(sql_types::Nullable<sql_types::Integer> => Option<i32>, decode_nullable_int);
aggregate_wire!(sql_types::Nullable<sql_types::BigInt> => Option<i64>, decode_nullable_int);
aggregate_wire!(sql_types::Nullable<sql_types::Float> => Option<f32>, decode_nullable_f32);
aggregate_wire!(sql_types::Nullable<sql_types::Double> => Option<f64>, decode_nullable_f64);
aggregate_wire!(sql_types::Nullable<sql_types::Numeric> => Option<f64>, decode_nullable_f64);
aggregate_wire!(sql_types::Nullable<sql_types::Text> => Option<String>, decode_nullable_string);
aggregate_wire!(sql_types::Nullable<sql_types::Binary> => Option<String>, decode_nullable_string);
aggregate_wire!(sql_types::Nullable<sql_types::Date> => Option<String>, decode_nullable_string);
aggregate_wire!(sql_types::Nullable<sql_types::Time> => Option<String>, decode_nullable_string);
aggregate_wire!(sql_types::Nullable<sql_types::Timestamp> => Option<String>, decode_nullable_string);
aggregate_wire!(sql_types::Nullable<sql_types::Json> => Option<serde_json::Value>, decode_nullable_json);
aggregate_wire!(sql_types::Nullable<sql_types::Jsonb> => Option<serde_json::Value>, decode_nullable_json);

// Postgres-only SQL types. Their diesel markers live behind diesel's
// postgres_backend, and the orphan rule forbids a downstream crate from
// mapping them, so this crate maps them behind an opt-in feature that keeps
// diesel's Postgres backend off every SQLite-only client. Both render as JSON
// strings on the wire (`Uuid` and `Timestamptz` through `to_string`).
#[cfg(feature = "postgres-types")]
aggregate_wire!(sql_types::Uuid => String, decode_string);
#[cfg(feature = "postgres-types")]
aggregate_wire!(sql_types::Timestamptz => String, decode_string);
#[cfg(feature = "postgres-types")]
aggregate_wire!(sql_types::Nullable<sql_types::Uuid> => Option<String>, decode_nullable_string);
#[cfg(feature = "postgres-types")]
aggregate_wire!(sql_types::Nullable<sql_types::Timestamptz> => Option<String>, decode_nullable_string);

/// Dispatch machinery behind [`Watchable`], keyed on the aggregation marker
/// `M` as a type parameter so the row and scalar impls stay coherent. `R` is
/// the handle's element type: the caller-chosen row type for a row query, and
/// the wire-derived scalar type for an aggregate.
pub trait WatchDispatch<T: Transport, M, R>: Sized {
    /// The live handle this dispatch produces.
    type Handle: LiveHandle;

    /// Subscribe through `client` and return the live handle.
    fn dispatch<'a>(
        self,
        client: &'a ConnettoClient<T>,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend + 'a
    where
        Self: 'a;
}

impl<T, Q, R> WatchDispatch<T, is_aggregate::No, R> for Q
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    Q: QueryFragment<Sqlite> + Clone + Send + 'static,
    Q: for<'query> LoadQuery<'query, diesel::SqliteConnection, R>,
    R: Clone + PartialEq + Send + Sync + 'static,
{
    type Handle = LiveQuery<R>;

    fn dispatch<'a>(
        self,
        client: &'a ConnettoClient<T>,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend + 'a
    where
        Self: 'a,
    {
        client.watch(self)
    }
}

impl<T, Q, V> WatchDispatch<T, is_aggregate::Yes, V> for Q
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    Q: AsQuery + QueryFragment<Sqlite> + Send + 'static,
    Q::Query: SelectionMarker,
    <Q::Query as SelectionMarker>::Selection: Expression,
    <<Q::Query as SelectionMarker>::Selection as Expression>::SqlType: AggregateWire<Value = V>,
    V: Clone + PartialEq + Send + Sync + 'static,
{
    type Handle = LiveValue<V>;

    fn dispatch<'a>(
        self,
        client: &'a ConnettoClient<T>,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend + 'a
    where
        Self: 'a,
    {
        client.watch_value_typed(
            self,
            <<<Q::Query as SelectionMarker>::Selection as Expression>::SqlType as AggregateWire>::decode,
        )
    }
}

/// A typed diesel query that can go live with `query.live(&client)`.
///
/// Implemented for every non-boxed select statement. The handle type is
/// chosen at compile time from the query's aggregation marker: row
/// projections produce a [`LiveQuery`] (annotate the row type on the binding,
/// as with diesel's `load`), scalar aggregates produce a [`LiveValue`] whose
/// value type is derived from the selection's SQL type, so it needs no
/// annotation at all.
pub trait Watchable<T: Transport, R>: Sized {
    /// The live handle this query produces.
    type Handle: LiveHandle;

    /// Subscribe and return the live handle. See
    /// [`ConnettoClient::watch`] and [`ConnettoClient::watch_value`] for the
    /// underlying contracts of the two handle kinds.
    fn live<'a>(
        self,
        client: &'a ConnettoClient<T>,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend + 'a
    where
        Self: 'a;
}

impl<T, Q, R> Watchable<T, R> for Q
where
    T: Transport + MaybeSend + 'static,
    T::Error: core::fmt::Display,
    Q: AsQuery,
    Q::Query: SelectionMarker,
    Q: WatchDispatch<T, <Q::Query as SelectionMarker>::Marker, R>,
{
    type Handle = <Q as WatchDispatch<T, <Q::Query as SelectionMarker>::Marker, R>>::Handle;

    fn live<'a>(
        self,
        client: &'a ConnettoClient<T>,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend + 'a
    where
        Self: 'a,
    {
        self.dispatch(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The decoders follow the wire, not serde strictness: integral floats for
    // integer targets (SUM's accumulator), numeric strings, and null as None.
    #[test]
    fn decoders_follow_wire_rendering() {
        assert_eq!(
            <sql_types::BigInt as AggregateWire>::decode("3").expect("count"),
            3,
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::BigInt> as AggregateWire>::decode("3.0")
                .expect("integral float"),
            Some(3),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::BigInt> as AggregateWire>::decode("null")
                .expect("null"),
            None,
        );
        assert!(
            <sql_types::Nullable<sql_types::BigInt> as AggregateWire>::decode("3.5").is_err(),
            "a fractional value must not silently truncate",
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Numeric> as AggregateWire>::decode("\"12.5\"")
                .expect("numeric string"),
            Some(12.5),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Text> as AggregateWire>::decode("\"low\"")
                .expect("text"),
            Some("low".to_owned()),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Text> as AggregateWire>::decode("null")
                .expect("text null"),
            None,
        );
    }

    // The broadened family, decoded against the exact bytes the server's
    // value_to_json emits (pinned in connetto-server's wire_contract test).
    #[test]
    fn decodes_broadened_family() {
        // Bool: a JSON bool on the re-execution wire, or 0/1 from a local
        // SQLite json_quote.
        assert!(<sql_types::Bool as AggregateWire>::decode("true").expect("true"));
        assert!(!<sql_types::Bool as AggregateWire>::decode("false").expect("false"));
        assert!(<sql_types::Bool as AggregateWire>::decode("1").expect("one is true"));
        assert!(!<sql_types::Bool as AggregateWire>::decode("0").expect("zero is false"));
        assert_eq!(
            <sql_types::Nullable<sql_types::Bool> as AggregateWire>::decode("null")
                .expect("bool null"),
            None,
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Bool> as AggregateWire>::decode("false")
                .expect("bool some"),
            Some(false),
        );
        assert!(
            <sql_types::Bool as AggregateWire>::decode("2").is_err(),
            "a non-boolean integer is not a bool",
        );

        // Non-null numeric and text a custom total aggregate returns.
        assert_eq!(
            <sql_types::Integer as AggregateWire>::decode("42").expect("i32"),
            42_i32,
        );
        assert_eq!(
            <sql_types::SmallInt as AggregateWire>::decode("7").expect("i16"),
            7_i16,
        );
        assert!(
            (<sql_types::Float as AggregateWire>::decode("1.5").expect("f32") - 1.5_f32).abs()
                < f32::EPSILON,
            "f32 decodes",
        );
        assert!(
            (<sql_types::Double as AggregateWire>::decode("1.5").expect("f64") - 1.5_f64).abs()
                < f64::EPSILON,
            "f64 decodes",
        );
        assert_eq!(
            <sql_types::Text as AggregateWire>::decode("\"hi\"").expect("text"),
            "hi",
        );

        // Binary rides through as the server's lossy UTF-8 string, invalid
        // bytes and all (see Trap 3).
        assert_eq!(
            <sql_types::Binary as AggregateWire>::decode("\"hi\"").expect("binary"),
            "hi",
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Binary> as AggregateWire>::decode("\"\u{fffd}a\"")
                .expect("lossy binary"),
            Some("\u{fffd}a".to_owned()),
        );

        // Temporal types arrive as JSON strings, passed through verbatim.
        assert_eq!(
            <sql_types::Timestamp as AggregateWire>::decode("\"2020-01-02 03:04:05\"")
                .expect("timestamp"),
            "2020-01-02 03:04:05",
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Date> as AggregateWire>::decode("\"2020-01-02\"")
                .expect("date"),
            Some("2020-01-02".to_owned()),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Time> as AggregateWire>::decode("null")
                .expect("time null"),
            None,
        );

        // Json and Jsonb decode the raw JSON value; a top-level null is None
        // for the nullable form.
        assert_eq!(
            <sql_types::Jsonb as AggregateWire>::decode("{\"k\":1}").expect("jsonb"),
            serde_json::json!({ "k": 1 }),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Json> as AggregateWire>::decode("[1,2]")
                .expect("json array"),
            Some(serde_json::json!([1, 2])),
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Json> as AggregateWire>::decode("null")
                .expect("json null"),
            None,
        );
    }

    // The Postgres-only types decode as string passthroughs under the opt-in
    // feature, matching value_to_json's to_string rendering.
    #[cfg(feature = "postgres-types")]
    #[test]
    fn decodes_postgres_types() {
        assert_eq!(
            <sql_types::Uuid as AggregateWire>::decode("\"550e8400-e29b-41d4-a716-446655440000\"",)
                .expect("uuid"),
            "550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(
            <sql_types::Nullable<sql_types::Timestamptz> as AggregateWire>::decode(
                "\"2020-01-02 03:04:05 UTC\"",
            )
            .expect("timestamptz"),
            Some("2020-01-02 03:04:05 UTC".to_owned()),
        );
    }
}
