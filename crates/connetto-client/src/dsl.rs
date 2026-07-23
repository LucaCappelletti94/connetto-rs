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
//! JSON strings. A custom aggregate declared with diesel's function macros
//! participates automatically as long as its SQL type maps.
//!
//! Boxed queries (`.into_boxed()`) erase their select clause into a trait
//! object, so no type-level marker survives boxing. Dynamic queries use the
//! explicit, runtime-guarded [`ConnettoClient::watch`] and
//! [`ConnettoClient::watch_value`] instead.

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

/// Parse one server push into a JSON value.
fn json_value(json: &str) -> Result<serde_json::Value, ClientError> {
    serde_json::from_str(json).map_err(|e| ClientError::Session(e.to_string()))
}

/// An integer from a JSON number or numeric string, tolerating the float
/// rendering the server's `SUM` accumulator produces for integer columns
/// (`"3.0"` for 3).
fn lenient_i64(value: &serde_json::Value) -> Option<i64> {
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

/// A float from a JSON number or numeric string (`NUMERIC` extremes arrive as
/// strings on the wire).
fn lenient_f64(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

/// Wire mapping for one aggregate selection's SQL type: the decoded value
/// type and the decoder that follows the server's JSON rendering rules.
///
/// Implemented for the SQL types the server-maintained aggregate family
/// produces. The nullable impls decode JSON `null` (the empty-set value of
/// `AVG` and the extremes) as `None`.
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

impl AggregateWire for sql_types::BigInt {
    type Value = i64;

    fn decode(json: &str) -> Result<i64, ClientError> {
        lenient_i64(&json_value(json)?)
            .ok_or_else(|| ClientError::Session(format!("expected an integer, got {json}")))
    }
}

/// Decode a nullable integer push, converting through `i64`.
fn decode_nullable_int<I: TryFrom<i64>>(json: &str) -> Result<Option<I>, ClientError> {
    let value = json_value(json)?;
    if value.is_null() {
        return Ok(None);
    }
    lenient_i64(&value)
        .and_then(|i| I::try_from(i).ok())
        .map(Some)
        .ok_or_else(|| ClientError::Session(format!("expected an integer, got {json}")))
}

impl AggregateWire for sql_types::Nullable<sql_types::SmallInt> {
    type Value = Option<i16>;

    fn decode(json: &str) -> Result<Option<i16>, ClientError> {
        decode_nullable_int(json)
    }
}

impl AggregateWire for sql_types::Nullable<sql_types::Integer> {
    type Value = Option<i32>;

    fn decode(json: &str) -> Result<Option<i32>, ClientError> {
        decode_nullable_int(json)
    }
}

impl AggregateWire for sql_types::Nullable<sql_types::BigInt> {
    type Value = Option<i64>;

    fn decode(json: &str) -> Result<Option<i64>, ClientError> {
        decode_nullable_int(json)
    }
}

/// Decode a nullable float push.
fn decode_nullable_f64(json: &str) -> Result<Option<f64>, ClientError> {
    let value = json_value(json)?;
    if value.is_null() {
        return Ok(None);
    }
    lenient_f64(&value)
        .map(Some)
        .ok_or_else(|| ClientError::Session(format!("expected a number, got {json}")))
}

impl AggregateWire for sql_types::Nullable<sql_types::Float> {
    type Value = Option<f32>;

    fn decode(json: &str) -> Result<Option<f32>, ClientError> {
        // Intended narrowing: the column's declared SQL type is a 4-byte
        // float, so the app's own model already accepts this precision.
        #[allow(clippy::cast_possible_truncation)]
        Ok(decode_nullable_f64(json)?.map(|f| f as f32))
    }
}

impl AggregateWire for sql_types::Nullable<sql_types::Double> {
    type Value = Option<f64>;

    fn decode(json: &str) -> Result<Option<f64>, ClientError> {
        decode_nullable_f64(json)
    }
}

impl AggregateWire for sql_types::Nullable<sql_types::Numeric> {
    type Value = Option<f64>;

    fn decode(json: &str) -> Result<Option<f64>, ClientError> {
        decode_nullable_f64(json)
    }
}

impl AggregateWire for sql_types::Nullable<sql_types::Text> {
    type Value = Option<String>;

    fn decode(json: &str) -> Result<Option<String>, ClientError> {
        match json_value(json)? {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => Ok(Some(s)),
            other => Err(ClientError::Session(format!(
                "expected a string, got {other}"
            ))),
        }
    }
}

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
        client.watch_value_decoded(
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
}
