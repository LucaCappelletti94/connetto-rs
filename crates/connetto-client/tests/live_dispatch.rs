//! Pins the compile-time dispatch of the `live()` verb: the handle type (row
//! [`LiveQuery`] versus scalar [`LiveValue`]) and the scalar's decoded value
//! type are chosen purely by the type system from a built diesel query, so a
//! misrouted query or a wrong value type does not compile.
//!
//! Every assertion here is primarily a compile-time fact (the functions
//! resolve trait impls); the runtime assertions on marker names are a bonus.
//! Known limit, by construction: `BoxedSelectStatement` erases its select
//! clause into `Box<dyn QueryFragment>`, so boxed queries cannot participate
//! and stay on the explicit `watch` and `watch_value` methods.

use connetto_client::dsl::{SelectionMarker, Watchable};
use connetto_client::{LiveQuery, LiveValue};
use connetto_core::transport::LoopbackTransport;
use diesel::dsl;
use diesel::expression::is_aggregate;
use diesel::prelude::*;
use diesel::query_builder::AsQuery;

diesel::table! {
    orders (id) {
        id -> BigInt,
        quantity -> BigInt,
        price -> Double,
        status -> Text,
    }
}

/// Runtime name for an `is_aggregate` marker type, for assertions.
trait MarkerName {
    const NAME: &'static str;
}

impl MarkerName for is_aggregate::Yes {
    const NAME: &'static str = "yes";
}
impl MarkerName for is_aggregate::No {
    const NAME: &'static str = "no";
}
impl MarkerName for is_aggregate::Never {
    const NAME: &'static str = "never";
}

fn marker_of<Q>(_query: &Q) -> &'static str
where
    Q: AsQuery,
    Q::Query: SelectionMarker,
    <Q::Query as SelectionMarker>::Marker: MarkerName,
{
    <<Q::Query as SelectionMarker>::Marker as MarkerName>::NAME
}

/// Compile-time assertion: `live()` on this query resolves to handle `H`.
fn resolves<Q, R, H>(_query: &Q)
where
    Q: Watchable<LoopbackTransport, R, Handle = H>,
{
}

#[test]
fn aggregation_marker_is_reachable_from_built_queries() {
    assert_eq!(marker_of(&orders::table), "no");
    assert_eq!(marker_of(&orders::table.select(orders::id)), "no");
    assert_eq!(
        marker_of(
            &orders::table
                .filter(orders::quantity.gt(0))
                .order(orders::id)
                .select((orders::id, orders::quantity)),
        ),
        "no",
    );
    assert_eq!(marker_of(&orders::table.count()), "yes");
    assert_eq!(
        marker_of(
            &orders::table
                .filter(orders::quantity.gt(0))
                .select(dsl::sum(orders::quantity)),
        ),
        "yes",
    );
}

#[test]
fn live_dispatch_resolves_handle_and_value_types() {
    // Row projections resolve to LiveQuery with the caller-chosen row type.
    resolves::<_, i64, LiveQuery<i64>>(&orders::table.select(orders::id));
    resolves::<_, (i64, i64), LiveQuery<(i64, i64)>>(
        &orders::table
            .filter(orders::quantity.gt(0))
            .order(orders::id)
            .select((orders::id, orders::quantity)),
    );

    // Aggregates resolve to LiveValue with the wire-derived value type:
    // COUNT is an exact integer, SUM maps through diesel's own Numeric
    // SqlType to Option<f64> (matching the server's float accumulator),
    // extremes carry the column's type, all nullable ones as Option.
    resolves::<_, i64, LiveValue<i64>>(&orders::table.count());
    resolves::<_, Option<f64>, LiveValue<Option<f64>>>(
        &orders::table.select(dsl::sum(orders::quantity)),
    );
    resolves::<_, Option<f64>, LiveValue<Option<f64>>>(
        &orders::table.select(dsl::max(orders::price)),
    );
    resolves::<_, Option<String>, LiveValue<Option<String>>>(
        &orders::table.select(dsl::min(orders::status)),
    );
}
