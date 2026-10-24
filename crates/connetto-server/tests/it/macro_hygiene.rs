//! `connetto_schema!` expands beside a caller that imports and uses diesel's
//! `query_dsl::methods` traits, which is what a hand-written schema module
//! does.
//!
//! A missing import is already covered, because each generated body imports the
//! traits it needs anonymously. A colliding one was not: the anonymous import
//! and the caller's named one both offer `filter`, so the call was ambiguous.

mod colliding {
    use diesel::query_dsl::methods::{FilterDsl, SelectDsl};

    connetto_server::connetto_schema! {
        pub struct HygieneSchema;
        id: String => diesel::sql_types::Text,
        audit_row_key: uuid::Uuid => diesel::sql_types::Uuid,
    }

    /// A query the caller builds through its own named imports.
    pub fn revoked_session_ids()
    -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg> + diesel::query_builder::QueryId
    {
        SelectDsl::select(
            FilterDsl::filter(
                connetto_sessions::table,
                diesel::ExpressionMethods::eq(connetto_sessions::revoked, true),
            ),
            connetto_sessions::session_id,
        )
    }

    /// A query the caller builds through its own named imports.
    pub fn one_bans_reason()
    -> impl diesel::query_builder::QueryFragment<diesel::pg::Pg> + diesel::query_builder::QueryId
    {
        SelectDsl::select(
            FilterDsl::filter(
                connetto_bans::table,
                diesel::ExpressionMethods::eq(connetto_bans::user_id, "alice"),
            ),
            connetto_bans::reason,
        )
    }
}

fn sql_of<Q>(query: &Q) -> String
where
    Q: diesel::query_builder::QueryFragment<diesel::pg::Pg> + diesel::query_builder::QueryId,
{
    diesel::debug_query::<diesel::pg::Pg, _>(query).to_string()
}

/// The caller's own query builds beside the session macro's expansion.
#[test]
fn the_auth_macro_survives_a_colliding_import() {
    let caller = sql_of(&colliding::revoked_session_ids());
    assert!(caller.contains("connetto_sessions"), "{caller}");
}

/// The caller's own query builds beside the ban macro's expansion.
#[test]
fn the_ban_macro_survives_a_colliding_import() {
    let caller = sql_of(&colliding::one_bans_reason());
    assert!(caller.contains("connetto_bans"), "{caller}");
}
