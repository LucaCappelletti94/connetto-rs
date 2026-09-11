//! The exported schema macros expand beside a caller that imports and uses
//! diesel's `query_dsl::methods` traits, which is what a hand-written schema
//! module does.
//!
//! A missing import is already covered, because each generated body imports the
//! traits it needs anonymously. A colliding one was not: the anonymous import
//! and the caller's named one both offer `filter`, so the call was ambiguous.
//!
//! `connetto_watermark_table!` is absent because it calls no `QueryDsl` method,
//! so nothing can collide with it.

mod colliding_auth {
    use diesel::query_dsl::methods::{FilterDsl, SelectDsl};

    connetto_server::connetto_auth_tables!(String, diesel::sql_types::Text);

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
}

mod colliding_ban {
    use diesel::query_dsl::methods::{FilterDsl, SelectDsl};

    connetto_server::connetto_ban_table!(String, diesel::sql_types::Text);

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

/// The session macro's revoke statement and the caller's own query coexist.
#[test]
fn the_auth_macro_survives_a_colliding_import() {
    use connetto_server::authn::schema::ConnettoStoreSchema;

    let revoke = sql_of(&colliding_auth::ConnettoAuthSchema::revoke_update(
        connetto_server::SessionId::from_uuid(uuid::Uuid::nil()),
    ));
    assert!(revoke.contains("connetto_sessions"), "{revoke}");

    let caller = sql_of(&colliding_auth::revoked_session_ids());
    assert!(caller.contains("connetto_sessions"), "{caller}");
}

/// The ban macro's lift statement and the caller's own query coexist.
#[test]
fn the_ban_macro_survives_a_colliding_import() {
    use connetto_server::ConnettoBanSchema;

    let lift = sql_of(&colliding_ban::ConnettoBans::ban_delete(
        &"alice".to_owned(),
    ));
    assert!(lift.contains("connetto_bans"), "{lift}");

    let caller = sql_of(&colliding_ban::one_bans_reason());
    assert!(caller.contains("connetto_bans"), "{caller}");
}
