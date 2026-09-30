//! A page attached through the builder's `attach()`.
//!
//! The page joins the election, wins it, spawns the smoke worker, and builds
//! its mirror from the same builder value a worker boots from. The worker
//! states who it is signed in as, so the mirror's policy views admit the
//! worker's rows, which is what reading a policy-split row proves.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use connetto_client::dsl::Watchable;
use connetto_client::{ClientBuilder, ClientEvent, ConnettoConnection, LiveQuery};
use connetto_wasm_smoke::BrowserSocket;
use connetto_wasm_smoke::build::{self, Once};
use connetto_wasm_smoke::leader;
use connetto_wasm_smoke::workers::{DEMO_WS_URL, demo_schema};
use connetto_web::builder::{TabTopology, WebClientBuilder};
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    owner_id: String,
    quantity: i64,
}

/// A direct client of the server, signed in with the minted session.
async fn writer(token: String, identity: &str) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect(DEMO_WS_URL)
        .await
        .expect("connect to connetto-server");
    ClientBuilder::new(demo_schema(), Once::new(transport))
        .signed_in(build::held(token, identity))
        .connect_driven()
        .await
        .expect("writer connect")
}

/// Insert one order owned by `identity` and wait for the server's ack.
async fn write_order(
    writer: &mut ConnettoConnection<BrowserSocket>,
    identity: &str,
) -> rosetta_uuid::Uuid {
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values((orders::owner_id.eq(identity), orders::quantity.eq(7_i64)))
        .execute(writer.conn())
        .expect("writer insert");
    let id = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    writer.push().await.expect("push").expect("mutation sent");
    loop {
        let event = writer.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "writer closed early");
        if matches!(event, ClientEvent::MutationApplied { .. }) {
            return id;
        }
    }
}

#[wasm_bindgen_test]
async fn an_attached_tab_reads_the_workers_policy_split_row() {
    harness::relay_worker_breadcrumbs();
    let (token, identity) = common::mint_session().await;
    let mut writer = writer(token, &identity).await;
    let written = write_order(&mut writer, &identity).await;
    writer.close().await.expect("close writer");
    harness::stage("writer committed an order");

    // The worker logs in for itself, and only a tab can answer that request.
    common::play_the_tab();
    let glue = harness::glue_url();
    let leader_lock = format!("connetto-attach-{}", harness::unique_base());
    let tab = WebClientBuilder::new(DEMO_WS_URL, demo_schema())
        .attach(TabTopology {
            leader_lock: &leader_lock,
            glue_url: &glue,
            bootstrap: leader::bootstrap(&glue),
        })
        .await
        .expect("the page attaches to the worker it spawned");
    assert!(
        tab.membership.is_leader(),
        "the only page in the election leads it"
    );
    harness::stage("tab attached");

    let mut live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .select(Order::as_select())
        .live(&tab.client)
        .await
        .expect("tab live query");
    while !live.rows().iter().any(|row| row.id == written) {
        live.changed().await.expect("tab refresh");
    }
    let row = live
        .rows()
        .into_iter()
        .find(|row| row.id == written)
        .expect("the written row");
    assert_eq!(
        row.owner_id, identity,
        "the mirror's policy view admits the worker's own row"
    );
}
