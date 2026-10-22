//! The orders pane: the visible rows newest first, the count the server
//! pushes, the add and remove buttons.

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::{FaCartShopping, FaMinus, FaPlus};

use crate::orders;
use connetto_dioxus::use_live;
use diesel::prelude::*;

use super::{ClientSlot, UserId};

/// The orders pane.
#[component]
pub fn OrdersPane() -> Element {
    let ClientSlot(client_slot) = use_context::<ClientSlot>();
    let client = client_slot.read().clone().expect("mounted with a client");
    let UserId(user_id) = use_context::<UserId>();
    let uid = user_id.read().clone().unwrap_or_default();

    let orders_live = use_live::<_, _, crate::Order>(
        &client,
        orders::table.order((orders::created_at.desc(), orders::id.desc())),
    );
    let count = use_live(&client, orders::table.count());
    let counts_by_quantity = use_live(
        &client,
        orders::table
            .group_by(orders::quantity)
            .select((orders::quantity, diesel::dsl::count_star())),
    );

    let rows: Vec<crate::Order> = orders_live.value().read().iter().cloned().collect();
    let sum: i64 = rows.iter().map(|row| row.quantity).sum();
    let count_text = count
        .value()
        .read()
        .map_or_else(|| "pending".to_owned(), |value| value.to_string());
    let rows_error = orders_live.error().read().clone();
    let count_error = count.error().read().clone();
    let grouped_text = grouped_label(&counts_by_quantity.value().read());
    let grouped_error = counts_by_quantity.error().read().clone();
    let newest_id = rows.first().map(|row| row.id);

    let add_uid = uid.clone();
    let add_client = client.clone();
    let remove_client = client.clone();

    rsx! {
        div { class: "pane",
            h2 {
                Icon { icon: FaCartShopping, width: 14, height: 14 }
                "orders "
                span { class: "badge synced", "synced" }
            }
            p { "count {rows.len()}, total quantity {sum}. Newest first. Converges across every window through Postgres." }
            p { "COUNT(*) pushed by the server: " strong { {count_text} } }
            p { "COUNT(*) grouped by quantity: " strong { {grouped_text} } }
            div { class: "row",
                button {
                    class: "primary",
                    disabled: uid.is_empty(),
                    onclick: move |_| {
                        let client = add_client.clone();
                        let identity = add_uid.clone();
                        spawn(async move {
                            let quantity = crate::fresh_quantity();
                            let result = client
                                .with_conn(move |conn| {
                                    diesel::insert_into(orders::table)
                                        .values((
                                            orders::owner_id.eq(identity.as_str()),
                                            orders::quantity.eq(quantity),
                                        ))
                                        .execute(conn.conn())
                                })
                                .await
                                .and_then(|insert| insert.map_err(Into::into));
                            if let Err(err) = result {
                                tracing::error!(error = %err, "order insert failed");
                            }
                        });
                    },
                    Icon { icon: FaPlus, width: 14, height: 14 }
                    "Add order"
                }
                if newest_id.is_some() {
                    button {
                        class: "danger",
                        onclick: move |_| {
                            let Some(id) = newest_id else {
                                return;
                            };
                            let client = remove_client.clone();
                            spawn(async move {
                                let result = client
                                    .with_conn(move |conn| {
                                        diesel::delete(orders::table.filter(orders::id.eq(id)))
                                            .execute(conn.conn())
                                    })
                                    .await
                                    .and_then(|insert| insert.map_err(Into::into));
                                if let Err(err) = result {
                                    tracing::error!(error = %err, "order remove failed");
                                }
                            });
                        },
                        Icon { icon: FaMinus, width: 14, height: 14 }
                        "Remove newest"
                    }
                }
            }
            if let Some(err) = rows_error {
                p { class: "error", "orders error: {err}" }
            }
            if let Some(err) = count_error {
                p { class: "error", "count error: {err}" }
            }
            if let Some(err) = grouped_error {
                p { class: "error", "grouped subscription error: {err}" }
            }
            table {
                thead { tr { th { "id" } th { "quantity" } } }
                tbody {
                    for (id, quantity) in rows
                        .iter()
                        .map(|row| (row.id.to_string(), row.quantity))
                        .collect::<Vec<_>>()
                    {
                        tr { key: "{id}",
                            td { code { class: "id", title: id.clone(), {crate::short_id(&id)} } }
                            td { "{quantity}" }
                        }
                    }
                }
            }
        }
    }
}

/// `quantity: count` pairs in quantity order, or `pending` before the first answer.
fn grouped_label(counts: &std::collections::HashMap<i64, i64>) -> String {
    let mut sorted: Vec<(i64, i64)> = counts.iter().map(|(q, c)| (*q, *c)).collect();
    sorted.sort_unstable();
    if sorted.is_empty() {
        return "pending".to_owned();
    }
    sorted
        .iter()
        .map(|(quantity, count)| format!("{quantity}: {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}
