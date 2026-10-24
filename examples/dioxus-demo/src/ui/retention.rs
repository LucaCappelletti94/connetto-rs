//! The retention pane: the replica mirror's footprint and the trim pass.

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::FaBroom;

use super::{ClientSlot, Footprint};

/// The retention pane.
#[component]
pub fn RetentionPane() -> Element {
    let ClientSlot(client_slot) = use_context::<ClientSlot>();
    let client = client_slot.read().clone().expect("mounted with a client");
    let Footprint(footprint) = use_context::<Footprint>();
    let (pages, free) = *footprint.read();
    let kb = pages * 4;
    let tidy_client = client.clone();

    rsx! {
        div { class: "pane",
            h2 {
                Icon { icon: FaBroom, width: 14, height: 14 }
                "retention "
                span { class: "badge trim", "trim" }
            }
            p { "Replica mirror: {pages} pages (~{kb} KB), {free} free to reclaim." }
            p { "Ending a subscription evicts the rows no live subscription still covers, and the trimming pass hands the freed pages back to storage." }
            div { class: "row",
                button {
                    onclick: move |_| {
                        let client = tidy_client.clone();
                        let footprint = footprint;
                        spawn(async move {
                            let mut footprint = footprint;
                            if let Err(err) = client.tidy().await {
                                tracing::error!(error = %err, "free up space failed");
                            }
                            footprint.set(crate::replica_footprint(&client).await);
                        });
                    },
                    Icon { icon: FaBroom, width: 14, height: 14 }
                    "Free up space"
                }
            }
        }
    }
}
