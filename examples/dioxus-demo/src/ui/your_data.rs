//! The your-data pane: export the device's local data to an archive and
//! restore an archive back, the file's version winning every clash.

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::{FaDatabase, FaFileExport};

use super::ContentSlot;

/// The your-data pane.
#[component]
pub fn YourDataPane() -> Element {
    let ContentSlot(content_slot) = use_context::<ContentSlot>();
    let content = content_slot
        .read()
        .clone()
        .expect("mounted with a content lane");

    let export_status: Signal<Option<String>> = use_signal(|| None);
    let import_status = use_signal(|| None);

    let export_msg = export_status.read().clone();
    let import_msg = import_status.read().clone();

    rsx! {
        div { class: "pane",
            h2 {
                Icon { icon: FaDatabase, width: 14, height: 14 }
                "your data "
                span { class: "badge local", "device-only" }
            }
            p { "Save a zip archive of this device's local data. The archive is not encrypted and holds every row the device can read: whoever holds the file holds the data." }
            div { class: "row",
                button {
                    onclick: {
                        let cc = content.clone();
                        move |_| {
                            let cc = cc.clone();
                            let mut export_status = export_status;
                            spawn(async move {
                                export_status.set(Some(
                                    crate::platform::export_data(&cc).await,
                                ));
                            });
                        }
                    },
                    Icon { icon: FaFileExport, width: 14, height: 14 }
                    "Export local data"
                }
            }
            if let Some(message) = export_msg {
                p { class: "status", {message} }
            }
            p { "Restore an archive from this account. The file's version wins every clash." }
            div { class: "row",
                input {
                    id: "import-file-input",
                    r#type: "file",
                    accept: ".zip",
                    onchange: crate::platform::import_onchange(
                        content.clone(),
                        import_status,
                    ),
                }
            }
            if let Some(message) = import_msg {
                p { class: "status", {message} }
            }
        }
    }
}
