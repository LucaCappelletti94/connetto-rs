//! The photos pane: the staged rows with their thumbnails, the file pick,
//! the pin controls, the refused uploads and the lost bytes.

use std::cell::RefCell;
use std::rc::Rc;

use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::{
    FaBroom, FaDownload, FaEraser, FaImages, FaLinkSlash, FaRotateRight, FaThumbtack,
};
use rosetta_uuid::Uuid;

use crate::photos;
use connetto_dioxus::use_live;
use connetto_file_core::FileId;
use diesel::prelude::*;

use super::{ClientSlot, ContentSlot, UserId};

/// The photos pane.
#[component]
pub fn PhotosPane() -> Element {
    let ClientSlot(client_slot) = use_context::<ClientSlot>();
    let ContentSlot(content_slot) = use_context::<ContentSlot>();
    let client = client_slot.read().clone().expect("mounted with a client");
    let content = content_slot
        .read()
        .clone()
        .expect("mounted with a content lane");
    let UserId(user_id) = use_context::<UserId>();
    let uid = user_id.read().clone().unwrap_or_default();

    let photos_live =
        use_live::<_, _, crate::Photo>(&client, photos::table.order(photos::id.asc()));
    let rows: Vec<crate::Photo> = photos_live.value().read().iter().cloned().collect();
    let photos_error = photos_live.error().read().clone();

    // The display source of each photo's bytes, refetched whenever the rows
    // move so a stale signed ticket never wedges the panel.
    let photo_srcs: Signal<std::collections::HashMap<Uuid, String>> =
        use_signal(std::collections::HashMap::new);
    {
        let key: Vec<Uuid> = rows.iter().map(|row| row.id).collect();
        let snapshot = rows.clone();
        let cc = content.clone();
        let last_key: Rc<RefCell<Option<Vec<Uuid>>>> = use_hook(|| Rc::new(RefCell::new(None)));
        use_effect(move || {
            if last_key.borrow().as_ref() == Some(&key) {
                return;
            }
            *last_key.borrow_mut() = Some(key.clone());
            let cc = cc.clone();
            let rows = snapshot.clone();
            spawn(async move {
                let mut photo_srcs = photo_srcs;
                photo_srcs.set(cc.sources(&rows).await);
            });
        });
    }

    // The content lane's standing: refused uploads and lost bytes, both
    // re-read from what the lane persisted, so a restart hides nothing.
    let feed_status: Signal<Option<String>> = use_signal(|| None);
    let mut refused: Signal<Vec<(FileId, String)>> = use_signal(Vec::new);
    let mut retired: Signal<Vec<FileId>> = use_signal(Vec::new);
    {
        let cc = content.clone();
        use_effect(move || {
            let cc = cc.clone();
            spawn(async move {
                for entry in cc.refused().await {
                    if !refused.read().iter().any(|(id, _)| *id == entry.0) {
                        refused.write().push(entry);
                    }
                }
                for id in cc.retired().await {
                    if !retired.read().contains(&id) {
                        retired.write().push(id);
                    }
                }
            });
        });
    }
    {
        let cc = content.clone();
        use_hook(move || {
            crate::platform::watch_content_events(&cc, feed_status, refused, retired);
        });
    }

    let stage_msg: Signal<Option<String>> = use_signal(|| None);
    let srcs = photo_srcs.read().clone();

    rsx! {
        div { class: "pane",
            h2 {
                Icon { icon: FaImages, width: 14, height: 14 }
                "photos "
                span { class: "badge synced", "synced" }
            }
            p { "count {rows.len()}. Pick an image file to stage and upload through the content route." }
            div { class: "row",
                input {
                    id: "photo-file-input",
                    r#type: "file",
                    accept: "image/*",
                    disabled: uid.is_empty(),
                    onchange: crate::platform::photo_onchange(
                        content.clone(),
                        client.clone(),
                        uid.clone(),
                        stage_msg,
                    ),
                }
            }
            if let Some(msg) = stage_msg.read().clone() {
                p { class: "status", {msg} }
            }
            if let Some(line) = feed_status.read().clone() {
                p { class: "status", "content: {line}" }
            }
            if let Some(err) = photos_error {
                p { class: "error", "photos error: {err}" }
            }
            table {
                thead { tr { th { "id" } th { "state" } th { "image" } } }
                tbody {
                    for (id, state, row_id) in rows
                        .iter()
                        .map(|row| {
                            (
                                row.id.to_string(),
                                row.content_state.as_deref().unwrap_or("pending").to_owned(),
                                row.id,
                            )
                        })
                        .collect::<Vec<_>>()
                    {
                        tr { key: "{id}",
                            td { code { class: "id", title: id.clone(), {crate::short_id(&id)} } }
                            td { {state} }
                            td {
                                if let Some(src) = srcs.get(&row_id) {
                                    img { class: "thumb", src: src.clone() }
                                }
                            }
                        }
                    }
                }
            }
            PinControls {}
            RefusedUploads { refused }
            LostBytes { retired }
        }
    }
}

/// The pin controls: pin, unpin, fetch and tidy on every platform.
#[component]
fn PinControls() -> Element {
    let ContentSlot(content_slot) = use_context::<ContentSlot>();
    let content = content_slot
        .read()
        .clone()
        .expect("mounted with a content lane");
    let mut message: Signal<Option<String>> = use_signal(|| None);
    let pin = content.clone();
    let unpin = content.clone();
    let fetch = content.clone();
    let tidy = content.clone();

    let fetch_tidy_controls: Element = rsx! {
        button {
            onclick: move |_| {
                let cc = fetch.clone();
                spawn(async move {
                    message.set(Some(cc.fetch_pinned().await));
                });
            },
            Icon { icon: FaDownload, width: 14, height: 14 }
            "Fetch pinned"
        }
        button {
            onclick: move |_| {
                let cc = tidy.clone();
                spawn(async move {
                    message.set(Some(cc.tidy().await));
                });
            },
            Icon { icon: FaBroom, width: 14, height: 14 }
            "Free up content storage"
        }
    };

    rsx! {
        div { class: "row",
            button {
                onclick: move |_| {
                    let cc = pin.clone();
                    spawn(async move {
                        message.set(Some(cc.pin().await));
                    });
                },
                Icon { icon: FaThumbtack, width: 14, height: 14 }
                "Pin all photos"
            }
            button {
                onclick: move |_| {
                    let cc = unpin.clone();
                    spawn(async move {
                        message.set(Some(cc.unpin().await));
                    });
                },
                Icon { icon: FaLinkSlash, width: 14, height: 14 }
                "Unpin photos"
            }
            {fetch_tidy_controls}
        }
        if let Some(msg) = message.read().clone() {
            p { class: "status", {msg} }
        }
    }
}

/// The refused uploads, each with a retry that clears its refusal.
#[component]
fn RefusedUploads(refused: Signal<Vec<(FileId, String)>>) -> Element {
    let ContentSlot(content_slot) = use_context::<ContentSlot>();
    let content = content_slot
        .read()
        .clone()
        .expect("mounted with a content lane");
    let entries = refused.read().clone();
    if entries.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "confirm",
            p { "Refused uploads" }
            for (fid, detail) in entries {
                div { key: "{crate::short_hex(fid.as_bytes())}",
                    p { class: "status", "{crate::short_hex(fid.as_bytes())}: {detail}" }
                    button {
                        onclick: {
                            let cc = content.clone();
                            move |_| {
                                let cc = cc.clone();
                                let mut refused = refused;
                                spawn(async move {
                                    match cc.retry(fid).await {
                                        Ok(_) => refused.write().retain(|(id, _)| *id != fid),
                                        Err(err) => tracing::error!(error = %err, "retry refused upload failed"),
                                    }
                                });
                            }
                        },
                        Icon { icon: FaRotateRight, width: 14, height: 14 }
                        "Retry"
                    }
                }
            }
        }
    }
}

/// The files whose unsent bytes were lost, acknowledged with a forget.
#[component]
fn LostBytes(retired: Signal<Vec<FileId>>) -> Element {
    let ContentSlot(content_slot) = use_context::<ContentSlot>();
    let content = content_slot
        .read()
        .clone()
        .expect("mounted with a content lane");
    let ids = retired.read().clone();
    if ids.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "confirm",
            p { "Bytes lost. These files' chunks are unreadable and their rows still exist. Acknowledge to clear the record." }
            for id in ids.clone() {
                p { class: "status", {crate::short_hex(id.as_bytes())} }
            }
            button {
                onclick: move |_| {
                    let ids = ids.clone();
                    let cc = content.clone();
                    let mut retired = retired;
                    spawn(async move {
                        match cc.forget(&ids).await {
                            Ok(_) => {
                                let mut held = retired.read().to_vec();
                                held.retain(|id| !ids.contains(id));
                                retired.set(held);
                            }
                            Err(err) => tracing::error!(error = %err, "forget lost bytes failed"),
                        }
                    });
                },
                Icon { icon: FaEraser, width: 14, height: 14 }
                "Acknowledge all"
            }
        }
    }
}
