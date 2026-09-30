//! R94 step 7: does the trim pass shrink the browser's OPFS replica file?
//!
//! The pass runs in the browser with no platform gate, so its documented
//! effect is measured here rather than assumed. The suite grows an encrypted
//! replica by several hundred pages, deletes the rows, and runs the pass
//! under a threshold and a budget that must fire.
#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::{ClientBuilder, ConnettoConnection, Gate, ReplicaKey, SyncTuning};
use connetto_wasm_smoke::BrowserSocket;
use connetto_wasm_smoke::build;
use connetto_wasm_smoke::workers::demo_schema;

use diesel::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DB_NAME: &str = "opfs-trim.sqlite";
/// Local rows sized so the growth spans several hundred pages. The payload
/// rides `photos.content_id`, since the policy pins `owner_id` to the caller.
const ROWS: usize = 400;
const PAYLOAD_BYTES: usize = 12_000;

/// A fixed key for this suite. What is under test is the pass, not the codec.
fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5c; ReplicaKey::LEN])
}

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        order_id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        content_id -> diesel::sql_types::Bytea,
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// The bytes OPFS reports for the data file backing `name`, the header sector
/// subtracted so the number is the file as SQLite sees it.
async fn opfs_bytes(name: &str) -> f64 {
    // The pool keeps every file under a random name and writes the real one
    // into the file's first 512 bytes, so the probe scans the pool and matches
    // on the stored name. A missing file answers zero.
    let js = format!(
        "(async () => {{ const root = await navigator.storage.getDirectory(); \
         const opaque = await root.getDirectoryHandle('.opfs-sahpool', {{ create: false }}) \
          .then((dir) => dir.getDirectoryHandle('.opaque', {{ create: false }})); \
         for await (const entry of opaque.values()) {{ if (entry.kind !== 'file') continue; \
         const file = await (await opaque.getFileHandle(entry.name)).getFile(); \
         const head = new Uint8Array(await file.slice(0, 512).arrayBuffer()); \
         if (new TextDecoder().decode(head).split('\\0')[0] === {name:?}) return file.size - 4096; }} \
         return 0; }})()"
    );
    let probe: js_sys::Promise<JsValue> = js_sys::eval(&js)
        .expect("evaluate the OPFS size probe")
        .unchecked_into();
    let value = JsFuture::from(probe)
        .await
        .expect("the OPFS size probe settles");
    value.as_f64().expect("the probe answers a number")
}

/// The replica's page statistics, as `PRAGMA page_count` and
/// `PRAGMA freelist_count` report them.
fn page_stats(conn: &mut ConnettoConnection<BrowserSocket>) -> (i64, i64) {
    (
        conn.conn().page_count(None).expect("page count"),
        conn.conn().freelist_count(None).expect("freelist count"),
    )
}

#[wasm_bindgen_test]
async fn the_trim_pass_shrinks_the_opfs_replica() {
    // Install sahpool as the default VFS, as every other suite here does.
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install sahpool vfs");

    // A bare connection, no pump. The pass is local, and the transport only
    // has to be live so the eviction half of `tidy` runs against the declared
    // subscriptions, of which there are none.
    let (token, user_id) = common::mint_session().await;
    let credential = build::held(token, &user_id);
    // Far from the defaults so the pass must fire. The freelist is most of
    // the file after the delete, and the budget outruns it in one call.
    let tuning = SyncTuning::default()
        .with_trim_threshold(10)
        .with_trim_budget(10_000);
    let mut conn = ClientBuilder::new(demo_schema(), build::server())
        .with_tuning(tuning)
        .signed_in(credential.clone())
        .durable(
            build::SuitePlace::new(DB_NAME, false),
            build::keys_for(&credential, replica_key()).await,
        )
        .with_gate(Gate::off())
        .connect_driven()
        .await
        .expect("client connect");

    let (pages, freelist) = page_stats(&mut conn);
    let bytes_before = opfs_bytes(DB_NAME).await;
    assert_eq!(freelist, 0, "a fresh replica has an empty freelist");

    // One `orders` row the policy admits, which the `photos` foreign key
    // points at, then the payload rows on `photos.content_id`.
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(conn.conn())
        .expect("seed row read")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values((
            orders::owner_id.eq(user_id.as_str()),
            orders::quantity.eq(1_i64),
        ))
        .execute(conn.conn())
        .expect("seed row insert");
    let order_id: rosetta_uuid::Uuid = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(conn.conn())
        .expect("seed row read back")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("minted order id");
    let payload = vec![0x5c_u8; PAYLOAD_BYTES];
    for _ in 0..ROWS {
        diesel::insert_into(photos::table)
            .values((
                photos::order_id.eq(order_id),
                photos::owner_id.eq(user_id.as_str()),
                photos::content_id.eq(&payload),
            ))
            .execute(conn.conn())
            .expect("grow row insert");
    }
    let (grown_pages, grown_freelist) = page_stats(&mut conn);
    let bytes_grown = opfs_bytes(DB_NAME).await;
    assert!(
        grown_pages - pages >= 300,
        "the growth spans several hundred pages, {pages} to {grown_pages}"
    );
    assert!(
        bytes_grown > bytes_before,
        "OPFS reports the growth, {bytes_before} to {bytes_grown}"
    );

    // A delete lands the pages on the freelist and leaves the file alone.
    diesel::delete(photos::table.filter(photos::owner_id.eq(user_id.as_str())))
        .execute(conn.conn())
        .expect("grow row delete");
    diesel::delete(orders::table.filter(orders::id.eq(order_id)))
        .execute(conn.conn())
        .expect("seed row delete");
    let (pages_after_delete, freed) = page_stats(&mut conn);
    let bytes_freed = opfs_bytes(DB_NAME).await;
    assert!(
        pages_after_delete == grown_pages && freed > grown_freelist,
        "the delete frees {freed} of {pages_after_delete} pages onto the freelist"
    );
    assert_eq!(
        bytes_freed, bytes_grown,
        "the delete alone leaves the file at {bytes_freed} bytes"
    );

    // The pass. `tidy` evicts the rows no subscription covers, of which there
    // are none, and then trims the freelist under the gate set above.
    conn.tidy().expect("trim pass");
    let (trimmed_pages, trimmed_freelist) = page_stats(&mut conn);
    let bytes_trimmed = opfs_bytes(DB_NAME).await;

    assert!(
        trimmed_freelist < freed,
        "the pass drains the freelist, {freed} to {trimmed_freelist} of {trimmed_pages} pages"
    );
    assert!(
        trimmed_pages < grown_pages,
        "the pass returns pages to the file, {grown_pages} to {trimmed_pages}"
    );
    assert!(
        bytes_trimmed < bytes_grown,
        "OPFS reports the shrink, {bytes_grown} to {bytes_trimmed} bytes"
    );

    conn.close().await.expect("close");
}
