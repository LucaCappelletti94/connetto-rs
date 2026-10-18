//! R31 in the DB worker: a newer build rebuilds the replica in place and
//! migrates the device-private tier on a connection of its own, both in OPFS
//! under the storage pool, and every handle is released afterwards.
//!
//! Runs in a dedicated worker against real OPFS, because the properties under
//! test are the pool's one-handle bookkeeping and the cipher codec opening
//! the tier on its own, which an in-memory VFS has neither of.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, ContentPlace, Custody, FirstThen, Gate,
    HeldCredential, Located, ReplicaKey, ReplicaPlace, SyncSchema, TierFailure, TierStepError,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{ReplicaKeyStore, Transport};
use connetto_core::{MAJOR_DIRECTIVE, Major, TierBoundary, TierHistory};
use connetto_web::auth::{BuilderKeyStore, IdbKeyStore};
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use std::rc::Rc;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_V1: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const REPLICA_V2: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT, rank INTEGER NOT NULL DEFAULT 0)";
const TIER_V1: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";
const TIER_V2: &str =
    "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT, pinned INTEGER NOT NULL DEFAULT 0)";
const ADD_PINNED: &str = "ALTER TABLE drafts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0";

diesel::table! {
    /// The device-private table at major 1, named bare as an application names it.
    drafts (id) {
        /// Draft identifier, the primary key.
        id -> Integer,
        /// Optional draft body.
        body -> Nullable<Text>,
    }
}

/// One pinned reading, read raw because the major 1 `table!` has no such column.
#[derive(QueryableByName, Debug, PartialEq)]
struct Pinned {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pinned: i32,
}

/// One `user_version` reading, which no `table!` can name.
#[derive(QueryableByName)]
struct UserVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    user_version: i32,
}

/// One schema name from the replica's own catalogue.
#[derive(QueryableByName)]
struct Owner {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

fn major(value: u32) -> Major {
    Major::new(value).expect("a test major is from 1 up")
}

fn first_build() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} 1"),
            "",
            REPLICA_V1,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            Some(TIER_V1),
        )
        .expect("the source declares major 1"),
    )
}

fn second_build() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} 2"),
            "",
            REPLICA_V2,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            Some(TIER_V2),
        )
        .expect("the source declares major 2")
        .with_tier_history(TierHistory::new(
            major(1),
            Some(major(1)),
            vec![TierBoundary::new(major(1), ADD_PINNED)],
        ))
        .expect("the history reaches major 2"),
    )
}

/// A build at `at` with the major 1 replica shape, a tier of `tier`,
/// carrying `history`.
fn build(at: u32, tier: Option<&str>, history: Option<TierHistory>) -> SyncSchema {
    let bundle = SchemaBundle::new(
        format!("{MAJOR_DIRECTIVE} {at}"),
        "",
        REPLICA_V1,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        tier,
    )
    .expect("the source declares its major");
    let bundle = match history {
        Some(history) => bundle
            .with_tier_history(history)
            .expect("the history reaches the build"),
        None => bundle,
    };
    SyncSchema::new(bundle)
}

/// The usual second build, at major 2 with the pinned column and its
/// generated step.
fn build_two(generated: &str) -> SyncSchema {
    build(
        2,
        Some(TIER_V2),
        Some(TierHistory::new(
            major(1),
            Some(major(1)),
            vec![TierBoundary::new(major(1), generated)],
        )),
    )
}

fn tier_major(conn: &mut ConnettoConnection<FakeTransport>) -> i32 {
    // A vendor pragma, which the typed DSL cannot express.
    diesel::sql_query("PRAGMA connetto_local.user_version")
        .get_result::<UserVersion>(conn.conn())
        .expect("read the tier's major")
        .user_version
}

fn pinned(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<Pinned> {
    // The column exists only from major 2, past what the `table!` above names.
    diesel::sql_query("SELECT id, pinned FROM drafts ORDER BY id")
        .load(conn.conn())
        .expect("read the migrated tier")
}

/// A replica at `url` whose tier sits at major 1 with one row.
async fn first_boot(url: &str, key: ReplicaKey) {
    let mut conn = open_at(build(1, Some(TIER_V1), None), url, key, true)
        .await
        .expect("first boot");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(7), drafts::body.eq("kept")))
        .execute(conn.conn())
        .expect("write the tier");
}

/// The replica at exactly `url`, fresh or already there as the test says.
struct At {
    url: String,
    exists: bool,
}

impl ReplicaPlace for At {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        Ok(Located::new(
            name,
            self.url.clone(),
            self.exists,
            ContentPlace::InMemory,
        ))
    }
}

/// A key store holding one key for every record.
struct Holding(ReplicaKey);

impl ReplicaKeyStore for Holding {
    type Error = ClientError;

    fn load(&self, _name: &str) -> impl Future<Output = Result<Option<ReplicaKey>, ClientError>> {
        core::future::ready(Ok(Some(self.0.clone())))
    }

    fn store(
        &self,
        _name: &str,
        _key: &ReplicaKey,
    ) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn clear(&self, _name: &str) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// The replica at `url` under `key` for `schema`, with no transport.
async fn open_at(
    schema: SyncSchema,
    url: &str,
    key: ReplicaKey,
    fresh: bool,
) -> Result<ConnettoConnection<FakeTransport>, ClientError> {
    let share_store = BuilderKeyStore::new(Rc::new(
        IdbKeyStore::open().await.expect("open the key store"),
    ));
    ClientBuilder::new(schema, once(FakeTransport::accepting()))
        .signed_in(
            HeldCredential::new(connetto_client::Grant::new("user:tester"), "tester")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: url.to_owned(),
                exists: !fresh,
            },
            Holding(key),
            share_store,
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
}

/// A newer build migrates the tier alone under the replica key, keeps its
/// rows, records the new major, and leaves no handle behind on either file.
#[wasm_bindgen_test]
async fn a_newer_build_migrates_the_tier_in_the_worker() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-tier-majors.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    {
        let mut conn = open_at(first_build(), &replica_url, key.clone(), true)
            .await
            .expect("first boot");
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(7), drafts::body.eq("kept")))
            .execute(conn.conn())
            .expect("write the tier");
    }
    {
        let mut conn = open_at(second_build(), &replica_url, key, false)
            .await
            .expect("the newer build opens and migrates");
        // The column exists only from major 2, past what the `table!` above names.
        let pinned: Vec<Pinned> = diesel::sql_query("SELECT id, pinned FROM drafts ORDER BY id")
            .load(conn.conn())
            .expect("read the migrated tier");
        assert_eq!(pinned, vec![Pinned { id: 7, pinned: 0 }]);
        // A vendor pragma, which the typed DSL cannot express.
        let tier: UserVersion = diesel::sql_query("PRAGMA connetto_local.user_version")
            .get_result(conn.conn())
            .expect("read the tier's major");
        assert_eq!(tier.user_version, 2);
        let replica: UserVersion = diesel::sql_query("PRAGMA main.user_version")
            .get_result(conn.conn())
            .expect("read the replica's major");
        assert_eq!(replica.user_version, 2, "the replica rebuilt in place");
    }
    // No await between the drop above and the deletes below. A handle the
    // migration or the rebuild left open would trip the pool here.
    storage
        .delete_db(&tier_name)
        .expect("the tier's handles were all released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A failing application step rolls its boundary back in the tier's own
/// transaction and refuses the open with `TierMigration`, leaving the tier
/// at the last committed major and the pool's handles free for the build
/// that migrates the tier for real.
#[wasm_bindgen_test]
async fn a_failing_step_rolls_its_boundary_back_and_refuses_the_open() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-failing-step.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;

    let failing = build_two(ADD_PINNED)
        .with_tier_step(
            major(1),
            |_: &mut SqliteConnection| -> Result<(), TierStepError> {
                Err("the application cannot convert".into())
            },
        )
        .expect("a step at the build's only boundary");

    match open_at(failing, &replica_url, key.clone(), false).await {
        Err(ClientError::TierMigration {
            from,
            to,
            cause: TierFailure::Step(_),
        }) => {
            assert_eq!((from, to), (major(1), major(2)));
        }
        Err(other) => panic!("expected the step's failure, got {other:?}"),
        Ok(_) => panic!("a failed step opened the tier"),
    }

    // The generated ADD COLUMN rolled back with the step, so running it again
    // succeeds instead of finding the column already there.
    {
        let mut conn = open_at(build_two(ADD_PINNED), &replica_url, key.clone(), false)
            .await
            .expect("the tier is still at major 1");
        assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 0 }]);
    }
    storage
        .delete_db(&tier_name)
        .expect("the tier's handles were all released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A generated step that leaves the tier in the wrong shape is refused on
/// the shape check with `TierMigration`, commits nothing, and leaves the
/// pool's handles free, so the build whose step produces the shape still
/// opens.
#[wasm_bindgen_test]
async fn a_step_that_produces_the_wrong_shape_is_refused() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-wrong-shape.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;

    match open_at(
        build_two("ALTER TABLE drafts ADD COLUMN pinned TEXT"),
        &replica_url,
        key.clone(),
        false,
    )
    .await
    {
        Err(ClientError::TierMigration {
            cause: TierFailure::Shape(differences),
            ..
        }) => assert_ne!(differences.len(), 0),
        Err(other) => panic!("expected the shape refusal, got {other:?}"),
        Ok(_) => panic!("a tier of the wrong shape opened"),
    }
    {
        let mut conn = open_at(build_two(ADD_PINNED), &replica_url, key.clone(), false)
            .await
            .expect("nothing of the wrong step committed");
        assert_eq!(tier_major(&mut conn), 2);
    }
    storage
        .delete_db(&tier_name)
        .expect("the tier's handles were all released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A table rebuild inside the generated step lands in the tier on its own
/// connection, keeps the rows, and leaves the replica's catalogue untouched.
#[wasm_bindgen_test]
async fn a_table_rebuild_stays_in_the_tier() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-rebuild-in-tier.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;
    let rebuild = "CREATE TABLE new_drafts (id INTEGER PRIMARY KEY, body TEXT, \
        pinned INTEGER NOT NULL DEFAULT 0); \
        INSERT INTO new_drafts (id, body) SELECT id, body FROM drafts; \
        DROP TABLE drafts; \
        ALTER TABLE new_drafts RENAME TO drafts";

    let mut conn = open_at(build_two(rebuild), &replica_url, key, false)
        .await
        .expect("open");
    assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 0 }]);
    // The system catalogue of the replica, which the typed DSL cannot name.
    let main_tables: Vec<Owner> =
        diesel::sql_query("SELECT name FROM main.sqlite_schema WHERE name LIKE '%drafts%'")
            .load(conn.conn())
            .expect("read the replica's catalogue");
    assert!(
        main_tables.is_empty(),
        "the rebuilt table landed in the replica: {:?}",
        main_tables.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
    storage
        .delete_db(&tier_name)
        .expect("the tier's handle was released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A tier that records a major ahead of the build's is refused with
/// `TierNewer` before any step runs, and the refused open leaves the pool's
/// handles free.
#[wasm_bindgen_test]
async fn a_tier_ahead_of_the_build_is_refused() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-tier-ahead.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;
    {
        let mut conn = open_at(
            build(1, Some(TIER_V1), None),
            &replica_url,
            key.clone(),
            false,
        )
        .await
        .expect("reopen");
        // A vendor pragma, which the typed DSL cannot express.
        conn.conn()
            .batch_execute("PRAGMA connetto_local.user_version = 3")
            .expect("move the tier ahead");
    }
    match open_at(build(1, Some(TIER_V1), None), &replica_url, key, false).await {
        Err(ClientError::TierNewer { recorded, build }) => {
            assert_eq!((recorded, build), (major(3), major(1)));
        }
        Err(other) => panic!("expected TierNewer, got {other:?}"),
        Ok(_) => panic!("a tier ahead of the build opened"),
    }
    storage
        .delete_db(&tier_name)
        .expect("the tier's handles were all released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A tier that records a major older than this build's oldest export is
/// refused with `TierTooOld`, and the refused open leaves the pool's handles
/// free.
#[wasm_bindgen_test]
async fn a_tier_older_than_the_oldest_export_is_refused() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-tier-older.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;
    let three = build(
        3,
        Some(TIER_V2),
        Some(TierHistory::new(
            major(2),
            Some(major(2)),
            vec![TierBoundary::new(major(2), "")],
        )),
    );
    match open_at(three, &replica_url, key, false).await {
        Err(ClientError::TierTooOld { recorded, oldest }) => {
            assert_eq!((recorded, oldest), (major(1), major(2)));
        }
        Err(other) => panic!("expected TierTooOld, got {other:?}"),
        Ok(_) => panic!("a tier no step reaches opened"),
    }
    storage
        .delete_db(&tier_name)
        .expect("the tier's handles were all released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A tier that a later major introduces is created on an existing install
/// that predates it, records the introducing major, and accepts a write.
#[wasm_bindgen_test]
async fn a_tier_a_later_major_introduces_is_created_on_an_existing_install() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-tier-later-major.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    drop(
        open_at(build(1, None, None), &replica_url, key.clone(), true)
            .await
            .expect("first boot without a tier"),
    );
    let two = build(
        2,
        Some(TIER_V1),
        Some(TierHistory::new(major(2), Some(major(2)), Vec::new())),
    );

    let mut conn = open_at(two, &replica_url, key, false)
        .await
        .expect("open the build that adds a tier");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1), drafts::body.eq("new")))
        .execute(conn.conn())
        .expect("write the new tier");
    assert_eq!(tier_major(&mut conn), 2);
    storage
        .delete_db(&tier_name)
        .expect("the tier's handle was released");
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}

/// A tier this install already had, lost from the pool, is never silently
/// recreated and the open fails loudly with the replica's handle back free.
#[wasm_bindgen_test]
async fn a_lost_tier_still_fails_loudly() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r31-lost-tier.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x31; ReplicaKey::LEN]);
    first_boot(&replica_url, key.clone()).await;
    storage.delete_db(&tier_name).expect("lose the tier");

    assert!(
        open_at(build(1, Some(TIER_V1), None), &replica_url, key, false)
            .await
            .is_err(),
        "a tier this install already had is lost, never silently recreated"
    );
    storage
        .delete_db(replica_name)
        .expect("the replica's handle was released");
}
