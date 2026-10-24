//! Shared public rows stay readable across account replicas.

use connetto_client::{ClientBuilder, ClientEvent, ConnettoConnection, DataDir, SyncSchema};
use connetto_core::messages::{BulkMessage, SnapshotPatch};
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::IncomingFrame;
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const SCHEMA: &str = "CREATE TABLE vocabulary (id INT PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE notes (id INT PRIMARY KEY, vocabulary_id INT NOT NULL, owner TEXT NOT NULL);
ALTER TABLE vocabulary ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;";
const POLICIES: &str = "CREATE POLICY vocabulary_read ON vocabulary FOR SELECT USING (id > 0);
CREATE POLICY notes_read ON notes FOR SELECT USING (owner = current_setting('app.user_id', true));";

diesel::table! {
    /// The public vocabulary reader.
    vocabulary (id) {
        /// Vocabulary key.
        id -> BigInt,
        /// Vocabulary label.
        label -> Text,
    }
}

diesel::table! {
    /// The account's private notes reader.
    notes (id) {
        /// Note key.
        id -> BigInt,
        /// Vocabulary key.
        vocabulary_id -> BigInt,
        /// Note owner.
        owner -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(vocabulary, notes);

fn schema() -> SyncSchema {
    SyncSchema::new(
        connetto_schema::translate_shared::<String, connetto_core::bots::TextIds>(
            SCHEMA,
            POLICIES,
            &["vocabulary"],
        )
        .expect("translate the shared vocabulary"),
    )
}

fn payload(owner: &str, vocabulary_id: i64) -> Vec<u8> {
    let word =
        Insert::<_, String, Vec<u8>>::from(SimpleTable::new("vocabulary", &["id", "label"], &[0]))
            .set(0, Value::Integer(vocabulary_id))
            .unwrap()
            .set(1, Value::Text(format!("word-{vocabulary_id}")))
            .unwrap();
    let note = Insert::<_, String, Vec<u8>>::from(SimpleTable::new(
        "notes",
        &["id", "vocabulary_id", "owner"],
        &[0],
    ))
    .set(0, Value::Integer(1))
    .unwrap()
    .set(1, Value::Integer(vocabulary_id))
    .unwrap()
    .set(2, Value::Text(owner.to_owned()))
    .unwrap();
    let bytes = PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(word)
        .insert(note)
        .build();
    zstd::encode_all(bytes.as_slice(), 3).unwrap()
}

async fn open(
    directory: &std::path::Path,
    keys: super::support::SharedKeys,
    owner: &str,
    schema: SyncSchema,
    seed: Option<i64>,
) -> ConnettoConnection<FakeTransport> {
    let frames = seed.map(|id| {
        IncomingFrame::Bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            "shared-read-proof".to_owned(),
            payload(owner, id),
        )))
    });
    let mut client = ClientBuilder::new(
        schema,
        super::support::Once::new(FakeTransport::accepting_then_delivering(frames)),
    )
    .signed_in(super::support::held(owner))
    .durable(
        DataDir::new(directory.to_path_buf()),
        keys,
        connetto_client::MemoryRefreshStore::default(),
    )
    .connect_driven()
    .await
    .expect("open account replica");
    client
        .subscribe("shared-read-proof", "SELECT * FROM vocabulary")
        .await
        .expect("subscribe to vocabulary");
    if seed.is_some() {
        for _ in 0..4 {
            if matches!(
                client.pump_one().await.expect("apply server frame"),
                ClientEvent::SnapshotApplied { .. }
            ) {
                return client;
            }
        }
        panic!("the snapshot was not applied");
    }
    client
}

fn words(client: &mut ConnettoConnection<FakeTransport>) -> Vec<(i64, String)> {
    vocabulary::table
        .order(vocabulary::id)
        .load(client.conn())
        .unwrap()
}

#[tokio::test]
async fn two_accounts_read_one_public_store_and_join_their_private_rows() {
    let directory = tempfile::tempdir().unwrap();
    let keys = super::support::SharedKeys::default();
    let mut alice = open(directory.path(), keys.clone(), "alice", schema(), Some(1)).await;
    assert_eq!(words(&mut alice), [(1, "word-1".to_owned())]);
    let mut bob = open(directory.path(), keys.clone(), "bob", schema(), Some(2)).await;
    assert_eq!(
        words(&mut bob),
        [(1, "word-1".to_owned()), (2, "word-2".to_owned())]
    );
    let joined: Vec<(String, String)> = notes::table
        .inner_join(vocabulary::table.on(notes::vocabulary_id.eq(vocabulary::id)))
        .select((notes::owner, vocabulary::label))
        .load(bob.conn())
        .unwrap();
    assert_eq!(joined, [("bob".to_owned(), "word-2".to_owned())]);
    assert_eq!(
        words(&mut alice),
        [(1, "word-1".to_owned()), (2, "word-2".to_owned())]
    );
    drop((alice, bob));
    let mut reopened = open(directory.path(), keys, "alice", schema(), None).await;
    assert_eq!(
        words(&mut reopened),
        [(1, "word-1".to_owned()), (2, "word-2".to_owned())]
    );
}

#[tokio::test]
async fn disabling_sharing_keeps_each_accounts_public_rows_in_its_own_replica() {
    let directory = tempfile::tempdir().unwrap();
    let keys = super::support::SharedKeys::default();
    let mut alice = open(
        directory.path(),
        keys.clone(),
        "alice",
        schema().with_shared_store(false),
        Some(1),
    )
    .await;
    let mut bob = open(
        directory.path(),
        keys,
        "bob",
        schema().with_shared_store(false),
        Some(2),
    )
    .await;
    assert_eq!(words(&mut alice), [(1, "word-1".to_owned())]);
    assert_eq!(words(&mut bob), [(2, "word-2".to_owned())]);
}
