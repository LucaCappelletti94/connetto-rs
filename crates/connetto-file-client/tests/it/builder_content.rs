//! R94: content through the builder.
//!
//! A build with `with_content(Content::default())` returns a client whose
//! content handle stages a file, and the bytes land in the store the place
//! dictates, in memory or durable beside the replica, the entry row is
//! written in the same transaction, and the staged bytes resolve locally.

use connetto_client::{
    Grant, HeldCredential, MemoryKeyStore, MemoryRefreshStore, NativeClientBuilder, SyncSchema,
    TransportFactory,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_file_client::{Content, ContentHandle, MimeClass, Resolved};
use diesel::prelude::*;
use tempfile::tempdir;

use crate::support::{DDL, photos};

/// The same photo table as Postgres holds it.
const PG_DDL: &str = "-- connetto:major 1\nCREATE TABLE photos (id INT PRIMARY KEY, \
                     content_state TEXT);";

/// The photograph both legs stage.
const PHOTO: &[u8] = b"a photograph's bytes, standing in for one taken in the field";

fn schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            PG_DDL,
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// The refusal the one-shot dialer hands back after its transport.
#[derive(Debug, thiserror::Error)]
enum DialRefused {
    #[error("the dialer handed out its last transport")]
    Exhausted,
}

/// A dialer that hands out exactly one transport, the one the test provides.
struct OneShot {
    transport: Option<FakeTransport>,
}

impl TransportFactory for OneShot {
    type Transport = FakeTransport;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<FakeTransport, DialRefused>> + Send {
        let transport = self.transport.take().ok_or(DialRefused::Exhausted);
        async move { transport }
    }
}

/// A build without a directory places its content in memory, and the staged
/// file is what its row names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_content_stages_a_file_in_memory() {
    let client = NativeClientBuilder::new("ws://127.0.0.1:1", schema())
        .with_dialer(OneShot {
            transport: Some(FakeTransport::accepting_but_silent()),
        })
        .with_content(Content::default())
        .connect()
        .await
        .expect("the build connects");
    let ContentHandle::InMemory(content) = client.content().expect("the build attached content")
    else {
        panic!("a build without a directory places its content in memory");
    };
    let (file_id, ()) = content
        .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage the file");
    let rows: Vec<Vec<u8>> = client
        .client()
        .with_conn(|conn| {
            photos::table
                .select(photos::content_id)
                .load(conn.conn())
                .expect("read the row")
        })
        .await
        .expect("the client is not locked");
    assert_eq!(
        rows,
        vec![file_id.as_bytes().to_vec()],
        "the staged file is what the row names"
    );
    assert!(
        matches!(
            content
                .resolve(file_id)
                .await
                .expect("resolve the staged file"),
            Resolved::Local { .. }
        ),
        "the staged bytes resolve from the local store"
    );
}

/// A durable build places its content at the content directory beside the
/// replica, and the staged file is what its row names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_content_stages_a_file_durable() {
    let dir = tempdir().expect("a temp dir");
    let client = Box::pin(
        NativeClientBuilder::new("ws://127.0.0.1:1", schema())
            .with_dialer(OneShot {
                transport: Some(FakeTransport::accepting_but_silent()),
            })
            .with_content(Content::default())
            .signed_in(
                HeldCredential::new(Grant::new("user:bob"), "bob").expect("the credential holds"),
            )
            .durable(
                dir.path(),
                MemoryKeyStore::default(),
                MemoryRefreshStore::default(),
            )
            .connect(),
    )
    .await
    .expect("the durable build connects");
    let ContentHandle::Durable(content) = client.content().expect("the build attached content")
    else {
        panic!("a durable build places its content at the content directory");
    };
    let (file_id, ()) = content
        .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage the file");
    let rows: Vec<Vec<u8>> = client
        .client()
        .with_conn(|conn| {
            photos::table
                .select(photos::content_id)
                .load(conn.conn())
                .expect("read the row")
        })
        .await
        .expect("the client is not locked");
    assert_eq!(
        rows,
        vec![file_id.as_bytes().to_vec()],
        "the staged file is what the row names"
    );
    assert!(
        matches!(
            content
                .resolve(file_id)
                .await
                .expect("resolve the staged file"),
            Resolved::Local { .. }
        ),
        "the staged bytes resolve from the content directory"
    );
}

/// A replica-key store shared across builds, so one process can reopen the same replica.
struct SharedKeys(std::sync::Arc<MemoryKeyStore>);

impl connetto_core::traits::ReplicaKeyStore for SharedKeys {
    type Error = connetto_client::ClientError;

    async fn load(&self, name: &str) -> Result<Option<connetto_client::ReplicaKey>, Self::Error> {
        self.0.load(name).await
    }

    async fn store(
        &self,
        name: &str,
        key: &connetto_client::ReplicaKey,
    ) -> Result<(), Self::Error> {
        self.0.store(name, key).await
    }

    async fn clear(&self, name: &str) -> Result<(), Self::Error> {
        self.0.clear(name).await
    }

    fn protection(&self) -> connetto_client::Custody {
        self.0.protection()
    }
}

/// A closed and dropped client releases its replica at once, so the same process reopens it even with a file still unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_client_with_unsent_content_reopens_at_once() {
    let dir = tempdir().expect("a temp dir");
    let keys = std::sync::Arc::new(MemoryKeyStore::default());
    for round in 0..20 {
        let client = Box::pin(
            NativeClientBuilder::new("ws://127.0.0.1:1", schema())
                .with_dialer(OneShot { transport: None })
                .with_content(Content::default())
                .signed_in(
                    HeldCredential::new(Grant::new("user:bob"), "bob")
                        .expect("the credential holds"),
                )
                .durable(
                    dir.path(),
                    SharedKeys(std::sync::Arc::clone(&keys)),
                    MemoryRefreshStore::default(),
                )
                .connect(),
        )
        .await
        .unwrap_or_else(|err| panic!("round {round} reopens the replica: {err}"));
        if round == 0 {
            let ContentHandle::Durable(content) =
                client.content().expect("the build attached content")
            else {
                panic!("a durable build places its content at the content directory");
            };
            content
                .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
                    diesel::insert_into(photos::table)
                        .values((
                            photos::id.eq(1),
                            photos::content_id.eq(file_id.as_bytes().to_vec()),
                        ))
                        .execute(conn)
                        .map(|_| ())
                })
                .await
                .expect("stage the file");
        }
        client.client().close().await;
        drop(client);
    }
}
