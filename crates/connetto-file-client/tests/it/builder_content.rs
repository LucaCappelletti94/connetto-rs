//! R94: content through the builder.
//!
//! A build with `with_content(Content::default())` returns a client whose
//! content handle stages a file, and the bytes land in the store the place
//! dictates, in memory or durable beside the replica, the entry row is
//! written in the same transaction, and the staged bytes resolve locally.

use connetto_client::{
    Grant, HeldCredential, MemoryKeyStore, NativeClientBuilder, SyncSchema, TransportFactory,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_file_client::{Content, ContentHandle, MimeClass, Resolved};
use diesel::prelude::*;
use tempfile::tempdir;

use crate::support::{DDL, photos};

/// The same photo table as Postgres holds it.
const PG_DDL: &str = "CREATE TABLE photos (id INT PRIMARY KEY, content_id BYTEA, \
                     content_state TEXT);";

/// The photograph both legs stage.
const PHOTO: &[u8] = b"a photograph's bytes, standing in for one taken in the field";

fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        PG_DDL,
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
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
    let client = NativeClientBuilder::new("ws://127.0.0.1:1", schema())
        .with_dialer(OneShot {
            transport: Some(FakeTransport::accepting_but_silent()),
        })
        .with_content(Content::default())
        .signed_in(
            HeldCredential::new(Grant::new("user:bob"), "bob").expect("the credential holds"),
        )
        .durable(dir.path(), MemoryKeyStore::default())
        .connect()
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
