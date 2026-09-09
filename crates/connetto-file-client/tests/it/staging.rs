//! Step 1 and the boot integrity pass: the same-transaction invariant, and
//! what happens to unsent bytes that are no longer there.

use connetto_file_client::{ContentError, ContentEvent, Resolved};
use connetto_file_core::{FileId, MimeClass};
use diesel::prelude::*;
use tempfile::tempdir;

use crate::support::{RecordingHttp, attach_content, offline_client, photos};

/// The photo bytes every case here stages.
const PHOTO: &[u8] = b"the bytes of one photograph, authored on this device";

/// A staged file commits its manifest, its outbox entry and the row that names
/// it together, and its chunk files are on disk before any of them.
#[tokio::test]
async fn a_staged_file_commits_its_manifest_with_its_row() {
    let dir = tempdir().expect("temp dir");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(
        client.clone(),
        &dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;

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
        .expect("stage the photo");

    let rows: Vec<Vec<u8>> = client
        .with_conn(|conn| {
            photos::table
                .select(photos::content_id)
                .load(conn.conn())
                .expect("read the photo rows")
        })
        .await;
    assert_eq!(
        rows,
        vec![file_id.as_bytes().to_vec()],
        "the row names the file that was staged"
    );
    assert_eq!(
        content.verify_unsent().await.expect("the boot pass runs"),
        Vec::<FileId>::new(),
        "the bytes are on disk, so nothing is lost"
    );
    assert!(
        matches!(
            content.resolve(file_id).await.expect("resolve"),
            Resolved::Local { .. }
        ),
        "an unsent file resolves from the chunk store"
    );
}

/// The invariant step 1 exists for: a failure between the bookkeeping writes
/// and the row write leaves no row, no manifest and no outbox entry.
///
/// Injected rather than asserted on a happy path, because a happy path passes
/// under a broken implementation that writes the manifest outside the
/// transaction.
#[tokio::test]
async fn an_entry_row_never_outlives_its_manifest() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(client.clone(), &chunks, RecordingHttp::default()).await;

    let refused = content
        .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
            // The manifest and the outbox entry are already written at this
            // point, inside the same transaction.
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)?;
            Err::<(), diesel::result::Error>(diesel::result::Error::NotFound)
        })
        .await;
    assert!(
        matches!(refused, Err(ContentError::Replica(_))),
        "the staging call reports the row write's failure, got {refused:?}"
    );

    let rows: i64 = client
        .with_conn(|conn| {
            photos::table
                .count()
                .get_result(conn.conn())
                .expect("count the photo rows")
        })
        .await;
    assert_eq!(rows, 0, "the row rolled back with the transaction");
    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        0,
        "no outbox entry survived, so the walk has nothing to send"
    );
    // The identity is the bytes alone, so staging the same bytes against a
    // throwaway replica names the same file, and asking this one about it
    // proves no manifest survived the rollback.
    let probe_dir = tempdir().expect("temp dir");
    let probe = attach_content(
        offline_client(&probe_dir.path().join("replica.sqlite")),
        &probe_dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let (file_id, ()) = probe
        .stage(PHOTO, MimeClass::Jpeg, |_, _| Ok(()))
        .await
        .expect("stage against a throwaway replica");
    assert!(
        matches!(content.resolve(file_id).await, Ok(Resolved::Unavailable)),
        "no manifest survived the rollback"
    );

    // The bytes themselves are on disk: the chunk files are written before the
    // transaction opens, so a crash orphans a file and never a row. The sweep
    // is what collects them.
    let orphans = walk_files(&chunks);
    assert!(
        !orphans.is_empty(),
        "the chunk files are written ahead of the transaction and outlive its rollback"
    );
}

/// An unsent file whose chunk files are gone loses its outbox entry, keeps its
/// manifest, and says so.
#[tokio::test]
async fn the_boot_pass_retires_an_unsent_file_whose_bytes_are_gone() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(client.clone(), &chunks, RecordingHttp::default()).await;
    let mut events = content.events();

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
        .expect("stage the photo");

    for path in walk_files(&chunks) {
        std::fs::remove_file(&path).expect("remove a chunk file");
    }

    assert_eq!(
        content.verify_unsent().await.expect("the boot pass runs"),
        vec![file_id],
        "the pass names the file whose bytes are gone"
    );
    assert!(
        matches!(
            events.try_recv(),
            Ok(ContentEvent::BytesLost { file_id: named, unreadable })
                if named == file_id && unreadable > 0
        ),
        "the loss is surfaced with the file it belongs to"
    );
    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        0,
        "the entry is retired, so the walk does not spin on bytes that cannot come back"
    );
    // The manifest is kept: it is the record that this device declared the
    // file, and the application's row still names it.
    assert!(
        matches!(content.resolve(file_id).await, Ok(Resolved::Unavailable)),
        "the manifest survives and the bytes do not"
    );
}

/// A chunk file that is present but does not authenticate is as lost as one
/// that is absent, which is why the pass reads rather than probes.
#[tokio::test]
async fn the_boot_pass_counts_a_corrupt_chunk_as_lost() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(client.clone(), &chunks, RecordingHttp::default()).await;

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
        .expect("stage the photo");

    let files = walk_files(&chunks);
    assert_eq!(files.len(), 1, "this photo is one chunk");
    // Same length, so a probe on presence or size sees nothing wrong.
    let original = std::fs::read(&files[0]).expect("read the chunk file");
    std::fs::write(&files[0], vec![0xAA; original.len()]).expect("corrupt the chunk file");

    assert_eq!(
        content.verify_unsent().await.expect("the boot pass runs"),
        vec![file_id],
        "a chunk that will not decrypt is a loss, not a hit"
    );
}

/// Deliberately separate from the loss cases: without this, a pass that
/// reported every file lost would satisfy them all.
#[tokio::test]
async fn the_boot_pass_keeps_an_unsent_file_it_can_read() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(client.clone(), &chunks, RecordingHttp::default()).await;

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
        .expect("stage the photo");

    assert_eq!(
        content.verify_unsent().await.expect("the boot pass runs"),
        Vec::<FileId>::new(),
        "nothing is lost, so nothing is retired"
    );
    // And the entry is still there to be walked.
    let sent = content.flush_outbox().await.expect("walk the outbox");
    assert_eq!(
        sent, 0,
        "the walk found the entry and failed to send it with no transport, rather than finding nothing"
    );
}

/// Every file under `root`, chunk files and any temporary left behind.
pub fn walk_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk_files(&path));
        } else {
            found.push(path);
        }
    }
    found.sort();
    found
}
