//! The reclaim half of the pin surface: what `tidy_content` spares and what
//! it sweeps.

use connetto_file_client::Resolved;
use connetto_file_core::{FileId, MimeClass};
use diesel::prelude::*;
use tempfile::tempdir;

use crate::staging::walk_files;
use crate::support::{RecordingHttp, Scripted, attach_content, connected_client, photos};

/// The granted write address every upload in this module runs under.
const INTENT_URL: &str = "http://files.test/files/aa/intent?t=TOKEN";

/// A scripted upload: the intent answer asking for one chunk, the chunk's 204,
/// and the commit's 200.
fn one_chunk_upload() -> Vec<(u16, Vec<u8>)> {
    vec![(200, br#"{"needed":[]}"#.to_vec()), (200, Vec::new())]
}

/// Stages `bytes` as photo `id` and returns its identity.
async fn stage_photo(
    content: &connetto_file_client::ContentClient<
        Scripted,
        connetto_file_client::FsStore,
        RecordingHttp,
    >,
    id: i32,
    bytes: &[u8],
    mime: MimeClass,
) -> FileId {
    let (file_id, ()) = content
        .stage(bytes, mime, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(id),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage a photo");
    file_id
}

/// A pin and an unsent entry each keep their bytes, and a cached file that
/// neither covers is swept.
#[tokio::test]
async fn tidy_spares_unsent_and_pinned_and_evicts_the_rest() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    // Two uploads, each answered with an empty needed list so no chunk PUT is
    // required, then a commit.
    let mut replies = one_chunk_upload();
    replies.extend(one_chunk_upload());
    let http = RecordingHttp::new(replies);
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(INTENT_URL),
    )
    .await;
    let content = attach_content(client.clone(), &chunks, http).await;

    let cached = stage_photo(&content, 1, b"a cached photo", MimeClass::Jpeg).await;
    let pinned = stage_photo(&content, 2, b"a pinned photo", MimeClass::Jpeg).await;
    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        2,
        "both uploads land, so both files are cache from here"
    );
    let unsent = stage_photo(&content, 3, b"a photo still waiting", MimeClass::Jpeg).await;

    content
        .pin_content(
            "one-photo",
            "SELECT content_id FROM photos WHERE id = 2",
            "content_id",
        )
        .await
        .expect("pin the second photo");

    assert_eq!(
        content.tidy_content().await.expect("tidy"),
        1,
        "only the cached file nothing covers is evicted"
    );

    assert_eq!(
        walk_files(&chunks).len(),
        2,
        "the pinned file's chunk and the unsent file's chunk are both still on disk"
    );
    assert!(
        matches!(
            content
                .resolve(pinned)
                .await
                .expect("resolve the pinned file"),
            Resolved::Local { .. }
        ),
        "the pin kept its bytes local"
    );
    assert!(
        matches!(
            content
                .resolve(unsent)
                .await
                .expect("resolve the unsent file"),
            Resolved::Local { .. }
        ),
        "unsent bytes cannot be refetched, so they are never swept"
    );
    // The evicted one has no manifest here any more, so the only answer left
    // is the server's.
    assert!(
        matches!(
            content
                .resolve(cached)
                .await
                .expect("resolve the evicted file"),
            Resolved::Remote { .. }
        ),
        "the evicted file is cache, refetchable by construction"
    );
}

/// A chunk two files share survives the eviction of one of them.
///
/// The case a naive sweep gets wrong: deleting every chunk the evicted
/// manifest named would take the surviving file's bytes with it. Content
/// defined chunking is what makes two files share chunks at all, so the two
/// here are one buffer and the same buffer with a tail.
#[tokio::test]
async fn tidy_keeps_a_chunk_two_files_share() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    // Every upload attempt is refused past the deployment's ceiling, which is
    // the permanent refusal: the entries retire and both files become cache,
    // which is the state the sweep acts on.
    let http = RecordingHttp::new(vec![(413, Vec::new()), (413, Vec::new())]);
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(INTENT_URL),
    )
    .await;
    let content = attach_content(client.clone(), &chunks, http).await;

    // Above the 4 MiB maximum chunk of the text class, so the files are
    // chunked rather than stored whole.
    let shared = pseudorandom(0x5EED, 12 * 1024 * 1024);
    let mut extended = shared.clone();
    extended.extend_from_slice(&pseudorandom(0xFEED, 64 * 1024));

    let evicted = stage_photo(&content, 1, &shared, MimeClass::Generic).await;
    let kept = stage_photo(&content, 2, &extended, MimeClass::Generic).await;
    assert_ne!(evicted, kept, "the two files have different identities");

    let before = walk_files(&chunks).len();
    assert!(
        before > 2,
        "both files are multi-chunk, so the sharing is real rather than incidental, got {before}"
    );

    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        0,
        "both are refused rather than sent, so neither is unsent any more"
    );

    content
        .pin_content(
            "longer",
            "SELECT content_id FROM photos WHERE id = 2",
            "content_id",
        )
        .await
        .expect("pin the longer file");

    assert_eq!(
        content.tidy_content().await.expect("tidy"),
        1,
        "the uncovered file is evicted"
    );

    let resolved = content.resolve(kept).await.expect("resolve the survivor");
    assert!(
        matches!(resolved, Resolved::Local { .. }),
        "the survivor still reads from the chunk store, so the chunks it shared were spared, got {resolved:?}"
    );
    let bytes = content
        .bytes(kept)
        .await
        .expect("read the surviving file")
        .expect("its bytes are local");
    assert_eq!(
        bytes, extended,
        "the surviving file reads back whole, so the chunks it shared with the evicted one are still there"
    );
    assert!(
        matches!(content.resolve(evicted).await, Ok(Resolved::Remote { .. })),
        "the evicted file has no manifest here any more"
    );
}

/// A deterministic pseudorandom buffer, so chunk boundaries are reproducible
/// and the data does not compress away.
fn pseudorandom(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}
