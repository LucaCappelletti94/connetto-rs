//! The reclaim half of the pin surface: what `tidy_content` spares and what
//! it sweeps.

use connetto_file_client::{ContentClient, FsStore};
use connetto_file_core::{FileId, MimeClass};
use tempfile::tempdir;

use crate::staging::walk_files;
use crate::support::{
    RecordingHttp, Scripted, assert_local, assert_remote, attach_content, connected_client,
    stage_photo,
};

/// The granted write address every upload in this module runs under.
const INTENT_URL: &str = "http://files.test/files/aa/intent?t=TOKEN";

/// A scripted upload: the intent answer asking for one chunk, the chunk's 204,
/// and the commit's 200.
fn one_chunk_upload() -> Vec<(u16, Vec<u8>)> {
    vec![(200, br#"{"needed":[]}"#.to_vec()), (200, Vec::new())]
}

/// The three file identities the tidy scenario stages.
struct TidyArrangement {
    /// A file that was uploaded but not pinned, so tidy evicts it.
    cached: FileId,
    /// A file that was uploaded and pinned under "one-photo", so tidy spares it.
    pinned: FileId,
    /// A file that was never uploaded, so tidy always spares it.
    unsent: FileId,
}

/// Stages a cached photo, a pinned photo, and an unsent photo; flushes the
/// outbox after the first two uploads and pins the second photo.
///
/// Returns the three identities so the tidy test can assert on each outcome
/// without rebuilding the arrangement inline.
async fn arrange_tidy_scenario(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
) -> TidyArrangement {
    let cached = stage_photo(content, 1, b"a cached photo", MimeClass::Jpeg).await;
    let pinned = stage_photo(content, 2, b"a pinned photo", MimeClass::Jpeg).await;
    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        2,
        "both uploads land, so both files are cache from here"
    );
    let unsent = stage_photo(content, 3, b"a photo still waiting", MimeClass::Jpeg).await;
    content
        .pin_content(
            "one-photo",
            "SELECT content_id FROM photos WHERE id = 2",
            "content_id",
        )
        .await
        .expect("pin the second photo");
    TidyArrangement {
        cached,
        pinned,
        unsent,
    }
}

/// The file identities used to prove that chunk sharing survives eviction.
struct SharedChunkScenario {
    /// The shorter file whose chunks overlap with `kept`, evicted by tidy.
    evicted: FileId,
    /// The longer file that survives the tidy pass.
    kept: FileId,
    /// The bytes of `kept`, for the post-reassembly assertion.
    kept_bytes: Vec<u8>,
}

/// Stages two files where the shorter is a prefix of the longer, so they share
/// at least one chunk, then returns both identities and the longer file's bytes.
///
/// Also asserts that both files are multi-chunk and have different identities,
/// so the sharing is structural rather than incidental.
async fn arrange_shared_chunk_scenario(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    chunks: &std::path::Path,
) -> SharedChunkScenario {
    let shared = pseudorandom(0x5EED, 12 * 1024 * 1024);
    let mut extended = shared.clone();
    extended.extend_from_slice(&pseudorandom(0xFEED, 64 * 1024));
    let evicted = stage_photo(content, 1, &shared, MimeClass::Generic).await;
    let kept = stage_photo(content, 2, &extended, MimeClass::Generic).await;
    assert_ne!(evicted, kept, "the two files have different identities");
    let before = crate::staging::walk_files(chunks).len();
    assert!(
        before > 2,
        "both files are multi-chunk, so the sharing is real rather than incidental, got {before}"
    );
    SharedChunkScenario {
        evicted,
        kept,
        kept_bytes: extended,
    }
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
    let arr = arrange_tidy_scenario(&content).await;

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
    assert_local(&content, arr.pinned, "the pin kept its bytes local").await;
    assert_local(
        &content,
        arr.unsent,
        "unsent bytes cannot be refetched, so they are never swept",
    )
    .await;
    // The evicted one has no manifest here any more, so the only answer left
    // is the server's.
    assert_remote(
        &content,
        arr.cached,
        "the evicted file is cache, refetchable by construction",
    )
    .await;
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
    let scenario = arrange_shared_chunk_scenario(&content, &chunks).await;

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
    assert_survivor_intact(&content, &scenario).await;
}

/// Asserts the pinned file still reads whole from the chunk store and the
/// evicted one no longer has a manifest here.
async fn assert_survivor_intact(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    scenario: &SharedChunkScenario,
) {
    assert_local(
        content,
        scenario.kept,
        "the survivor still reads from the chunk store, so the chunks it shared were spared",
    )
    .await;
    let bytes = content
        .bytes(scenario.kept)
        .await
        .expect("read the surviving file")
        .expect("its bytes are local");
    assert_eq!(
        bytes, scenario.kept_bytes,
        "the surviving file reads back whole, so the chunks it shared with the evicted one are still there"
    );
    assert_remote(
        content,
        scenario.evicted,
        "the evicted file has no manifest here any more",
    )
    .await;
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
