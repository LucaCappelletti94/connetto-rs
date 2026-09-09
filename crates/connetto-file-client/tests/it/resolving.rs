//! Step 4: what the resolver answers, and the pin surface it reads.

use connetto_file_client::{ContentError, Resolved};
use connetto_file_core::MimeClass;
use tempfile::tempdir;

use crate::support::{
    RecordingHttp, Scripted, TicketAnswer, attach_content, connected_client, connected_content,
    insert_row_and_pin_album, learn_file_id, offline_client, stage_photo,
};

/// A granted read address, the shape the file server mints for a download.
const READ_URL: &str = "http://files.test/files/ab?t=TOKEN";

/// A granted write address, for the cases that also stage.
const INTENT_URL: &str = "http://files.test/files/ab/intent?t=TOKEN";

/// The bytes every case here works with.
const PHOTO: &[u8] = b"one photograph, resolved four different ways";

/// A file nothing local holds resolves to the URL the server granted.
#[tokio::test]
async fn resolve_answers_a_signed_url_when_nothing_local_holds_the_bytes() {
    let dir = tempdir().expect("temp dir");
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(READ_URL),
    )
    .await;
    let content =
        attach_content(client, &dir.path().join("chunks"), RecordingHttp::default()).await;

    let unknown = connetto_file_core::FileId::from_bytes([7; 32]);
    assert_eq!(
        content.resolve(unknown).await.expect("resolve"),
        Resolved::Remote {
            url: READ_URL.to_owned()
        },
        "the common case is a signed URL and no chunk storage at all"
    );
}

/// Offline with nothing local is the one case that says so.
#[tokio::test]
async fn resolve_answers_unavailable_when_offline_and_nothing_local() {
    let dir = tempdir().expect("temp dir");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content =
        attach_content(client, &dir.path().join("chunks"), RecordingHttp::default()).await;

    let unknown = connetto_file_core::FileId::from_bytes([7; 32]);
    assert_eq!(
        content.resolve(unknown).await.expect("resolve"),
        Resolved::Unavailable,
        "no local bytes and no server to ask"
    );
}

/// An unsent file answers from the chunk store even with a server right there,
/// because the server has never held those bytes.
#[tokio::test]
async fn an_unsent_file_never_answers_a_url() {
    let dir = tempdir().expect("temp dir");
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(READ_URL),
    )
    .await;
    let content =
        attach_content(client, &dir.path().join("chunks"), RecordingHttp::default()).await;
    let file_id = stage_photo(&content, 1, PHOTO, MimeClass::Jpeg).await;

    let resolved = content.resolve(file_id).await.expect("resolve");
    assert!(
        matches!(&resolved, Resolved::Local { bytes, .. } if bytes == PHOTO),
        "an unsent file resolves to its own bytes, got {resolved:?}"
    );
}

/// A pin prefers the bytes it paid to keep, which is the whole point of it.
#[tokio::test]
async fn a_pinned_file_prefers_local_bytes_to_a_url() {
    let dir = tempdir().expect("temp dir");
    // The upload's intent, its commit, then nothing further is needed.
    let http = RecordingHttp::new(vec![(200, br#"{"needed":[]}"#.to_vec()), (200, Vec::new())]);
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(INTENT_URL),
    )
    .await;
    let content = attach_content(client, &dir.path().join("chunks"), http).await;
    let file_id = stage_photo(&content, 1, PHOTO, MimeClass::Jpeg).await;

    assert_eq!(
        content.flush_outbox().await.expect("walk the outbox"),
        1,
        "the file is uploaded, so it is no longer unsent"
    );

    // Without the pin, a file the server holds answers a URL.
    assert!(
        matches!(content.resolve(file_id).await, Ok(Resolved::Remote { .. })),
        "cache with nothing covering it points at the server"
    );

    content
        .pin_content("album", "SELECT content_id FROM photos", "content_id")
        .await
        .expect("pin the album");
    let resolved = content.resolve(file_id).await.expect("resolve");
    assert!(
        matches!(&resolved, Resolved::Local { bytes, .. } if bytes == PHOTO),
        "the pin is what makes the answer local, got {resolved:?}"
    );
}

/// A pin names the files its query returns, and re-evaluates as the rows move.
#[tokio::test]
async fn a_pin_names_the_files_its_query_returns() {
    let dir = tempdir().expect("temp dir");
    let (_client, content) = connected_content(
        dir.path(),
        Scripted::granting(INTENT_URL),
        RecordingHttp::default(),
    )
    .await;

    let first = stage_photo(&content, 1, b"first photo", MimeClass::Jpeg).await;
    content
        .pin_content("album", "SELECT content_id FROM photos", "content_id")
        .await
        .expect("pin the album");
    assert_eq!(
        content.pinned().await.expect("evaluate the pins"),
        [first].into_iter().collect(),
        "the pin names the one row there is"
    );

    let second = stage_photo(&content, 2, b"second photo", MimeClass::Jpeg).await;
    assert_eq!(
        content.pinned().await.expect("evaluate the pins"),
        [first, second].into_iter().collect(),
        "a row joining the set is covered with no re-declaration, which is why the pin is query-shaped"
    );

    assert_eq!(
        content.content_pins().await.expect("list the pins"),
        vec![(
            "album".to_owned(),
            "SELECT content_id FROM photos".to_owned(),
            "content_id".to_owned()
        )]
    );

    content.unpin_content("album").await.expect("unpin");
    assert!(
        content
            .pinned()
            .await
            .expect("evaluate the pins")
            .is_empty(),
        "the pin is gone, so it names nothing"
    );
}

/// A pin naming a column its query does not return is refused when it is made,
/// not on every later evaluation.
#[tokio::test]
async fn a_pin_whose_column_is_not_returned_is_refused() {
    let dir = tempdir().expect("temp dir");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content =
        attach_content(client, &dir.path().join("chunks"), RecordingHttp::default()).await;

    let refused = content
        .pin_content("album", "SELECT id FROM photos", "content_id")
        .await;
    assert!(
        matches!(
            refused,
            Err(ContentError::PinColumnMissing { ref name, ref column })
                if name == "album" && column == "content_id"
        ),
        "the pin names what it could not find, got {refused:?}"
    );
    assert!(
        content
            .content_pins()
            .await
            .expect("list the pins")
            .is_empty(),
        "a refused pin is not recorded"
    );
}

/// A pinned file this device does not hold comes down whole, proves its own
/// identity, and is re-chunked into the store.
#[tokio::test]
async fn fetch_pinned_downloads_verifies_and_rechunks() {
    let dir = tempdir().expect("temp dir");
    let chunks = dir.path().join("chunks");
    // The staging client learns the identity, then a second, empty client
    // fetches it: the first is only how the test knows what to ask for.
    let file_id = learn_file_id(PHOTO).await;

    let http = RecordingHttp::new(vec![(200, PHOTO.to_vec())]);
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(READ_URL),
    )
    .await;
    let content = attach_content(client.clone(), &chunks, http.clone()).await;
    insert_row_and_pin_album(&client, &content, file_id).await;

    assert_eq!(
        content.fetch_pinned().await.expect("fetch the pinned file"),
        vec![file_id],
        "the pinned file arrives"
    );
    assert_eq!(
        http.sent().len(),
        1,
        "one whole-file GET, not a request per chunk"
    );
    let resolved = content.resolve(file_id).await.expect("resolve");
    assert!(
        matches!(&resolved, Resolved::Local { bytes, .. } if bytes == PHOTO),
        "the fetched bytes read back through the chunk store, got {resolved:?}"
    );

    // Nothing further is fetched, because the bytes are already here.
    assert!(
        content
            .fetch_pinned()
            .await
            .expect("fetch again")
            .is_empty(),
        "a second pass over a pin already satisfied costs no request"
    );
}

/// Bytes that are not the file that was asked for are refused rather than
/// stored under its identity.
#[tokio::test]
async fn fetch_pinned_refuses_bytes_that_are_not_the_file() {
    let dir = tempdir().expect("temp dir");
    // The staging client learns the identity, then a second, empty client
    // fetches it: the first is only how the test knows what to ask for.
    let file_id = learn_file_id(PHOTO).await;

    let http = RecordingHttp::new(vec![(200, b"somebody else's bytes entirely".to_vec())]);
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::granting(READ_URL),
    )
    .await;
    let content = attach_content(client.clone(), &dir.path().join("chunks"), http).await;
    insert_row_and_pin_album(&client, &content, file_id).await;

    let refused = content.fetch_pinned().await;
    assert!(
        matches!(refused, Err(ContentError::IdentityMismatch { expected, .. }) if expected == file_id),
        "the download proves itself or it is refused, got {refused:?}"
    );
    assert!(
        matches!(content.resolve(file_id).await, Ok(Resolved::Remote { .. })),
        "nothing was recorded under the identity that was asked for"
    );
}

/// A refused read ticket is a refusal, not an absence.
#[tokio::test]
async fn a_refused_read_ticket_is_reported() {
    let dir = tempdir().expect("temp dir");
    let client = connected_client(
        &dir.path().join("replica.sqlite"),
        Scripted::new([TicketAnswer::Refuse(
            connetto_core::messages::CONTENT_TICKET_REFUSED.to_owned(),
        )]),
    )
    .await;
    let content =
        attach_content(client, &dir.path().join("chunks"), RecordingHttp::default()).await;

    let unknown = connetto_file_core::FileId::from_bytes([7; 32]);
    let refused = content.resolve(unknown).await;
    assert!(
        matches!(refused, Err(ContentError::TicketRefused { file_id }) if file_id == unknown),
        "a caller learns it may not read, and learns nothing else, got {refused:?}"
    );
}
