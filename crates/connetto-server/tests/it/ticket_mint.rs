//! Content ticket mint and refusal-vocabulary tests.

use connetto_core::messages::{
    CONTENT_TICKET_REFUSED, CONTENT_TICKET_SIGNER_ERROR, ContentTicketGrant, ContentVerb,
    ControlMessage, NonFatalError,
};
use connetto_core::traits::Transport;
use connetto_server::ThrottleConfig;
use connetto_test_harness::{Fixture, RosterAuth, WITHHELD_ID};

use super::ticket_shared::{
    BrokenSigner, FILE_ID, OkSigner, open_session_with_handshake, request_ticket, setup_reader,
};

/// A visible file yields a `ContentTicketGrant` carrying the signer's URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visible_file_yields_grant() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let (mut client, server) = open_session_with_handshake(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "alice",
    )
    .await;

    let resp = request_ticket(&mut client, "req-1", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::ContentTicketGrant(ContentTicketGrant { request_id, url }) = resp else {
        panic!("expected ContentTicketGrant, got {resp:?}");
    };
    assert_eq!(request_id, "req-1", "request_id is echoed");
    assert_eq!(
        url,
        format!("https://cdn.example.com/files/{:02x}/alice", FILE_ID[0]),
        "URL comes from OkSigner"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// An invisible file is refused with `CONTENT_TICKET_REFUSED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invisible_file_is_refused() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let (mut client, server) = open_session_with_handshake(
        reader_pool,
        RosterAuth::granting("bob").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "bob",
    )
    .await;

    // The visibility function returns empty for bob, so the ticket is refused.
    let resp = request_ticket(&mut client, "req-2", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    assert_eq!(related_to.as_deref(), Some("req-2"), "request_id echoed");
    assert_eq!(
        detail, CONTENT_TICKET_REFUSED,
        "invisible file uses the shared detail"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// A signer fault yields a distinct detail so a retry is meaningful.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signer_failure_yields_distinct_detail() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let (mut client, server) = open_session_with_handshake(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        BrokenSigner,
        &ThrottleConfig::default(),
        "alice",
    )
    .await;

    // File is visible but the signer is broken.
    let resp = request_ticket(&mut client, "req-4", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    assert_eq!(related_to.as_deref(), Some("req-4"), "request_id echoed");
    assert_eq!(
        detail, CONTENT_TICKET_SIGNER_ERROR,
        "signer failure uses the distinct signer-error detail"
    );
    assert_ne!(
        detail, CONTENT_TICKET_REFUSED,
        "signer failure must be distinguishable from a visibility refusal"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}
