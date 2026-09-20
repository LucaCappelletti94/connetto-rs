//! Content ticket mint and refusal-vocabulary tests.

use connetto_core::messages::{
    CONTENT_TICKET_REFUSED, CONTENT_TICKET_SIGNER_ERROR, ContentTicketGrant, ContentVerb,
    ControlMessage, NonFatalError,
};
use connetto_core::traits::Transport;
use connetto_server::ThrottleConfig;
use connetto_test_harness::{Fixture, RosterAuth, WITHHELD_ID};

use super::ticket_shared::{
    ADMITS_ALICE_OR_KEY, ADMITS_ALICE_UNDER_OWN_SETTING, ADMITS_BLANK_IDENTITY, ADMITS_KEY,
    BrokenSigner, FILE_ID, KEY_GRANT, OWN_SETTING, OkSigner, RecordingSigner,
    open_session_named_setting, open_session_with_grants, open_session_with_handshake,
    request_ticket, setup_reader, setup_reader_admitting,
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

/// A caller authenticated only by a share key may still mint a ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_only_caller_gets_a_ticket() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, ADMITS_KEY).await;

    let (mut client, server) = open_session_with_grants(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "holder-k1",
        &[KEY_GRANT],
    )
    .await;

    let resp = request_ticket(&mut client, "req-key", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::ContentTicketGrant(ContentTicketGrant { request_id, url }) = resp else {
        panic!("expected ContentTicketGrant, got {resp:?}");
    };
    assert_eq!(request_id, "req-key", "request_id is echoed");
    assert_eq!(
        url,
        format!(
            "https://cdn.example.com/files/{:02x}/{KEY_GRANT}",
            FILE_ID[0]
        ),
        "the signer sees the share-key subject when no identity resolved"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// An unidentified caller must leave the identity setting unbound, not bound to `""`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unidentified_caller_binds_nothing() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, ADMITS_BLANK_IDENTITY).await;

    let (mut client, server) = open_session_with_grants(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "anon-run",
        &[],
    )
    .await;

    let resp = request_ticket(&mut client, "req-anon", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    assert_eq!(related_to.as_deref(), Some("req-anon"), "request_id echoed");
    assert_eq!(
        detail, CONTENT_TICKET_REFUSED,
        "blank identity must not be admitted"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// A connection that already served an identified caller must not let the next
/// caller, holding nothing, be read as the blank identity.
///
/// Postgres keeps a custom setting's placeholder for the life of the session
/// once anything has bound it, so the pool hands the next caller a connection
/// where an unbound identity reads as `''` rather than NULL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reused_connection_carries_no_blank_identity() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, ADMITS_BLANK_IDENTITY).await;

    // Alice first, so the pooled connection has the setting bound once, which
    // is what leaves the placeholder behind.
    let (mut alice, alice_server) = open_session_with_grants(
        reader_pool.clone(),
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "alice",
        &["user:alice"],
    )
    .await;
    let _ = request_ticket(&mut alice, "req-alice", FILE_ID, ContentVerb::Read).await;
    alice.close().await.expect("close");
    alice_server.await.expect("join").expect("session ok");

    let (mut anon, anon_server) = open_session_with_grants(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "anon-after-alice",
        &[],
    )
    .await;
    let resp = request_ticket(&mut anon, "req-after", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("a caller holding nothing must be refused on a reused connection, got {resp:?}");
    };
    assert_eq!(
        related_to.as_deref(),
        Some("req-after"),
        "request_id echoed"
    );
    assert_eq!(
        detail, CONTENT_TICKET_REFUSED,
        "the placeholder must not read as a blank identity"
    );

    anon.close().await.expect("close");
    anon_server.await.expect("join").expect("session ok");
}

/// Identity and capability subjects are a union on the ticket-mint visibility path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_plus_key_is_the_union() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, ADMITS_ALICE_OR_KEY).await;

    for (session_id, grants, should_grant) in [
        ("alice-only", vec!["user:alice"], true),
        ("key-only", vec![KEY_GRANT], true),
        ("alice-and-key", vec!["user:alice", KEY_GRANT], true),
        ("bob-only", vec!["user:bob"], false),
    ] {
        let (mut client, server) = open_session_with_grants(
            reader_pool.clone(),
            RosterAuth::granting("alice").withholding(WITHHELD_ID),
            OkSigner,
            &ThrottleConfig::default(),
            session_id,
            &grants,
        )
        .await;

        let resp = request_ticket(&mut client, session_id, FILE_ID, ContentVerb::Read).await;
        match (should_grant, resp) {
            (true, ControlMessage::ContentTicketGrant(ContentTicketGrant { request_id, .. })) => {
                assert_eq!(request_id, session_id, "request_id is echoed");
            }
            (false, ControlMessage::NonFatalError(NonFatalError { related_to, detail })) => {
                assert_eq!(related_to.as_deref(), Some(session_id), "request_id echoed");
                assert_eq!(detail, CONTENT_TICKET_REFUSED, "bob is outside the union");
            }
            (expected_grant, other) => {
                panic!("expected should_grant={expected_grant}, got {other:?}");
            }
        }

        client.close().await.expect("close");
        server.await.expect("join").expect("session ok");
    }
}

/// The ticket path honours a deployment that renamed the identity setting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ticket_policy_may_name_its_own_identity_setting() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, ADMITS_ALICE_UNDER_OWN_SETTING).await;

    let (mut client, server) = open_session_named_setting(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &ThrottleConfig::default(),
        "alice",
        &["user:alice"],
        OWN_SETTING,
    )
    .await;

    let resp = request_ticket(&mut client, "req-own-setting", FILE_ID, ContentVerb::Read).await;

    let ControlMessage::ContentTicketGrant(ContentTicketGrant { request_id, url }) = resp else {
        panic!("expected ContentTicketGrant, got {resp:?}");
    };
    assert_eq!(request_id, "req-own-setting", "request_id is echoed");
    assert_eq!(
        url,
        format!("https://cdn.example.com/files/{:02x}/alice", FILE_ID[0]),
        "the ticket path uses the deployment's named setting"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// The mint receives the caller's share keys, and an absent half stays absent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ticket_carries_the_whole_caller() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader_admitting(&fixture, "true").await;
    let minted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    for (session_id, grants) in [("holder-k1", vec![KEY_GRANT]), ("anon-run", vec![])] {
        let (mut client, server) = open_session_with_grants(
            reader_pool.clone(),
            RosterAuth::granting("alice").withholding(WITHHELD_ID),
            RecordingSigner(std::sync::Arc::clone(&minted)),
            &ThrottleConfig::default(),
            session_id,
            &grants,
        )
        .await;
        let resp = request_ticket(&mut client, session_id, FILE_ID, ContentVerb::Read).await;
        assert!(
            matches!(resp, ControlMessage::ContentTicketGrant(_)),
            "an admitting fixture grants every caller, got {resp:?}"
        );
        client.close().await.expect("close");
        server.await.expect("join").expect("session ok");
    }

    let minted = minted
        .lock()
        .expect("the recording signer's mutex is never poisoned");
    let [key_only, anonymous] = minted.as_slice() else {
        panic!("expected exactly two mints, got {minted:?}");
    };
    assert_eq!(
        key_only.subjects(),
        [KEY_GRANT],
        "the share key rides to the signer"
    );
    assert_eq!(
        key_only.identity(),
        None,
        "a key-only caller mints with no identity, not with an empty one"
    );
    assert_eq!(anonymous.identity(), None, "an anonymous caller has none");
    assert!(
        anonymous.subjects().is_empty(),
        "and holds no subject either"
    );
    assert!(
        anonymous.attributions().is_empty(),
        "so there is nobody to attribute a commit to"
    );
    assert_eq!(
        anonymous.storage_key(),
        None,
        "and it has no manifest key at all"
    );
}
