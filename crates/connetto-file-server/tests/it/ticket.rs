//! Ticket property tests: expired, forged, and wrong-verb tokens all fail
//! identically, and a valid token verifies against its declared payload.

use connetto_core::messages::ContentVerb;
use connetto_core::traits::ContentTicketSigner;
use connetto_file_server::ticket::{TicketPayload, TicketVerifier, Verb};

use crate::fixture::make_signer;

fn payload_for(verb: Verb, ceiling: u64, expiry_offset_secs: i64) -> TicketPayload {
    TicketPayload {
        file_id: [1u8; 32],
        verb,
        ceiling,
        expiry: chrono::Utc::now().timestamp() + expiry_offset_secs,
        caller: "alice".into(),
    }
}

#[tokio::test]
async fn valid_read_ticket_verifies() {
    let (signer, verifier) = make_signer();
    let payload = payload_for(Verb::Read, 0, 600);
    let token = signer.mint(&payload).unwrap();
    let decoded = verifier.verify_verb(&token, Verb::Read).unwrap();
    assert_eq!(decoded.file_id, payload.file_id);
    assert_eq!(decoded.caller, "alice");
}

#[tokio::test]
async fn valid_write_ticket_verifies() {
    let (signer, verifier) = make_signer();
    let payload = payload_for(Verb::Write, 1024 * 1024, 600);
    let token = signer.mint(&payload).unwrap();
    let decoded = verifier.verify_verb(&token, Verb::Write).unwrap();
    assert_eq!(decoded.ceiling, 1024 * 1024);
}

/// Proves: an expired ticket answers with a `TicketError::Expired` variant,
/// which the HTTP layer maps to 404.
#[tokio::test]
async fn expired_ticket_is_refused() {
    let (signer, verifier) = make_signer();
    let payload = payload_for(Verb::Read, 0, -1);
    let token = signer.mint(&payload).unwrap();
    assert!(
        matches!(
            verifier.verify(&token),
            Err(connetto_file_server::ticket::TicketError::Expired)
        ),
        "expired token must be refused with Expired"
    );
}

/// Proves: a token signed by a different key (forged) is indistinguishable
/// from an expired or absent-file 404 — the verifier produces an error.
#[tokio::test]
async fn forged_token_is_refused() {
    let (signer_a, _) = make_signer();
    let (_, verifier_b) = make_signer();
    let payload = payload_for(Verb::Read, 0, 600);
    let token = signer_a.mint(&payload).unwrap();
    assert!(
        verifier_b.verify(&token).is_err(),
        "token signed by another key must be refused"
    );
}

/// Proves: a write ticket presented at a read endpoint fails verb check.
#[tokio::test]
async fn wrong_verb_is_refused() {
    let (signer, verifier) = make_signer();
    let payload = payload_for(Verb::Write, 0, 600);
    let token = signer.mint(&payload).unwrap();
    assert!(
        verifier.verify_verb(&token, Verb::Read).is_err(),
        "wrong verb must be refused"
    );
}

/// Proves: a tampered token (bit flip in the payload segment) fails signature
/// verification.
#[tokio::test]
async fn tampered_payload_is_refused() {
    let (signer, verifier) = make_signer();
    let payload = payload_for(Verb::Read, 0, 600);
    let token = signer.mint(&payload).unwrap();
    // Replace one character in the payload segment with a different base64
    // character. The signature over the modified bytes cannot match.
    let dot = token.rfind('.').unwrap();
    let mut chars: Vec<char> = token.chars().collect();
    let idx = dot / 2;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(
        verifier.verify(&tampered).is_err(),
        "tampered token must be refused"
    );
}

/// Proves: two signers generate different keypairs and their tokens are not
/// cross-verifiable.
#[tokio::test]
async fn different_signers_do_not_cross_verify() {
    let (signer_a, verifier_a) = make_signer();
    let (signer_b, verifier_b) = make_signer();
    let payload = payload_for(Verb::Read, 0, 600);
    let token_a = signer_a.mint(&payload).unwrap();
    let token_b = signer_b.mint(&payload).unwrap();
    assert!(verifier_b.verify(&token_a).is_err());
    assert!(verifier_a.verify(&token_b).is_err());
}

/// Proves: `public_key_bytes()` is accepted by `TicketVerifier::new`, and the
/// resulting verifier accepts a token minted by that signer.
#[tokio::test]
async fn signer_exposes_public_key() {
    let (signer, _) = make_signer();
    let pub_key = signer.public_key_bytes().to_vec();
    let verifier = TicketVerifier::new(pub_key);
    let payload = payload_for(Verb::Read, 0, 600);
    let token = signer.mint(&payload).unwrap();
    assert!(verifier.verify(&token).is_ok());
}

/// Proves: a completely synthetic token string is refused cleanly.
#[tokio::test]
async fn garbage_token_is_refused() {
    let (_, verifier) = make_signer();
    assert!(verifier.verify("not.a.valid.token").is_err());
    assert!(verifier.verify("").is_err());
    assert!(verifier.verify("nodot").is_err());
}

/// Extracts the ticket token from the URL the trait mint returns.
///
/// The URL ends with `?t=<token>` or `.../intent?t=<token>`.
fn token_from_url(url: &str) -> &str {
    url.split("?t=").nth(1).expect("URL must contain ?t=")
}

/// Proves: a read ticket minted via [`ContentTicketSigner`] verifies against
/// [`TicketVerifier`] and carries the correct verb, file id, caller, and the
/// configured read ceiling rather than an uncapped sentinel.
#[tokio::test]
async fn content_signer_read_ticket_verifies() {
    let (signer, verifier) = make_signer();
    let file_id = [7u8; 32];
    let url = ContentTicketSigner::mint(&signer, "bob", file_id, ContentVerb::Read)
        .await
        .expect("mint must succeed");
    assert!(
        url.contains("/files/"),
        "URL must contain the files path segment"
    );
    let token = token_from_url(&url);
    let payload = verifier
        .verify_verb(token, Verb::Read)
        .expect("read ticket must verify");
    assert_eq!(payload.file_id, file_id);
    assert_eq!(payload.caller, "bob");
    assert_eq!(payload.verb, Verb::Read);
    assert_eq!(
        payload.ceiling,
        10 * 1024 * 1024,
        "read ceiling must match the configured value, not u64::MAX"
    );
}

/// Proves: the read ceiling is the value supplied at construction time, not
/// an uncapped sentinel. A signer built with a small ceiling mints a ticket
/// whose ceiling equals that value.
#[tokio::test]
async fn content_signer_read_ceiling_is_configured_value() {
    use std::time::Duration;
    let configured: u64 = 512 * 1024;
    let (signer, verifier) = {
        let (s, pk) = connetto_file_server::TicketSigner::generate(
            "http://localhost".to_owned(),
            Duration::from_secs(3600),
            configured,
        )
        .expect("signer");
        (s, connetto_file_server::TicketVerifier::new(pk))
    };
    let url = ContentTicketSigner::mint(&signer, "eve", [2u8; 32], ContentVerb::Read)
        .await
        .expect("mint must succeed");
    let token = token_from_url(&url);
    let payload = verifier.verify(token).expect("token must verify");
    assert_eq!(
        payload.ceiling, configured,
        "ceiling must equal the value set at construction"
    );
    assert_ne!(
        payload.ceiling,
        u64::MAX,
        "ceiling must not be the uncapped sentinel"
    );
}

/// Proves: a write ticket minted via [`ContentTicketSigner`] verifies and
/// carries `Verb::Write` with `ceiling` equal to the declared upload size.
#[tokio::test]
async fn content_signer_write_ticket_verifies() {
    let (signer, verifier) = make_signer();
    let file_id = [9u8; 32];
    let declared_len: u64 = 4096;
    let url = ContentTicketSigner::mint(
        &signer,
        "carol",
        file_id,
        ContentVerb::Write { declared_len },
    )
    .await
    .expect("mint must succeed");
    assert!(
        url.contains("/intent"),
        "write URL must point at the intent endpoint"
    );
    let token = token_from_url(&url);
    let payload = verifier
        .verify_verb(token, Verb::Write)
        .expect("write ticket must verify");
    assert_eq!(payload.file_id, file_id);
    assert_eq!(payload.caller, "carol");
    assert_eq!(payload.ceiling, declared_len);
}

/// Proves: a read ticket minted via the trait is refused when presented as a
/// write ticket, so the verb mapping survives the round-trip.
#[tokio::test]
async fn content_signer_read_token_refused_as_write() {
    let (signer, verifier) = make_signer();
    let file_id = [3u8; 32];
    let url = ContentTicketSigner::mint(&signer, "dave", file_id, ContentVerb::Read)
        .await
        .expect("mint must succeed");
    let token = token_from_url(&url);
    assert!(
        matches!(
            verifier.verify_verb(token, Verb::Write),
            Err(connetto_file_server::ticket::TicketError::WrongVerb)
        ),
        "read ticket must be refused when presented as write"
    );
}

/// Proves: a public `http://` base is refused and the error names the base.
#[test]
fn http_public_base_is_refused() {
    let Err(err) = connetto_file_server::TicketSigner::generate(
        "http://files.example.com".to_owned(),
        std::time::Duration::from_secs(3600),
        1024,
    ) else {
        panic!("public http base must be refused, got Ok")
    };
    assert!(
        matches!(
            &err,
            connetto_file_server::ticket::TicketError::InsecureBase { base }
                if base == "http://files.example.com"
        ),
        "expected InsecureBase with the named base, got: {err:?}"
    );
}

/// Proves: an `http://127.0.0.1` base is accepted because the host is loopback.
#[test]
fn http_loopback_127_base_is_accepted() {
    connetto_file_server::TicketSigner::generate(
        "http://127.0.0.1:8080".to_owned(),
        std::time::Duration::from_secs(3600),
        1024,
    )
    .expect("loopback http base must be accepted");
}

/// Proves: the bracketed IPv6 loopback is accepted with a port, which is the form a
/// harness binds when it serves on `::1`.
#[test]
fn http_loopback_ipv6_base_is_accepted() {
    connetto_file_server::TicketSigner::generate(
        "http://[::1]:8080".to_owned(),
        std::time::Duration::from_secs(3600),
        1024,
    )
    .expect("loopback http base must be accepted");
}

/// Proves: an `https://` base is accepted and the minted grant still carries
/// that exact base, so the validation does not mangle the stored URL.
#[tokio::test]
async fn https_base_accepted_and_preserved_in_grant() {
    let (signer, _) = connetto_file_server::TicketSigner::generate(
        "https://files.example.com".to_owned(),
        std::time::Duration::from_secs(3600),
        1024,
    )
    .expect("https base must be accepted");
    let url = connetto_core::traits::ContentTicketSigner::mint(
        &signer,
        "alice",
        [1u8; 32],
        connetto_core::messages::ContentVerb::Read,
    )
    .await
    .expect("mint must succeed");
    assert!(
        url.starts_with("https://files.example.com"),
        "minted URL must start with the configured base; got: {url}"
    );
}
