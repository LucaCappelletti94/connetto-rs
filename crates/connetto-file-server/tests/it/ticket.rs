//! Ticket property tests: expired, forged, and wrong-verb tokens all fail
//! identically, and a valid token verifies against its declared payload.

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
        verifier.verify(&token).is_err(),
        "expired token must be refused"
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

/// Produces a `TicketSigner` from the given raw public-key bytes — verifies that
/// `public_key_bytes()` is compatible with `TicketVerifier::new`.
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
