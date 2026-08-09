//! Reading the expiry a share key already carries.
//!
//! A grant is an `EdDSA` JWT, and a JWT payload is base64url and signed rather
//! than encrypted, so a client reads `exp` out of a token it holds with no key
//! and no round trip. `docs/architecture/02-protocol.md` records the one
//! exception this makes to the rule that a grant is opaque to the client.
//!
//! Advisory only. The server verifies `exp` authoritatively, so a client fed a
//! forged claim either presents a dead key and is refused exactly as before, or
//! skips a live one and harms only itself. Anything this cannot read is
//! therefore presented rather than withheld.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::messages::Grant;
use serde::Deserialize;

/// The one claim read here. Everything else in the payload is the server's
/// business.
#[derive(Deserialize)]
struct Expiry {
    exp: i64,
}

/// Whether `grant` says it died at or before `now`, in seconds since the epoch.
///
/// False for anything unreadable: a token with no `exp`, a payload that is not
/// base64url or not JSON, or a string that is not a JWT at all. Presenting one
/// of those costs a refusal the server was going to issue anyway, while
/// withholding it would break a caller over a parse this side got wrong.
pub(crate) fn has_expired(grant: &Grant, now: i64) -> bool {
    expiry_of(grant).is_some_and(|exp| exp <= now)
}

/// The `exp` claim in `grant`'s payload, or `None` when there is none to read.
fn expiry_of(grant: &Grant) -> Option<i64> {
    let mut parts = grant.as_str().split('.');
    let payload = parts.nth(1)?;
    // Three segments exactly: a two-segment string is an unsigned JWT and a
    // four-segment one is JWE, whose payload is encrypted and would decode to
    // noise rather than to claims.
    if parts.next().is_none() || parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<Expiry>(&bytes)
        .ok()
        .map(|claims| claims.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    /// A three-segment token whose payload is `claims`, signed with nothing.
    /// The signature is never checked here, which is the point of the feature.
    fn token(claims: &str) -> Grant {
        Grant::new(format!(
            "{}.{}.{}",
            B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#),
            B64.encode(claims.as_bytes()),
            B64.encode(b"not-a-signature"),
        ))
    }

    #[test]
    fn a_key_whose_expiry_has_passed_reads_as_expired() {
        assert!(has_expired(&token(r#"{"knd":"key","exp":1000}"#), 1001));
    }

    /// The boundary is inclusive: a key expiring exactly now is dead, matching
    /// what the server's own check would say a moment later.
    #[test]
    fn the_expiry_second_itself_counts_as_expired() {
        assert!(has_expired(&token(r#"{"knd":"key","exp":1000}"#), 1000));
        assert!(!has_expired(&token(r#"{"knd":"key","exp":1000}"#), 999));
    }

    /// Everything unreadable is presented, because the server decides and this
    /// check exists only to save a round trip.
    #[test]
    fn anything_unreadable_is_presented() {
        for grant in [
            token(r#"{"knd":"key"}"#),
            token(r#"{"exp":"soon"}"#),
            token("not json"),
            Grant::new("header.!!not base64!!.signature"),
            Grant::new("opaque-string"),
            Grant::new("two.segments"),
            Grant::new("a.b.c.d"),
            Grant::new(String::new()),
        ] {
            assert!(
                !has_expired(&grant, i64::MAX),
                "an unreadable grant must still be presented: {}",
                grant.as_str()
            );
        }
    }

    /// The claim shape connetto actually signs, read out of a real minted
    /// token rather than a hand-built one, so a change to the claims that
    /// moved or renamed `exp` fails here.
    #[test]
    fn a_real_minted_capability_reads_its_own_expiry() {
        use connetto_core::auth::CapabilitySubject;
        use connetto_server::{AuthConfig, TokenAuthority};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let authority = TokenAuthority::generate(&AuthConfig::default()).expect("keypair");
        let issued_at = SystemTime::now() - Duration::from_secs(7200);
        let minted = authority
            .mint_capability(
                &CapabilitySubject::<String>::new("share:doc-1"),
                issued_at,
                Duration::from_secs(3600),
            )
            .expect("mint");
        let expected = i64::try_from(
            issued_at
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs()
                + 3600,
        )
        .expect("an epoch second fits");

        assert_eq!(expiry_of(&Grant::new(minted.clone())), Some(expected));
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs(),
        )
        .expect("an epoch second fits");
        assert!(has_expired(&Grant::new(minted), now));
    }
}
