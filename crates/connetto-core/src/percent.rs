//! Percent-encoding for query-string values, shared by every side that builds
//! a login URL or reads a callback query by hand.
//!
//! The preserved set is RFC 3986's unreserved characters, which is all a PKCE
//! challenge, an authorization code, and a CSRF state are made of. A
//! client-chosen state need not be, so everything else is escaped defensively.

use core::fmt::Write as _;

/// Percent-encode `value`, preserving only `A-Z a-z 0-9 - _ . ~`.
///
/// ```
/// use connetto_core::percent::percent_encode;
///
/// assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
/// assert_eq!(percent_encode("a b&c=d"), "a%20b%26c%3Dd");
/// ```
#[must_use]
pub fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// Decode a percent-encoded query value.
///
/// A `%` not followed by two hex digits yields a literal `%` and drops the two
/// bytes it consumed. Harmless where this is used: the only producer of these
/// values is [`percent_encode`], so a malformed escape means a value that
/// fails its downstream check anyway. Bytes that do not form valid UTF-8
/// become the replacement character.
///
/// ```
/// use connetto_core::percent::percent_decode;
///
/// assert_eq!(percent_decode("a%20b%26c"), "a b&c");
/// assert_eq!(percent_decode("100% sure"), "100%ure");
/// ```
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes.next();
            let lo = bytes.next();
            if let (Some(hi), Some(lo)) = (hi, lo)
                && let (Some(hi), Some(lo)) =
                    (char::from(hi).to_digit(16), char::from(lo).to_digit(16))
            {
                // Both nibbles are in 0..16, so the byte fits.
                out.push(u8::try_from(hi * 16 + lo).expect("nibble byte fits u8"));
                continue;
            }
            out.push(b'%');
        } else {
            out.push(byte);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
