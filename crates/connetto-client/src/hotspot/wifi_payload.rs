//! The hotspot offer as a `WIFI:` payload, the string a QR code or a
//! message carries (R76 decision 23).

use zeroize::Zeroizing;

use super::{HotspotOffer, HotspotSecurity};

/// Why a string is not a hotspot offer's payload (R76 decision 23).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WifiPayloadError {
    /// The string does not start with `WIFI:`.
    #[error("the string is not a WIFI: payload")]
    NotWifi,
    /// The payload ends before its closing `;;`, as a cut string does.
    #[error("the payload ends before its closing ;;")]
    Unterminated,
    /// A field is not a letter, a colon and a value.
    #[error("a field of the payload is not a letter, a colon and a value")]
    Malformed,
    /// A field appears twice.
    #[error("the payload names its {0} field twice")]
    Repeated(char),
    /// The payload names no network.
    #[error("the payload names no network")]
    NoSsid,
    /// The payload carries no password.
    #[error("the payload carries no password")]
    NoPassword,
    /// The payload's security is not one a hotspot offers.
    #[error("the payload's security {0} is not WPA or SAE")]
    Security(String),
    /// The payload's port is not a port.
    #[error("the payload's port {0} is not a port")]
    Port(String),
}

impl HotspotOffer {
    /// The offer as a `WIFI:` payload, which a phone's camera joins and
    /// [`HotspotOffer::from_wifi_payload`] reads back with the port.
    #[must_use]
    pub fn to_wifi_payload(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(String::from("WIFI:T:"));
        payload.push_str(match self.security {
            HotspotSecurity::Wpa2 => "WPA",
            HotspotSecurity::Wpa3 => "SAE",
        });
        payload.push_str(";S:");
        escape_into(&mut payload, &self.ssid);
        payload.push_str(";P:");
        escape_into(&mut payload, &self.passphrase);
        payload.push(';');
        if let Some(port) = self.port {
            payload.push_str("X:");
            payload.push_str(&port.to_string());
            payload.push(';');
        }
        payload.push(';');
        payload
    }

    /// The offer a `WIFI:` payload carries. A missing security reads as WPA2,
    /// fields the format knows beyond these are skipped, and the payload must
    /// end in its `;;`, so a string cut short is refused rather than read
    /// with a shortened password.
    ///
    /// # Errors
    ///
    /// [`WifiPayloadError`] naming what the string lacks or carries wrong.
    pub fn from_wifi_payload(payload: &str) -> Result<Self, WifiPayloadError> {
        let body = payload
            .strip_prefix("WIFI:")
            .ok_or(WifiPayloadError::NotWifi)?;
        let mut security = None;
        let mut ssid = None;
        let mut passphrase: Option<Zeroizing<String>> = None;
        let mut port = None;
        let mut chars = body.chars();
        loop {
            let Some(name) = chars.next() else {
                return Err(WifiPayloadError::Unterminated);
            };
            // The empty field closes the payload.
            if name == ';' {
                break;
            }
            if chars.next() != Some(':') {
                return Err(WifiPayloadError::Malformed);
            }
            let value = Zeroizing::new(read_value(&mut chars)?);
            let slot = match name {
                'T' => &mut security,
                'S' => &mut ssid,
                'P' => {
                    if passphrase.replace(value).is_some() {
                        return Err(WifiPayloadError::Repeated('P'));
                    }
                    continue;
                }
                'X' => &mut port,
                _ => continue,
            };
            if slot.replace(value.to_string()).is_some() {
                return Err(WifiPayloadError::Repeated(name));
            }
        }
        let security = match security.as_deref() {
            None | Some("WPA") => HotspotSecurity::Wpa2,
            Some("SAE") => HotspotSecurity::Wpa3,
            Some(other) => return Err(WifiPayloadError::Security(other.to_owned())),
        };
        let ssid = ssid
            .filter(|ssid| !ssid.is_empty())
            .ok_or(WifiPayloadError::NoSsid)?;
        let passphrase = passphrase
            .filter(|passphrase| !passphrase.is_empty())
            .ok_or(WifiPayloadError::NoPassword)?;
        let port = port
            .map(|text| match text.parse::<u16>() {
                Ok(port) if port != 0 => Ok(port),
                _ => Err(WifiPayloadError::Port(text)),
            })
            .transpose()?;
        Ok(Self::new(ssid, passphrase.as_str(), security, port))
    }
}

/// The characters the format escapes with a backslash.
const ESCAPED: [char; 5] = ['\\', ';', ',', ':', '"'];

fn escape_into(payload: &mut String, value: &str) {
    for c in value.chars() {
        if ESCAPED.contains(&c) {
            payload.push('\\');
        }
        payload.push(c);
    }
}

/// One field's value, up to its unescaped `;`.
fn read_value(chars: &mut std::str::Chars<'_>) -> Result<String, WifiPayloadError> {
    let mut value = String::new();
    loop {
        match chars.next() {
            Some(';') => return Ok(value),
            Some('\\') => match chars.next() {
                Some(escaped) => value.push(escaped),
                None => return Err(WifiPayloadError::Unterminated),
            },
            Some(c) => value.push(c),
            None => return Err(WifiPayloadError::Unterminated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(
        ssid: &str,
        passphrase: &str,
        security: HotspotSecurity,
        port: Option<u16>,
    ) -> HotspotOffer {
        HotspotOffer::new(ssid, passphrase, security, port)
    }

    #[test]
    fn an_offer_writes_the_standard_fields_and_its_port() {
        assert_eq!(
            offer(
                "AndroidShare_1234",
                "k7v2pq9x",
                HotspotSecurity::Wpa2,
                Some(41_234)
            )
            .to_wifi_payload()
            .as_str(),
            "WIFI:T:WPA;S:AndroidShare_1234;P:k7v2pq9x;X:41234;;"
        );
        assert_eq!(
            offer("camp", "secret pass", HotspotSecurity::Wpa3, None)
                .to_wifi_payload()
                .as_str(),
            "WIFI:T:SAE;S:camp;P:secret pass;;"
        );
    }

    #[test]
    fn the_format_s_special_characters_are_escaped_and_read_back() {
        let tricky = offer(r#"a;b,c:d\e"f"#, r"p;w\d:,", HotspotSecurity::Wpa2, Some(1));
        let payload = tricky.to_wifi_payload();
        assert_eq!(
            payload.as_str(),
            r#"WIFI:T:WPA;S:a\;b\,c\:d\\e\"f;P:p\;w\\d\:\,;X:1;;"#
        );
        assert_eq!(HotspotOffer::from_wifi_payload(&payload), Ok(tricky));
    }

    #[test]
    fn a_payload_reads_in_any_field_order_and_skips_unknown_fields() {
        assert_eq!(
            HotspotOffer::from_wifi_payload("WIFI:S:camp;H:false;X:7;R:1;T:SAE;P:pw;;"),
            Ok(offer("camp", "pw", HotspotSecurity::Wpa3, Some(7)))
        );
        assert_eq!(
            HotspotOffer::from_wifi_payload("WIFI:P:pw;S:camp;T:WPA;;"),
            Ok(offer("camp", "pw", HotspotSecurity::Wpa2, None))
        );
    }

    #[test]
    fn a_payload_the_offer_cannot_stand_on_is_refused_by_name() {
        for (payload, refusal) in [
            ("https://example.com", WifiPayloadError::NotWifi),
            ("WIFI:T:WPA;P:pw;;", WifiPayloadError::NoSsid),
            ("WIFI:T:WPA;S:camp;;", WifiPayloadError::NoPassword),
            (
                "WIFI:T:nopass;S:camp;P:pw;;",
                WifiPayloadError::Security("nopass".into()),
            ),
            (
                "WIFI:T:WEP;S:camp;P:pw;;",
                WifiPayloadError::Security("WEP".into()),
            ),
            (
                "WIFI:T:WPA;S:camp;P:pw;X:70000;;",
                WifiPayloadError::Port("70000".into()),
            ),
            (
                "WIFI:T:WPA;S:camp;P:pw;X:0;;",
                WifiPayloadError::Port("0".into()),
            ),
            ("WIFI:T:WPA;S:camp;P:pw\\", WifiPayloadError::Unterminated),
            ("WIFI:T:WPA;S:camp;P:pw;", WifiPayloadError::Unterminated),
            (
                "WIFI:T:WPA;S:camp;P:pw;S:other;;",
                WifiPayloadError::Repeated('S'),
            ),
            ("WIFI:T:WPA;Scamp;P:pw;;", WifiPayloadError::Malformed),
        ] {
            assert_eq!(
                HotspotOffer::from_wifi_payload(payload),
                Err(refusal),
                "{payload}"
            );
        }
    }

    #[test]
    fn a_missing_security_reads_as_wpa2() {
        assert_eq!(
            HotspotOffer::from_wifi_payload("WIFI:S:camp;P:pw;;"),
            Ok(offer("camp", "pw", HotspotSecurity::Wpa2, None))
        );
    }
}
