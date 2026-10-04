//! The platform browser session a native connetto app signs in through on a
//! phone.
//!
//! RFC 8252 prefers, for mobile, an in-app browser tab that returns through a
//! redirect the operating system routes to the app (section 7.1), where a
//! desktop listens on loopback (section 7.3). [`authorize`] opens the login in
//! that tab and resolves to the URL the redirect delivered, which carries the
//! authorization code and the request's `state`.
//!
//! On Android the tab is a Custom Tab, and the redirect is any URI whose
//! scheme is the app's `applicationId`, which the bundled `RedirectActivity`
//! receives. On iOS it is an ephemeral `ASWebAuthenticationSession`, which
//! catches any URI whose scheme is the lowercased bundle identifier. Other
//! platforms answer [`AuthSessionError::Unsupported`].
//!
//! On Android it also hosts the prompt a Keystore-gated store unlocks through
//! (`device_secure`, `approve_unlock`), since the store is pure JNI and
//! cannot receive the prompt's callback itself.

use std::time::Duration;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "ios")]
mod ios;

/// Why a browser session produced no redirect.
#[derive(Debug, thiserror::Error)]
pub enum AuthSessionError {
    /// This platform has no browser session here.
    #[error("no in-app browser session on this platform")]
    Unsupported,
    /// The platform bridge failed.
    #[error("browser session bridge: {0}")]
    Bridge(String),
    /// No redirect arrived within the bound.
    #[error("no redirect arrived within {0:?}")]
    TimedOut(Duration),
}

/// Open `url` in the platform's in-app browser tab and resolve to the redirect
/// URL it delivers back to the app, waiting at most `timeout`.
///
/// A redirect left over from an earlier session is discarded first, so the
/// URL returned belongs to this one. The caller still checks its `state`.
///
/// # Errors
///
/// [`AuthSessionError::Unsupported`] off Android and iOS,
/// [`AuthSessionError::Bridge`] when the tab cannot be opened or read, and
/// [`AuthSessionError::TimedOut`] when the user never finishes the login.
#[cfg_attr(
    not(any(target_os = "android", target_os = "ios")),
    expect(
        clippy::unused_async,
        reason = "one async signature on every target, awaiting only where a session exists"
    )
)]
pub async fn authorize(url: &str, timeout: Duration) -> Result<String, AuthSessionError> {
    #[cfg(target_os = "android")]
    return android::authorize(url, timeout).await;
    #[cfg(target_os = "ios")]
    return ios::authorize(url, timeout).await;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = (url, timeout);
        Err(AuthSessionError::Unsupported)
    }
}

/// The redirect this process received before any [`authorize`] ran in it,
/// taken so it is returned once. A process the system started to deliver a
/// login's redirect holds it here. iOS never starts a process for one, since
/// the session that caught the redirect dies with the process that opened it.
///
/// # Errors
///
/// [`AuthSessionError::Bridge`] when the platform bridge cannot be reached.
pub fn delivered() -> Result<Option<String>, AuthSessionError> {
    #[cfg(target_os = "android")]
    return android::delivered();
    #[cfg(not(target_os = "android"))]
    Ok(None)
}

/// The JNI access an Android build's device key needs, reaching the Java VM
/// through the Activity Dioxus holds, for
/// `NativeDurable::with_java_access` (R74 decision 20).
#[cfg(all(target_os = "android", feature = "device-identity"))]
#[must_use]
pub fn java_access() -> std::sync::Arc<dyn connetto_client::device_key::JavaAccess> {
    std::sync::Arc::new(android::ActivityJava)
}

/// Whether the device has a secure lock screen, which a key held behind the
/// user's verification needs.
///
/// # Errors
///
/// [`AuthSessionError::Bridge`] when the platform bridge cannot be reached.
#[cfg(target_os = "android")]
pub fn device_secure() -> Result<bool, AuthSessionError> {
    android::device_secure()
}

/// Show the biometric or device-credential prompt titled `title` over
/// `cipher`, a `javax.crypto.Cipher` a Keystore-gated store handed out, and
/// answer whether the user approved it. Blocks the calling thread until the
/// prompt closes, at most `timeout`, so it runs off the app's event loop.
///
/// # Errors
///
/// [`AuthSessionError::Bridge`] when the prompt cannot be shown, and
/// [`AuthSessionError::TimedOut`] when nobody answers within the bound.
#[cfg(target_os = "android")]
pub fn approve_unlock(
    cipher: &manganis::jni::objects::JObject<'_>,
    title: &str,
    timeout: Duration,
) -> Result<bool, AuthSessionError> {
    android::approve_unlock(cipher, title, timeout)
}
