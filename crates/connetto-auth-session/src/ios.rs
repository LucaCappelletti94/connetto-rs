//! The authentication session and its redirect, through the bundled Swift
//! package.

use std::time::Duration;

use tokio::time::{Instant, sleep};

use crate::AuthSessionError;

#[manganis::ffi("ios")]
unsafe extern "Swift" {
    pub type AuthSessionPlugin;
    pub fn begin(this: &AuthSessionPlugin, url: String);
    pub fn take_redirect(this: &AuthSessionPlugin) -> Option<String>;
}

const POLL: Duration = Duration::from_millis(250);

pub(crate) async fn authorize(url: &str, timeout: Duration) -> Result<String, AuthSessionError> {
    let plugin = AuthSessionPlugin::new().map_err(bridge)?;
    begin(&plugin, url.to_owned()).map_err(bridge)?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(redirect) = take_redirect(&plugin).map_err(bridge)? {
            return Ok(redirect);
        }
        if Instant::now() >= deadline {
            return Err(AuthSessionError::TimedOut(timeout));
        }
        sleep(POLL).await;
    }
}

fn bridge(err: &'static str) -> AuthSessionError {
    AuthSessionError::Bridge(err.to_owned())
}
