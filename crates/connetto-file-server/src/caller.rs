//! The caller a ticket carries, and the one place it is bound.
//!
//! The server mints a ticket carrying both halves of the caller, the identity
//! and the packed capability subjects. Every check here binds both under the
//! names this deployment's policies read, so a caller whose rights come from a
//! share key is answered on its keys rather than refused.

use connetto_core::auth::{ContentCaller, DEFAULT_SUBJECTS_SETTING, DEFAULT_USER_SETTING};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::error::ServerError;
use crate::functions;

/// The session settings this deployment's policies read the caller from.
///
/// Mirrors the server's own configuration, which may rename either, so a
/// renamed deployment is not answered under connetto's defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerSettings {
    /// The setting the identity is bound to.
    pub user: String,
    /// The setting the packed capability subjects are bound to.
    pub subjects: String,
}

impl Default for CallerSettings {
    fn default() -> Self {
        Self {
            user: DEFAULT_USER_SETTING.to_owned(),
            subjects: DEFAULT_SUBJECTS_SETTING.to_owned(),
        }
    }
}

/// Bind whichever halves `caller` holds for the rest of the transaction.
///
/// A half the caller does not hold stays unbound, so `current_setting` yields
/// NULL and a comparison against it fails closed.
pub(crate) async fn bind_caller(
    conn: &mut AsyncPgConnection,
    settings: &CallerSettings,
    caller: &ContentCaller,
) -> Result<(), diesel::result::Error> {
    match (caller.identity(), caller.subjects()) {
        (None, None) => Ok(()),
        (Some(user), None) => diesel::select(functions::set_config(&settings.user, user, true))
            .get_result::<String>(conn)
            .await
            .map(drop),
        (None, Some(subjects)) => {
            diesel::select(functions::set_config(&settings.subjects, subjects, true))
                .get_result::<String>(conn)
                .await
                .map(drop)
        }
        (Some(user), Some(subjects)) => diesel::select((
            functions::set_config(&settings.user, user, true),
            functions::set_config(&settings.subjects, subjects, true),
        ))
        .get_result::<(String, String)>(conn)
        .await
        .map(drop),
    }
}

/// The key `caller` owns manifest rows under, and the value the deployment
/// attributes a commit to.
///
/// The identity when a login resolved, else the packed subjects, which are one
/// value per subject set. A caller holding neither has no key, so it owns no
/// manifest and is refused the way an absent file is.
///
/// # Errors
///
/// [`ServerError::NotFound`] when the ticket's caller holds neither half.
pub(crate) fn manifest_key(caller: &ContentCaller) -> Result<&str, ServerError> {
    caller.attribution().ok_or(ServerError::NotFound)
}
