//! The caller a ticket carries, and the one place it is bound.
//!
//! The server mints a ticket carrying both halves of the caller, the identity
//! and the packed capability subjects. Every check here binds both under the
//! names this deployment's policies read, so a caller whose rights come from a
//! share key is answered on its keys rather than refused.

use connetto_core::auth::{
    ContentCaller, DEFAULT_SUBJECTS_SETTING, DEFAULT_USER_SETTING, absent_marker,
};
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

/// Bind both halves of `caller` for the rest of the transaction.
///
/// A half the caller does not hold takes [`absent_marker`], which no row can
/// carry, so a comparison against it is false. Leaving it unbound instead
/// would read as `''` to the next caller on a pooled connection, because
/// Postgres keeps the placeholder for the life of the session once anything
/// has bound it.
pub(crate) async fn bind_caller(
    conn: &mut AsyncPgConnection,
    settings: &CallerSettings,
    caller: &ContentCaller,
) -> Result<(), diesel::result::Error> {
    let marker = absent_marker();
    diesel::select((
        functions::set_config(&settings.user, caller.identity().unwrap_or(marker), true),
        functions::set_config(
            &settings.subjects,
            caller.subjects().unwrap_or(marker),
            true,
        ),
    ))
    .get_result::<(String, String)>(conn)
    .await
    .map(drop)
}

/// The key `caller` owns manifest rows under.
///
/// Namespaced by the half it came from, so an identity and a capability
/// subject that render alike cannot own one another's rows. The deployment is
/// attributed the plain value instead, through
/// [`ContentCaller::attribution`], because that is what its own policies
/// compare against.
///
/// # Errors
///
/// [`ServerError::NotFound`] when the ticket's caller holds neither half, so
/// it owns no manifest and is refused the way an absent file is.
pub(crate) fn manifest_key(caller: &ContentCaller) -> Result<String, ServerError> {
    caller.storage_key().ok_or(ServerError::NotFound)
}

/// The value the deployment's content-state setter is given for the commit.
///
/// # Errors
///
/// [`ServerError::NotFound`] when the ticket's caller holds neither half.
pub(crate) fn attribution(caller: &ContentCaller) -> Result<&str, ServerError> {
    caller.attribution().ok_or(ServerError::NotFound)
}
