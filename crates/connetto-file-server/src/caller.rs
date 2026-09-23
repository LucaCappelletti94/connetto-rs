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
    /// The setting the joined capability subjects are bound to.
    pub subjects: String,
    /// The character the subjects are joined by, which the deployment's
    /// policies split them on.
    pub separator: char,
}

impl Default for CallerSettings {
    fn default() -> Self {
        Self {
            user: DEFAULT_USER_SETTING.to_owned(),
            subjects: DEFAULT_SUBJECTS_SETTING.to_owned(),
            separator: ',',
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
    let subjects = caller
        .packed_subjects(settings.separator)
        .unwrap_or_else(|| marker.to_owned());
    diesel::select((
        functions::set_config(&settings.user, caller.identity().unwrap_or(marker), true),
        functions::set_config(&settings.subjects, subjects.as_str(), true),
    ))
    .get_result::<(String, String)>(conn)
    .await
    .map(drop)
}

/// The key `caller` owns manifest rows under.
///
/// Namespaced by the half it came from, so an identity and a capability
/// subject that render alike cannot own one another's rows, and joined under
/// the deployment's own separator, which no single key may contain, so two
/// callers holding different keys cannot render one value. The deployment is
/// attributed the plain values instead, through [`attributions`], because
/// that is what its own policies compare against.
///
/// # Errors
///
/// [`ServerError::NotFound`] when the ticket's caller holds neither half, so
/// it owns no manifest and is refused the way an absent file is.
pub(crate) fn manifest_key(
    settings: &CallerSettings,
    caller: &ContentCaller,
) -> Result<String, ServerError> {
    caller
        .storage_key(settings.separator)
        .ok_or(ServerError::NotFound)
}

/// Everyone the deployment's content-state setter is told the commit belongs
/// to: the identity, else each subject the caller holds.
///
/// A key holder is named once per key, because a deployment that stores the
/// value as the owner and compares it against one subject would never match a
/// row owned by the joined list, hiding the file from its own uploader.
///
/// # Errors
///
/// [`ServerError::NotFound`] when the ticket's caller holds neither half.
pub(crate) fn attributions(caller: &ContentCaller) -> Result<Vec<&str>, ServerError> {
    let attributions = caller.attributions();
    if attributions.is_empty() {
        return Err(ServerError::NotFound);
    }
    Ok(attributions)
}

/// The attributions a stored manifest key was written for, the inverse of [`manifest_key`] then [`attributions`].
pub(crate) fn attributions_of_key<'k>(settings: &CallerSettings, key: &'k str) -> Vec<&'k str> {
    if let Some(identity) = key.strip_prefix("user:") {
        return vec![identity];
    }
    key.strip_prefix("keys:")
        .map(|keys| keys.split(settings.separator).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(caller: &ContentCaller) -> Vec<String> {
        let settings = CallerSettings::default();
        let key = manifest_key(&settings, caller).expect("a caller with a half owns a key");
        attributions_of_key(&settings, &key)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn owned(caller: &ContentCaller) -> Vec<String> {
        attributions(caller)
            .expect("a caller with a half is attributed")
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn every_caller_shape_round_trips_to_its_attributions() {
        for caller in [
            ContentCaller::new(Some("alice".to_owned()), None),
            ContentCaller::new(Some("keys:user:a,b".to_owned()), None),
            ContentCaller::new(None, ["key:k1".to_owned()]),
            ContentCaller::new(None, ["key:k1".to_owned(), "key:k2".to_owned()]),
        ] {
            assert_eq!(round_trip(&caller), owned(&caller), "{caller:?}");
        }
    }

    #[test]
    fn a_key_of_neither_shape_names_nobody() {
        assert_eq!(
            attributions_of_key(&CallerSettings::default(), "alice"),
            Vec::<&str>::new()
        );
    }
}
