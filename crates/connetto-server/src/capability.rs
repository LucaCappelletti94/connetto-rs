//! Share keys: the deployment's key type, and the authorized mint call.
//!
//! A capability is a connetto-signed token asserting the bearer is a named
//! subject and nothing more. The permission attached to that name is an
//! ordinary row in the application's own table, gated by an ordinary policy, so
//! withdrawing a share is deleting that row and nothing here is consulted at
//! use time beyond the signature. See
//! `docs/architecture/12-identity-session-capability.md`.
//!
//! [`CapabilityKey`] is the one seam: the deployment's key type implements it,
//! naming how a fresh key is minted and how the keys a caller holds are packed
//! into the single Postgres setting a policy compares against. `String`
//! implements it, and is the default.
//!
//! [`CapabilityIssuer`] is the library call an application makes from its own
//! handler. connetto gains no endpoint for it.

use core::fmt::Display;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::auth::{CapabilitySubject, Principal};
use diesel::sql_types::{Bool, Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde::Serialize;
use serde::de::DeserializeOwned;
use subql::backend::{Postgres, Value};
use subql::visibility::{Verdict, VisibilityPolicy};

use crate::authn::token::{AuthConfig, TokenAuthority, TokenError};
use crate::row_view::ValuesRow;
use crate::snapshot::RowSource;

/// The deployment's share-key type: how one is minted, and how the keys a
/// caller holds reach Postgres.
///
/// A policy can only compare against a value the transaction bound, and a
/// caller may hold several keys, so the set travels as one text value under
/// [`SETTING`](Self::SETTING). The default packing joins the keys with
/// [`SEPARATOR`](Self::SEPARATOR), which a policy unpacks:
///
/// ```sql
/// viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
/// ```
///
/// Whatever a deployment chooses is the contract its policies are written
/// against, so choose before writing policies rather than after. A deployment
/// wanting its own key type, setting, or packing implements this for that type
/// and everything downstream follows from
/// [`Principal`]'s key parameter.
pub trait CapabilityKey:
    Clone + Display + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// The Postgres setting the packed keys are bound to.
    const SETTING: &'static str = "app.subjects";

    /// The character joining packed keys. A key whose rendering contains it is
    /// refused at minting, because one that slipped through would split into
    /// two and grant a neighbouring key's access.
    const SEPARATOR: char = ',';

    /// Mint a fresh key. It is a bearer secret, so it must be unguessable.
    fn mint() -> Self;

    /// Pack the keys a caller holds, or `None` to leave the setting unbound.
    ///
    /// Unbound rather than empty is what makes an absent capability fail
    /// closed: `current_setting` yields NULL, and a comparison against NULL is
    /// NULL rather than true.
    fn pack(keys: &[CapabilitySubject<Self>]) -> Option<String> {
        if keys.is_empty() {
            return None;
        }
        let mut packed = String::new();
        for key in keys {
            if !packed.is_empty() {
                packed.push(Self::SEPARATOR);
            }
            packed.push_str(&key.key().to_string());
        }
        Some(packed)
    }
}

/// The default share-key: `key:` followed by a version 4 UUID.
///
/// 122 bits of randomness, and no rendering of it can contain the separator.
impl CapabilityKey for String {
    fn mint() -> Self {
        format!("key:{}", uuid::Uuid::new_v4())
    }
}

diesel::define_sql_function! {
    /// Postgres `set_config`, the only way to hand a value to a policy. The
    /// query DSL has no other spelling for a session setting, so it is declared
    /// here as a typed function rather than written as a raw string.
    fn set_config(name: Text, value: Text, is_local: Bool) -> Text;
}

/// The caller rendered for one RLS transaction: the identity, and the share
/// keys packed by the deployment's [`CapabilityKey`].
///
/// Built outside the transaction (the values are owned so the apply future
/// stays `Send`) and applied as its first statement. Every path that runs SQL
/// as a caller goes through this, so the snapshot, the write, and the per-row
/// visibility check cannot answer differently about what the caller holds.
pub(crate) struct CallerBinding {
    user_id: Option<String>,
    user_setting: Arc<str>,
    setting: &'static str,
    subjects: Option<String>,
}

impl CallerBinding {
    /// Render `caller` under the deployment's key binding, naming the identity
    /// setting `user_setting`.
    pub(crate) fn of<Id: Display, Key: CapabilityKey>(
        caller: &Principal<Id, Key>,
        user_setting: Arc<str>,
    ) -> Self {
        Self {
            // A caller with no identity binds nothing, leaving the setting
            // unset for the whole transaction, so an owner comparison is NULL
            // and hides the row while a public predicate still returns its own.
            // An empty string would be a real identity that happens to be
            // blank, which a policy could match.
            user_id: caller
                .identity()
                .map(|identity| identity.user_id.to_string()),
            user_setting,
            setting: Key::SETTING,
            subjects: Key::pack(caller.capabilities()),
        }
    }

    /// Bind both values for the rest of the transaction, in one statement.
    pub(crate) async fn apply(self, conn: &mut AsyncPgConnection) -> diesel::QueryResult<()> {
        let user_setting = self.user_setting.to_string();
        match (self.user_id, self.subjects) {
            (None, None) => Ok(()),
            (Some(user), None) => diesel::select(set_config(user_setting, user, true))
                .execute(conn)
                .await
                .map(drop),
            (None, Some(subjects)) => diesel::select(set_config(self.setting, subjects, true))
                .execute(conn)
                .await
                .map(drop),
            (Some(user), Some(subjects)) => diesel::select((
                set_config(user_setting, user, true),
                set_config(self.setting, subjects, true),
            ))
            .execute(conn)
            .await
            .map(drop),
        }
    }
}

/// The setting an application's policies read the caller's identity from,
/// unless it names another.
///
/// The share-key setting has been the application's choice since R4, through
/// [`CapabilityKey::SETTING`]. This one was fixed in connetto's source until
/// 2026-08-06, for no reason beyond the key setting having somewhere obvious to
/// live and this one not.
pub const DEFAULT_USER_SETTING: &str = "app.user_id";

/// A share key that was minted, and the token proving the bearer holds it.
///
/// The application writes the row granting this key access, so the two agree on
/// the name by construction. What the application must not skip is the policy
/// on that table: connetto checked the caller may read the resource it named,
/// and only a `WITH CHECK` on the grant row makes the row that actually lands
/// answer to the same rule.
#[derive(Debug, Clone)]
pub struct IssuedCapability<Key> {
    /// The minted key, for the row the application writes.
    pub key: CapabilitySubject<Key>,
    /// The signed token, for the application to deliver however it likes.
    pub token: String,
    /// When the token stops checking out.
    pub expires_at: SystemTime,
}

/// A share could not be minted.
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    /// The caller may not read the resource it asked to share.
    #[error("the caller may not read {table}, so it may not share it")]
    Unauthorized {
        /// The table the caller named.
        table: String,
    },
    /// The row could not be reached at all, which is not the same as the
    /// caller not being allowed to share it.
    #[error("reading the row to share failed: {0}")]
    Read(String),
    /// The authorization check itself failed.
    #[error("authorization check failed: {0}")]
    Policy(String),
    /// The requested lifetime exceeds the deployment's ceiling.
    #[error("requested lifetime {requested:?} exceeds the ceiling {ceiling:?}")]
    TtlTooLong {
        /// What the caller asked for.
        requested: Duration,
        /// The configured maximum.
        ceiling: Duration,
    },
    /// The minted key's rendering contains the packing separator, so binding it
    /// would grant a neighbouring key's access.
    #[error("the minted key contains the packing separator {separator:?}")]
    SeparatorInKey {
        /// The separator the binding uses.
        separator: char,
    },
    /// Signing failed.
    #[error(transparent)]
    Mint(#[from] TokenError),
}

/// Mints share keys, having checked the caller may read what it is sharing.
///
/// Held beside [`AuthService`](crate::AuthService) at startup and called from
/// the application's own handler, so the application keeps its routing, its
/// request shape and its rate limits.
pub struct CapabilityIssuer<P, R, Id> {
    authority: Arc<TokenAuthority>,
    policy: Arc<P>,
    rows: Arc<R>,
    ttl: Duration,
    max_ttl: Duration,
    /// Sink for the durable record of a successful mint. `None` records
    /// nothing. It also fixes `Id`, so no separate marker is needed.
    audit: Option<crate::audit::AuditHook<Id>>,
}

impl<P, R, Id> CapabilityIssuer<P, R, Id> {
    /// Build over the token authority, the visibility policy, the row source
    /// the shared row is read through, and the lifetimes the deployment
    /// configured.
    #[must_use]
    pub fn new(
        authority: Arc<TokenAuthority>,
        policy: Arc<P>,
        rows: Arc<R>,
        config: &AuthConfig,
    ) -> Self {
        Self {
            authority,
            policy,
            rows,
            ttl: config.capability_ttl,
            max_ttl: config.capability_max_ttl,
            audit: None,
        }
    }

    /// Record every successful mint through `hook`.
    ///
    /// Unlike the revocation paths, this row names its user: the mint runs as
    /// the caller and so already holds the identity, with no extra round trip.
    #[must_use]
    pub fn with_audit(mut self, hook: crate::audit::AuditHook<Id>) -> Self {
        self.audit = Some(hook);
        self
    }

    /// Mint a share key over the row `key` names in `table`, on behalf of
    /// `caller`.
    ///
    /// `ttl` overrides the configured default and is refused rather than
    /// quietly shortened when it exceeds the ceiling, so an application's own
    /// statement of when a link dies cannot be a lie.
    ///
    /// The row is read before the question is asked, because the question is
    /// about the row and the caller named only its key. That read runs as the
    /// caller, so a row it may not see and a row that does not exist are the
    /// same refusal and minting cannot be turned into a probe. The question
    /// itself is the same visibility seam every other path goes through,
    /// because a caller must not share what it cannot read.
    ///
    /// # Errors
    ///
    /// [`ShareError`] when the caller may not read the row, the row cannot be
    /// reached, the lifetime exceeds the ceiling, or signing fails.
    pub async fn issue<Key>(
        &self,
        caller: &Principal<Id, Key>,
        table: &str,
        key: &[Value<Postgres>],
        ttl: Option<Duration>,
    ) -> Result<IssuedCapability<Key>, ShareError>
    where
        Id: Clone,
        Key: CapabilityKey,
        P: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
        P::Error: Display,
        R: RowSource<Id, Key>,
    {
        let ttl = match ttl {
            Some(requested) if requested > self.max_ttl => {
                return Err(ShareError::TtlTooLong {
                    requested,
                    ceiling: self.max_ttl,
                });
            }
            Some(requested) => requested,
            None => self.ttl,
        };
        let row = self
            .rows
            .read_row(caller, table, key)
            .await
            .map_err(|err| ShareError::Read(err.to_string()))?;
        let unauthorized = || ShareError::Unauthorized {
            table: table.to_owned(),
        };
        let row = row.ok_or_else(unauthorized)?;
        let view = ValuesRow::new(row.table_id, &row.values);
        let watchers = [Arc::new(caller.clone())];
        let mut verdicts = Vec::new();
        Verdict::reset(&mut verdicts, watchers.len());
        self.policy
            .may_see(&view, &watchers, &mut verdicts)
            .await
            .map_err(|err| ShareError::Policy(err.to_string()))?;
        if !matches!(verdicts.as_slice(), [Verdict::Allow, ..]) {
            return Err(unauthorized());
        }
        // Paired with the hook below in one `Option`, so the captured row and
        // the decision to record cannot disagree. Captured here because `key` is
        // shadowed by the minted subject on the next line. The values travel as
        // read: what type the audit table stores a row key as is the
        // application's, through `ConnettoAuditSchema::row_key`.
        let recording = self.audit.as_ref().map(|hook| (hook, key.to_vec()));
        let key = CapabilitySubject::<Key>::new(Key::mint());
        if key.key().to_string().contains(Key::SEPARATOR) {
            return Err(ShareError::SeparatorInKey {
                separator: Key::SEPARATOR,
            });
        }
        let issued_at = SystemTime::now();
        let token = self.authority.mint_capability(&key, issued_at, ttl)?;
        // After the mint, so a refused request records nothing: this table
        // holds what happened, and denials go to the log.
        if let Some((hook, shared_row)) = recording {
            hook(
                crate::audit::AuthEvent::new(
                    caller.session_id(),
                    caller.identity().map(|ctx| ctx.user_id.clone()),
                    crate::audit::AuthOp::CapabilityMinted,
                )
                .about_row(table, shared_row),
            );
        }
        Ok(IssuedCapability {
            key,
            token,
            expires_at: issued_at + ttl,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_held_leaves_the_setting_unbound() {
        assert!(String::pack(&[]).is_none());
    }

    #[test]
    fn held_keys_pack_in_order_under_one_separator() {
        let keys = [
            CapabilitySubject::new("key:a"),
            CapabilitySubject::new("key:b"),
        ];
        assert_eq!(String::pack(&keys).as_deref(), Some("key:a,key:b"));
    }

    #[test]
    fn a_minted_key_never_contains_the_separator() {
        for _ in 0..64 {
            assert!(!String::mint().contains(<String as CapabilityKey>::SEPARATOR));
        }
    }

    #[test]
    fn two_mints_never_collide() {
        assert_ne!(String::mint(), <String as CapabilityKey>::mint());
    }
}
