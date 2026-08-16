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
use subql::visibility::{RowWrite, Verdict, VisibilityPolicy, WriteOp};

use crate::authn::token::{AuthConfig, TokenAuthority, TokenError};
use crate::reserve::{ReaderGate, ReaderPermit};
use crate::row_view::ValuesRow;
use crate::snapshot::RowSource;
use crate::throttle::Tier;

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

/// The write verbs a share certifies, beside the reading every share certifies.
///
/// The application is the only party that knows what its own permission row
/// grants, so it names the verbs and connetto certifies exactly those. A read
/// share names none, which is [`ShareLevel::read`].
///
/// # Why creating is not among them
///
/// A share names a table and one row's key, and a write question is judged on
/// the row versions its verb needs. Creating is judged on the row being
/// created, which a mint does not hold and cannot: whatever the bearer later
/// inserts is a different row under a different key, so a question asked now
/// about the shared row says nothing about it. Handing the row the mint read
/// over as the row being created asks whether the caller may create a row that
/// already exists, which is a different question wearing the right name.
///
/// ```
/// use connetto_server::ShareLevel;
///
/// // A share that lets the bearer edit the row but never remove it.
/// let level = ShareLevel::read().with_update();
/// assert!(!level.is_read_only());
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ShareLevel {
    update: bool,
    delete: bool,
}

impl ShareLevel {
    /// Certify reading and nothing else.
    #[must_use]
    pub const fn read() -> Self {
        Self {
            update: false,
            delete: false,
        }
    }

    /// Also certify replacing the row's values.
    #[must_use]
    pub const fn with_update(mut self) -> Self {
        self.update = true;
        self
    }

    /// Also certify removing the row.
    #[must_use]
    pub const fn with_delete(mut self) -> Self {
        self.delete = true;
        self
    }

    /// Whether this share certifies no write at all.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !self.update && !self.delete
    }

    /// The named verbs as questions about `row`, in a fixed order, so a mint
    /// asks the same questions in the same sequence however the caller built
    /// the level.
    ///
    /// A mint holds one version of the row, so a replacement is asked as
    /// [`RowWrite::UpdateUsing`], which is subql's question for exactly this
    /// case: whether the row as it stands may be replaced at all. It is the
    /// weaker half of the full replacement question, and it is the half a
    /// delegated permission over a row needs.
    fn writes<R: ?Sized>(self, row: &R) -> impl Iterator<Item = RowWrite<'_, R>> {
        [
            (self.update, RowWrite::UpdateUsing { old: row }),
            (self.delete, RowWrite::Delete { old: row }),
        ]
        .into_iter()
        .filter_map(|(named, write)| named.then_some(write))
    }

    /// The named verbs, in the order the mint asks them, so an
    /// application can read back what a share certified.
    ///
    /// The unit stands in for a row because [`RowWrite::op`] reads the variant
    /// and never the row, which keeps one ordered list rather than two that
    /// can drift.
    pub fn verbs(self) -> impl Iterator<Item = WriteOp> {
        self.writes(&()).map(|write| write.op())
    }
}

/// One write verb as prose, for a refusal a person reads.
const fn verb(op: WriteOp) -> &'static str {
    match op {
        WriteOp::Insert => "insert into",
        WriteOp::Update => "update",
        WriteOp::Delete => "delete from",
    }
}

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
    /// What connetto certified the caller holds, which is what the permission
    /// row must not exceed. It travels here rather than in the token, because a
    /// permission inside the token would split authorization between the
    /// token's contents and the model.
    pub level: ShareLevel,
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
    /// The caller may read the row but may not perform a verb it asked to
    /// share, so it may not hand that verb on.
    #[error("the caller may not {} {table}, so it may not share that", verb(*op))]
    NotWritable {
        /// The table the caller named.
        table: String,
        /// The first named verb the policy denied.
        op: WriteOp,
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
    /// The unreserved reader share stayed full for the whole queue window, so
    /// the reads behind the mint were refused rather than served on capacity
    /// R39 reserves for identified callers.
    #[error("no reader capacity for an unidentified caller, retry after {retry_after:?}")]
    RateLimited {
        /// How long to wait before asking again.
        retry_after: Duration,
    },
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
    /// The reader-pool gate the mint's reads take a share permit from. `None`
    /// leaves them ungated, the pre-R39 behaviour.
    reader: Option<ReaderGate>,
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
            ttl: config.capability_ttl(),
            max_ttl: config.capability_max_ttl(),
            audit: None,
            reader: None,
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

    /// Bound this issuer's reads by the reader pool's reserved split (R39).
    ///
    /// The mint reads the shared row and asks the visibility question on the
    /// reader pool, so without this an unidentified caller could occupy
    /// connections past the reserve. Clone the same [`ReaderGate`] the
    /// [`RequestGuard`](crate::RequestGuard) holds: one split per pool.
    #[must_use]
    pub fn with_reader_gate(mut self, gate: ReaderGate) -> Self {
        self.reader = Some(gate);
        self
    }

    /// Mint a share key over the row `key` names in `table`, on behalf of
    /// `caller`, certifying `level`.
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
    /// A share certifying a write asks the seam's write question once per verb
    /// [`ShareLevel`] names, about the row as it stands, and all of them must
    /// allow (R34). Against the row-level-security policy every write is
    /// allowed, so the refusal waits on an engine that can answer.
    ///
    /// # Errors
    ///
    /// [`ShareError`] when the caller may not read the row or may not perform
    /// a verb it named, the row cannot be reached, the lifetime exceeds the
    /// ceiling, signing fails, or an unidentified caller finds the unreserved
    /// reader share full.
    pub async fn issue<Key>(
        &self,
        caller: &Principal<Id, Key>,
        table: &str,
        key: &[Value<Postgres>],
        level: ShareLevel,
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
        // The row read and the visibility question below both check out
        // reader connections, one at a time, so one share permit spans the
        // mint (R39).
        let _reader_permit = match &self.reader {
            Some(gate) => gate
                .acquire(Tier::of(caller))
                .await
                .map_err(|retry_after| ShareError::RateLimited { retry_after })?,
            None => ReaderPermit::none(),
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
        // One question per verb the caller named, about the row as it stands,
        // which is the only version a mint holds. All must allow: a share must
        // not hand on a verb the sharer does not hold itself.
        for write in level.writes(&view) {
            let verdict = self
                .policy
                .may_write(write, &watchers[0])
                .await
                .map_err(|err| ShareError::Policy(err.to_string()))?;
            if !verdict.allowed() {
                return Err(ShareError::NotWritable {
                    table: table.to_owned(),
                    op: write.op(),
                });
            }
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
            level,
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
