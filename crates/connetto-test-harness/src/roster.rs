//! The suite's stand-in for a real authorization policy (R9).
//!
//! Every integration test needs something behind
//! [`VisibilityPolicy`], and until R9 that
//! something wrote `Allow` into every answer slot, so a test installing it
//! passed whether or not connetto asked the question at all. [`RosterAuth`] is
//! told who its fixture's caller is and refuses anybody else, and it is told
//! one primary key to refuse to everybody, so a delivery path that stopped
//! consulting the policy delivers a row the test asserts never arrives.
//!
//! It is not a policy a deployment could use. The shipped answer comes from
//! `FgaAuth`, and `RlsAuth` is the row-level-security one.

use core::convert::Infallible;
use core::future::ready;
use std::sync::Arc;

use connetto_core::auth::Principal;
use subql::backend::{Postgres, Value};
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};

/// The primary key every fixture withholds from its own caller.
///
/// A fixture seeds a row with this key and asserts it never arrives. The value
/// is arbitrary and only has to miss every key the fixtures already use.
pub const WITHHELD_ID: i64 = 4242;

/// A policy told which callers it grants and which rows it withholds.
///
/// A caller is granted when the roster names it. A login grant `user:alice`
/// resolves to the identity `alice`, so `alice` is what the roster holds, while
/// a share-key grant `key:abc123` resolves to the subject `key:abc123`, prefix
/// included, so the whole string is what the roster holds. That asymmetry is
/// `TestGrantChecker`'s, not this type's.
///
/// A withheld key is refused to every caller, granted or not, on both the read
/// and the write question. That is what a fixture asserts on: the row exists,
/// the caller is granted everything else, and the row still must not arrive.
///
/// The write question is answered from the same two rules rather than passing,
/// because a stand-in that allowed every write would be the thing this type
/// replaced, wearing one fewer name.
// No `Default`: "grants nobody" has exactly one spelling, `granting_nobody`,
// so a fixture cannot arrive at it by accident.
#[derive(Debug, Clone)]
pub struct RosterAuth {
    /// Identities and share-key subjects this grants.
    names: Vec<String>,
    /// Whether the caller carrying neither an identity nor a share key is
    /// granted.
    unnamed: bool,
    /// Primary keys refused to everybody.
    withheld: Vec<i64>,
}

impl RosterAuth {
    /// Grant one caller, by the name its grant resolves to.
    pub fn granting(name: impl Into<String>) -> Self {
        Self {
            names: vec![name.into()],
            unnamed: false,
            withheld: Vec::new(),
        }
    }

    /// Grant nobody at all.
    ///
    /// For a fixture that puts no question to the policy, which is the honest
    /// configuration rather than a lazy one: nine of the suite's fixtures serve
    /// their rows from a snapshot stub and send no mutation, and connetto routes
    /// neither a snapshot nor an aggregate through the policy.
    #[must_use]
    pub const fn granting_nobody() -> Self {
        Self {
            names: Vec::new(),
            unnamed: false,
            withheld: Vec::new(),
        }
    }

    /// Grant one more caller.
    #[must_use]
    pub fn and(mut self, name: impl Into<String>) -> Self {
        self.names.push(name.into());
        self
    }

    /// Grant the caller that presents neither an identity nor a share key.
    ///
    /// One named entry and not a way back to granting everybody: a caller
    /// holding a name this roster does not list is still refused. It exists
    /// because connetto serves an unidentified caller on purpose, and a test
    /// proving the database refuses such a caller's write needs the write to
    /// reach the database.
    #[must_use]
    pub fn and_the_unnamed_caller(mut self) -> Self {
        self.unnamed = true;
        self
    }

    /// Withhold one primary key from everybody.
    #[must_use]
    pub fn withholding(mut self, key: i64) -> Self {
        self.withheld.push(key);
        self
    }

    /// Whether the roster names this caller.
    fn grants(&self, caller: &Principal) -> bool {
        if let Some(identity) = caller.identity()
            && self.names.contains(&identity.user_id)
        {
            return true;
        }
        if caller
            .capabilities()
            .iter()
            .any(|subject| self.names.contains(subject.key()))
        {
            return true;
        }
        self.unnamed && caller.identity().is_none() && caller.capabilities().is_empty()
    }

    /// Whether this row is one of the withheld ones.
    ///
    /// The key is read straight off the row view, the way the row-level-security
    /// policy reads it. A row whose first column is not an integer is not
    /// withheld, so a fixture over a table with a binary or text key cannot
    /// withhold anything and must not claim to.
    fn withholds<R>(&self, row: &R) -> bool
    where
        R: RowView<Backend = Postgres> + ?Sized,
    {
        matches!(row.value_at(0), Ok(Value::Int(key)) if self.withheld.contains(&key))
    }
}

impl VisibilityPolicy for RosterAuth {
    type Watcher = Arc<Principal>;
    type Error = Infallible;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), Infallible>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        if !self.withholds(row) {
            for (watcher, verdict) in watchers.iter().zip(verdicts.iter_mut()) {
                if self.grants(watcher) {
                    *verdict = Verdict::Allow;
                }
            }
        }
        ready(Ok(()))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_write<R>(
        &self,
        write: RowWrite<'_, R>,
        watcher: &Self::Watcher,
    ) -> Result<Verdict, Infallible>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let touches_withheld = match write {
            RowWrite::Insert { new } => self.withholds(new),
            RowWrite::Update { old, new } => self.withholds(old) || self.withholds(new),
            RowWrite::UpdateUsing { old } | RowWrite::Delete { old } => self.withholds(old),
            // The question learned a verb this does not know, so it refuses
            // rather than guessing which version it should have looked at.
            _ => true,
        };
        Ok(if touches_withheld || !self.grants(watcher) {
            Verdict::Deny
        } else {
            Verdict::Allow
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RosterAuth, WITHHELD_ID};
    use connetto_core::SessionId;
    use connetto_core::auth::{
        AuthContext, CapabilitySubject, Principal, Subject, VerifiedSession,
    };
    use std::sync::Arc;
    use subql::backend::{Postgres, Value};
    use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
    use subql::{ColumnId, TableId, ValueError};

    /// One row of one table, carrying an integer key and nothing else.
    struct Row(i64);

    impl RowView for Row {
        type Backend = Postgres;

        fn table_id(&self) -> TableId {
            0
        }

        fn value_at(&self, col: ColumnId) -> Result<Value<Postgres>, ValueError> {
            if col == 0 {
                Ok(Value::Int(self.0))
            } else {
                Ok(Value::Missing)
            }
        }
    }

    fn signed_in(user: &str) -> Arc<Principal> {
        let mut principal = Principal::unidentified(SessionId::from_token_hash(user));
        principal
            .accept(Subject::Identity(VerifiedSession {
                context: AuthContext::new(user),
                session_id: SessionId::from_token_hash(user),
            }))
            .expect("one identity");
        Arc::new(principal)
    }

    fn holding_a_key(key: &str) -> Arc<Principal> {
        let mut principal = Principal::unidentified(SessionId::from_token_hash(key));
        principal
            .accept(Subject::Capability(CapabilitySubject::new(key)))
            .expect("a capability");
        Arc::new(principal)
    }

    fn nobody() -> Arc<Principal> {
        Arc::new(Principal::unidentified(SessionId::from_token_hash(
            "nobody",
        )))
    }

    async fn verdicts(auth: &RosterAuth, key: i64, watchers: &[Arc<Principal>]) -> Vec<Verdict> {
        let mut answers = vec![Verdict::Deny; watchers.len()];
        auth.may_see(&Row(key), watchers, &mut answers)
            .await
            .expect("infallible");
        answers
    }

    #[tokio::test]
    async fn a_caller_the_roster_does_not_name_is_refused() {
        let auth = RosterAuth::granting("alice");
        let watchers = vec![signed_in("alice"), signed_in("mallory")];
        assert_eq!(
            verdicts(&auth, 1, &watchers).await,
            vec![Verdict::Allow, Verdict::Deny],
            "the roster names alice and nobody else"
        );
    }

    #[tokio::test]
    async fn a_roster_granting_nobody_refuses_every_caller() {
        let auth = RosterAuth::granting_nobody();
        let watchers = vec![signed_in("alice"), holding_a_key("key:abc"), nobody()];
        assert_eq!(
            verdicts(&auth, 1, &watchers).await,
            vec![Verdict::Deny; 3],
            "an empty roster grants nothing to anybody"
        );
    }

    #[tokio::test]
    async fn a_share_key_is_named_with_its_prefix() {
        let auth = RosterAuth::granting("key:abc");
        assert_eq!(
            verdicts(&auth, 1, &[holding_a_key("key:abc")]).await,
            vec![Verdict::Allow]
        );
        assert_eq!(
            verdicts(&auth, 1, &[holding_a_key("key:def")]).await,
            vec![Verdict::Deny],
            "another key is another subject"
        );
    }

    #[tokio::test]
    async fn the_unnamed_caller_is_refused_unless_the_roster_admits_it() {
        let refusing = RosterAuth::granting("alice");
        assert_eq!(
            verdicts(&refusing, 1, &[nobody()]).await,
            vec![Verdict::Deny]
        );

        let admitting = RosterAuth::granting("alice").and_the_unnamed_caller();
        assert_eq!(
            verdicts(&admitting, 1, &[nobody()]).await,
            vec![Verdict::Allow]
        );
        assert_eq!(
            verdicts(&admitting, 1, &[signed_in("mallory")]).await,
            vec![Verdict::Deny],
            "admitting the unnamed caller is not admitting a named one"
        );
    }

    #[tokio::test]
    async fn the_withheld_row_is_refused_to_a_granted_caller() {
        let auth = RosterAuth::granting("alice").withholding(WITHHELD_ID);
        let watchers = vec![signed_in("alice")];
        assert_eq!(verdicts(&auth, 1, &watchers).await, vec![Verdict::Allow]);
        assert_eq!(
            verdicts(&auth, WITHHELD_ID, &watchers).await,
            vec![Verdict::Deny],
            "the withheld row is refused to the caller the roster grants"
        );
    }

    #[tokio::test]
    async fn the_write_question_follows_the_same_two_rules() {
        let auth = RosterAuth::granting("alice").withholding(WITHHELD_ID);
        let alice = signed_in("alice");
        let mallory = signed_in("mallory");

        let own = Row(1);
        let withheld = Row(WITHHELD_ID);
        assert_eq!(
            auth.may_write(RowWrite::Insert { new: &own }, &alice)
                .await
                .expect("infallible"),
            Verdict::Allow
        );
        assert_eq!(
            auth.may_write(RowWrite::Insert { new: &own }, &mallory)
                .await
                .expect("infallible"),
            Verdict::Deny,
            "a caller the roster does not name writes nothing"
        );
        assert_eq!(
            auth.may_write(RowWrite::Delete { old: &withheld }, &alice)
                .await
                .expect("infallible"),
            Verdict::Deny,
            "the withheld row cannot be written either"
        );
        assert_eq!(
            auth.may_write(
                RowWrite::Update {
                    old: &own,
                    new: &withheld,
                },
                &alice,
            )
            .await
            .expect("infallible"),
            Verdict::Deny,
            "an update is judged on both versions"
        );
    }
}
