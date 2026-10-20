//! Fakes shared by the client and browser test suites.
//!
//! Behind the `test-support` feature, so nothing here reaches a production build.
//! It lives in the core rather than in a test file because four suites across two
//! crates and both targets need the same fake, and the only things it depends on
//! are the transport trait and the message types, which are here.

use crate::messages::{BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck};
use crate::traits::{IncomingFrame, Transport};
use crate::{Cursor, ReplicaKey, SchemaVersion};
use std::collections::VecDeque;

/// A fixed key for a test replica.
///
/// A durable replica is always encrypted, so a suite whose subject is something
/// else still needs a key to open one. Sharing the constant keeps those suites
/// from each inventing their own, and it is deliberately not the key any suite
/// that is actually about the codec uses.
#[must_use]
pub fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

/// A [`HandshakeAuthority`](crate::traits::HandshakeAuthority) that reads the
/// subject straight out of the grant string, performing no cryptographic
/// verification.
///
/// The test replacement for the deleted production default. It lives behind
/// `test-support` precisely because it checks nothing, so no production build
/// can reach it and no constructor installs it by default.
///
/// A grant is `user:<id>`, optionally `user:<id>#<run>`, `key:<subject>`,
/// optionally `key:<subject>@<unix seconds>`, or `bot:<id>#<entries>`.
/// Anything else is refused. The prefix stands in for
/// the `knd` claim the real checker reads out of a verified token: this
/// stand-in has no signature to carry one, so the string is all there is, and
/// mirroring the claim keeps every test explicit about which kind of grant it
/// presents.
///
/// The `@` form names the same subject with an expiry in unix seconds, the
/// stand-in for the `exp` claim a real capability token carries, and a
/// non-numeric suffix is refused like any other bad grant.
///
/// A `user:<id>#<run>` grant names one person holding several concurrent runs:
/// the part between the prefix and the `#` is the `user_id` and the whole
/// string seeds the handle, deterministically, so a reconnect on the same
/// grant keeps its watermark. A real deployment gets the handle from the auth
/// store, which mints a fresh one per login, so two devices of one person never
/// collide.
///
/// A `bot:<id>#<entries>` grant binds a bot's session settings the way a bot
/// login resolves them, with the identity before the `#` and the effective
/// list after it as `table:verb` entries joined by commas, and any other shape
/// is refused like a bad grant.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestGrantChecker;

impl crate::traits::HandshakeAuthority<String> for TestGrantChecker {
    fn check_grant<'a>(
        &'a self,
        grant: &'a crate::messages::Grant,
    ) -> crate::traits::GrantCheckFuture<'a, String> {
        Box::pin(async move {
            let token = grant.as_str();
            if let Some(named) = token.strip_prefix("key:") {
                let (subject, expires_at) = match named.split_once('@') {
                    None => (named.to_owned(), None),
                    Some((name, seconds)) => {
                        let seconds: u64 = seconds.parse().map_err(|_| {
                            crate::traits::GrantRefused::Invalid(format!(
                                "a capability grant's expiry spells no seconds: {seconds:?}"
                            ))
                        })?;
                        (name.to_owned(), Some(seconds))
                    }
                };
                if subject.is_empty() {
                    return Err(crate::traits::GrantRefused::Invalid(
                        "a capability grant named no subject".to_owned(),
                    ));
                }
                return Ok(crate::traits::CheckedGrant {
                    subject: crate::auth::Subject::Capability(crate::auth::CapabilitySubject::new(
                        format!("key:{subject}"),
                    )),
                    expires_at,
                });
            }
            if let Some(bot) = token.strip_prefix("bot:") {
                let (user_id, entries) = bot.split_once('#').ok_or_else(|| {
                    crate::traits::GrantRefused::Invalid("a bot grant names no entries".to_owned())
                })?;
                if user_id.is_empty() {
                    return Err(crate::traits::GrantRefused::Invalid(
                        "a bot grant named no user".to_owned(),
                    ));
                }
                let mut list = Vec::new();
                if !entries.is_empty() {
                    for entry in entries.split(crate::schema::BOT_LIST_SEPARATOR) {
                        let (table, verb) = entry.split_once(':').ok_or_else(|| {
                            crate::traits::GrantRefused::Invalid(format!(
                                "a bot list entry names no verb: {entry:?}"
                            ))
                        })?;
                        if table.is_empty() {
                            return Err(crate::traits::GrantRefused::Invalid(
                                "a bot list entry names no table".to_owned(),
                            ));
                        }
                        let Some(verb) = crate::bots::Verb::parse(verb) else {
                            return Err(crate::traits::GrantRefused::Invalid(format!(
                                "a bot list entry spells no verb: {verb:?}"
                            )));
                        };
                        list.push((table.to_owned(), verb));
                    }
                }
                return Ok(crate::traits::CheckedGrant {
                    subject: crate::auth::Subject::Identity(crate::auth::VerifiedSession {
                        context: crate::auth::AuthContext::new(user_id),
                        session_id: crate::SessionId::from_token_hash(token),
                        bot_list: Some(crate::bots::BotList::new(list)),
                    }),
                    expires_at: None,
                });
            }
            let Some(named) = token.strip_prefix("user:") else {
                return Err(crate::traits::GrantRefused::Invalid(format!(
                    "a grant naming neither a user, a key nor a bot: {token:?}"
                )));
            };
            let user_id = named.split_once('#').map_or(named, |(user, _run)| user);
            if user_id.is_empty() {
                return Err(crate::traits::GrantRefused::Invalid(
                    "a login grant named no user".to_owned(),
                ));
            }
            Ok(crate::traits::CheckedGrant {
                subject: crate::auth::Subject::Identity(crate::auth::VerifiedSession {
                    context: crate::auth::AuthContext::new(user_id),
                    session_id: crate::SessionId::from_token_hash(token),
                    bot_list: None,
                }),
                expires_at: None,
            })
        })
    }

    /// A handle blob with no signature over it, which is why this type is
    /// confined to `test-support`. It still refuses anything not of its own
    /// shape, so a caller cannot present a bare handle it invented.
    fn mint_handle(
        &self,
        session_id: crate::SessionId,
    ) -> Result<String, crate::traits::HandleError> {
        Ok(format!("run:{session_id}"))
    }

    fn read_handle(&self, blob: &str) -> Result<crate::SessionId, crate::traits::HandleError> {
        blob.strip_prefix("run:")
            .and_then(|handle| handle.parse().ok())
            .ok_or_else(|| crate::traits::HandleError(format!("not a test handle: {blob:?}")))
    }
}

/// How a [`FakeTransport`] answers the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeReply {
    /// A well-formed acknowledgement, so the handshake succeeds.
    Accept,
    /// `FatalError(reason)`, so the connection never opens. No grant produces
    /// this: a refused grant leaves the connection open and says nothing, so
    /// the reasons a real server sends here are a version mismatch, a newer
    /// connection on the same handle, and a shutdown.
    Refuse(FatalErrorReason),
}

/// The typed error the transport trait requires.
#[derive(Debug, thiserror::Error)]
pub enum FakeTransportError {
    /// The peer is gone.
    #[error("fake transport closed")]
    Closed,
    /// A bulk send was rejected, as a connection reset under an upload does.
    #[error("fake transport rejected a bulk send")]
    BulkRejected,
}

/// A transport that answers the handshake with a canned reply and drops
/// everything else on the floor.
///
/// Enough to drive `connect`, `connect_existing`, and `resume` with no server.
/// Because it acknowledges nothing after the handshake, an uploaded mutation is
/// never retired, which is how a test arranges a replica that still has unsynced
/// work in it.
///
/// By default a drained inbox reads as end of stream, so the peer looks gone. That
/// suits a test driving a connection directly, and not one behind a task that reads
/// the upstream continuously, which would see the close and stop. For those,
/// [`accepting_but_silent`](Self::accepting_but_silent) stays open instead.
pub struct FakeTransport {
    reply: HandshakeReply,
    inbox: VecDeque<IncomingFrame>,
    /// Park on a drained inbox rather than reporting end of stream.
    silent: bool,
    /// Delivered once, right after the handshake ack, as a deliberate server
    /// close (a shutdown or a revocation) does.
    closing: Option<FatalErrorReason>,
    /// Delivered in order right after the handshake ack, so a test can drive
    /// the frames a connected session would receive (a snapshot, a live patch,
    /// an aggregate push) before the stream drains and the peer looks gone.
    post_handshake: VecDeque<IncomingFrame>,
    /// Fail every bulk send, as a connection reset under an upload does.
    bulk_fails: bool,
}

impl FakeTransport {
    /// A transport whose handshake succeeds.
    #[must_use]
    pub fn accepting() -> Self {
        Self::new(HandshakeReply::Accept)
    }

    /// A transport that closes the connection at the handshake, carrying
    /// `reason`. No grant produces this, so the reasons a real server sends
    /// here are a version mismatch, a newer connection on the same handle, and
    /// a shutdown.
    #[must_use]
    pub fn refusing(reason: FatalErrorReason) -> Self {
        Self::new(HandshakeReply::Refuse(reason))
    }

    /// A transport whose handshake succeeds and which then stays open forever
    /// without saying anything, so an uploaded mutation is neither acknowledged nor
    /// failed. This is a client that is connected but offline, as opposed to one
    /// whose peer has gone.
    #[must_use]
    pub fn accepting_but_silent() -> Self {
        Self {
            silent: true,
            ..Self::new(HandshakeReply::Accept)
        }
    }

    /// A transport whose handshake succeeds and which then closes the session
    /// deliberately, carrying `reason`, as a graceful shutdown or a mid-session
    /// revocation does.
    #[must_use]
    pub fn accepting_then_closing(reason: FatalErrorReason) -> Self {
        Self {
            closing: Some(reason),
            ..Self::new(HandshakeReply::Accept)
        }
    }

    /// A transport whose handshake succeeds and which then delivers `frames`
    /// in order, as a connected session's snapshot, live patches, or aggregate
    /// pushes arrive, before the stream drains and the peer looks gone.
    #[must_use]
    pub fn accepting_then_delivering(frames: impl IntoIterator<Item = IncomingFrame>) -> Self {
        Self {
            post_handshake: frames.into_iter().collect(),
            ..Self::new(HandshakeReply::Accept)
        }
    }

    /// A transport whose handshake succeeds, which then stays open without saying
    /// anything, and which fails every bulk send, as a reset under an upload does.
    #[must_use]
    pub fn accepting_but_failing_bulk() -> Self {
        Self {
            bulk_fails: true,
            ..Self::accepting_but_silent()
        }
    }

    /// A transport answering with `reply`, whose peer looks gone once its inbox
    /// drains.
    #[must_use]
    pub fn new(reply: HandshakeReply) -> Self {
        Self {
            reply,
            inbox: VecDeque::new(),
            silent: false,
            closing: None,
            post_handshake: VecDeque::new(),
            bulk_fails: false,
        }
    }

    fn answer(&self) -> IncomingFrame {
        match &self.reply {
            HandshakeReply::Accept => {
                IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
                    connection_id: "connection-fake".to_owned(),
                    session_token: "00000000-0000-4000-8000-000000000000".to_owned(),
                    resume_token: "run:00000000-0000-4000-8000-000000000000".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None::<SchemaVersion>,
                    initial_credits: 64,
                    last_applied_seq: None,
                }))
            }
            HandshakeReply::Refuse(reason) => {
                IncomingFrame::Control(ControlMessage::FatalError(FatalError::new(reason.clone())))
            }
        }
    }
}

impl Transport for FakeTransport {
    type Error = FakeTransportError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeTransportError> {
        if matches!(message, ControlMessage::Handshake(_)) {
            let frame = self.answer();
            self.inbox.push_back(frame);
            self.inbox.append(&mut self.post_handshake);
            if let Some(reason) = self.closing.take() {
                self.inbox
                    .push_back(IncomingFrame::Control(ControlMessage::FatalError(
                        FatalError::new(reason),
                    )));
            }
        }
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeTransportError> {
        if self.bulk_fails {
            return Err(FakeTransportError::BulkRejected);
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeTransportError> {
        if let Some(frame) = self.inbox.pop_front() {
            return Ok(Some(frame));
        }
        if self.silent {
            core::future::pending::<()>().await;
        }
        Ok(None)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn close(&mut self) -> Result<(), FakeTransportError> {
        Ok(())
    }
}

/// Two accounts on one device, driven through a
/// [`RefreshTokenStore`](crate::traits::RefreshTokenStore) by name
/// alone.
///
/// One caller written against the trait rather than against any store, run
/// against every implementation. That is the property the seam exists to buy.
///
/// Both records are cleared on the way in and on the way out, so a durable
/// store survives a rerun.
///
/// # Panics
///
/// If either account reads back anything but its own token.
pub async fn two_accounts_keep_their_own_token<S: crate::traits::RefreshTokenStore>(
    store: &S,
    alice: &str,
    bob: &str,
) {
    assert_ne!(alice, bob, "the two accounts must differ");
    store.clear(alice).await.expect("clear alice");
    store.clear(bob).await.expect("clear bob");

    assert_eq!(
        store.load(alice).await.expect("load alice"),
        None,
        "starts empty"
    );

    store
        .store(alice, "alice-refresh")
        .await
        .expect("store alice");
    assert_eq!(
        store.load(bob).await.expect("load bob"),
        None,
        "alice's write did not reach bob"
    );

    store.store(bob, "bob-refresh").await.expect("store bob");
    assert_eq!(
        store.load(alice).await.expect("load alice").as_deref(),
        Some("alice-refresh"),
        "alice reads her own token back"
    );
    assert_eq!(
        store.load(bob).await.expect("load bob").as_deref(),
        Some("bob-refresh"),
        "and bob his"
    );

    store.clear(alice).await.expect("clear alice");
    assert_eq!(
        store.load(alice).await.expect("load alice"),
        None,
        "the clear removed alice"
    );
    assert_eq!(
        store.load(bob).await.expect("load bob").as_deref(),
        Some("bob-refresh"),
        "and left bob alone"
    );
    store.clear(bob).await.expect("clear bob");
}

/// Every stored account is listed, and connetto's own records are not, driven
/// through a [`RefreshTokenStore`](crate::traits::RefreshTokenStore) by name
/// alone.
///
/// The sibling of [`two_accounts_keep_their_own_token`] and the same doctrine:
/// one caller written against the trait, run against every implementation.
///
/// `reserved` is one of connetto's own record names, which the caller supplies
/// because the core does not define them. Writing it and finding it absent from
/// the list is the load-bearing assertion here: a reserved record shares the key
/// namespace with the accounts, and offering one as somebody to sign in as would
/// put a credential nobody owns in front of a user.
///
/// Order carries no meaning, so nothing here asserts one.
///
/// # Panics
///
/// If a stored account is missing from the list, a cleared one survives in it, or
/// a reserved record appears in it.
pub async fn every_stored_account_is_listed<S: crate::traits::RefreshTokenStore>(
    store: &S,
    alice: &str,
    bob: &str,
    reserved: &str,
) {
    assert_ne!(alice, bob, "the two accounts must differ");
    for name in [alice, bob, reserved] {
        store.clear(name).await.expect("clear");
    }

    let listed = store.accounts().await.expect("list an empty store");
    assert!(
        !listed.contains(&alice.to_owned()) && !listed.contains(&bob.to_owned()),
        "an empty store offers neither account, got {listed:?}"
    );

    store
        .store(alice, "alice-refresh")
        .await
        .expect("store alice");
    let listed = store.accounts().await.expect("list one account");
    assert!(listed.contains(&alice.to_owned()), "alice is listed");
    assert!(
        !listed.contains(&bob.to_owned()),
        "bob is not, having stored nothing"
    );

    store.store(bob, "bob-refresh").await.expect("store bob");
    let listed = store.accounts().await.expect("list two accounts");
    assert!(
        listed.contains(&alice.to_owned()) && listed.contains(&bob.to_owned()),
        "both accounts are signed in at once, got {listed:?}"
    );

    store
        .store(reserved, "not-an-account")
        .await
        .expect("store the reserved record");
    let listed = store.accounts().await.expect("list past a reserved record");
    assert!(
        !listed.contains(&reserved.to_owned()),
        "connetto's own record is not somebody to sign in as, got {listed:?}"
    );
    assert!(
        listed.contains(&alice.to_owned()) && listed.contains(&bob.to_owned()),
        "and it hid neither account, got {listed:?}"
    );

    store.clear(alice).await.expect("clear alice");
    let listed = store.accounts().await.expect("list after a clear");
    assert!(
        !listed.contains(&alice.to_owned()),
        "a signed-out account is no longer offered, got {listed:?}"
    );
    assert!(
        listed.contains(&bob.to_owned()),
        "and the other stays signed in, got {listed:?}"
    );

    for name in [bob, reserved] {
        store.clear(name).await.expect("clear");
    }
}

/// Two accounts on one device, driven through a
/// [`ReplicaKeyStore`](crate::traits::ReplicaKeyStore) by name alone. The
/// awaiting twin of [`two_accounts_keep_their_own_token`], and the same
/// property.
///
/// # Panics
///
/// If either record reads back anything but its own key.
pub async fn two_accounts_keep_their_own_key<S: crate::traits::ReplicaKeyStore>(
    store: &S,
    alice: &str,
    bob: &str,
) {
    assert_ne!(alice, bob, "the two records must differ");
    let alice_key = ReplicaKey::from_bytes([0xa1; ReplicaKey::LEN]);
    let bob_key = ReplicaKey::from_bytes([0xb2; ReplicaKey::LEN]);
    store.clear(alice).await.expect("clear alice");
    store.clear(bob).await.expect("clear bob");

    assert_eq!(
        store.load(alice).await.expect("load alice"),
        None,
        "starts empty"
    );

    store
        .store(alice, &alice_key)
        .await
        .expect("store alice's key");
    assert_eq!(
        store.load(bob).await.expect("load bob"),
        None,
        "alice's write did not reach bob"
    );

    store.store(bob, &bob_key).await.expect("store bob's key");
    assert_eq!(
        store.load(alice).await.expect("load alice"),
        Some(alice_key),
        "alice reads her own key back"
    );
    assert_eq!(
        store.load(bob).await.expect("load bob"),
        Some(bob_key.clone()),
        "and bob his"
    );

    store.clear(alice).await.expect("clear alice");
    assert_eq!(
        store.load(alice).await.expect("load alice"),
        None,
        "the clear crypto-shredded alice"
    );
    assert_eq!(
        store.load(bob).await.expect("load bob"),
        Some(bob_key),
        "and left bob openable"
    );
    store.clear(bob).await.expect("clear bob");
}

#[cfg(test)]
mod tests {
    use crate::auth::{CapabilitySubject, Subject};
    use crate::messages::Grant;
    use crate::traits::{CheckedGrant, GrantRefused, HandshakeAuthority};

    use super::TestGrantChecker;

    fn check(grant: &str) -> Result<CheckedGrant, GrantRefused> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build a runtime");
        runtime.block_on(async { TestGrantChecker.check_grant(&Grant::new(grant)).await })
    }

    /// A `bot:` grant resolves to an identity carrying the list it names, and
    /// a person's grant resolves none.
    #[test]
    fn a_bot_grant_binds_the_list_it_names() {
        let subject = check("bot:bot-a#t:read,t:insert")
            .expect("the grant resolves")
            .subject;
        let Subject::Identity(session) = subject else {
            panic!("a bot grant resolves a login");
        };
        assert_eq!(session.context.user_id, "bot-a");
        let list = session.bot_list.expect("the grant names a list");
        assert_eq!(
            list.entries(),
            &[
                ("t".to_owned(), crate::bots::Verb::Read),
                ("t".to_owned(), crate::bots::Verb::Insert),
            ]
        );

        let subject = check("user:alice").expect("the grant resolves").subject;
        let Subject::Identity(person) = subject else {
            panic!("a person grant resolves a login");
        };
        assert!(person.bot_list.is_none());
    }

    /// A bot grant naming no entries binds the empty list, which sees nothing.
    #[test]
    fn a_bot_grant_with_no_entries_is_an_empty_list() {
        let subject = check("bot:bot-a#").expect("the grant resolves").subject;
        let Subject::Identity(session) = subject else {
            panic!("a bot grant resolves a login");
        };
        assert!(session.bot_list.expect("the grant names a list").is_empty());
    }

    /// An entry outside the shape is refused like any other bad grant.
    #[test]
    fn a_bot_grant_entry_outside_the_shape_is_refused() {
        for grant in [
            "bot:bot-a",
            "bot:#t:read",
            "bot:bot-a#t:drop",
            "bot:bot-a#t",
            "bot:bot-a#:read",
            "bot:bot-a#t:read,,",
        ] {
            assert!(check(grant).is_err(), "{grant:?} is refused");
        }
    }

    /// A `key:` grant never expires, the `@` form names its expiry in unix
    /// seconds, and a login names none.
    #[test]
    fn a_key_grant_reports_the_expiry_it_names() {
        let plain = check("key:abc").expect("the grant resolves");
        assert_eq!(
            plain,
            CheckedGrant {
                subject: Subject::Capability(CapabilitySubject::new("key:abc")),
                expires_at: None,
            }
        );

        let bounded = check("key:abc@1700000000").expect("the grant resolves");
        assert_eq!(
            bounded,
            CheckedGrant {
                subject: Subject::Capability(CapabilitySubject::new("key:abc")),
                expires_at: Some(1_700_000_000),
            }
        );

        let login = check("user:alice").expect("the grant resolves");
        assert_eq!(login.expires_at, None);
    }

    /// A capability expiry that spells no seconds is refused like any other
    /// bad grant.
    #[test]
    fn a_key_grant_with_a_bad_expiry_is_refused() {
        for grant in [
            "key:@1700000000",
            "key:abc@",
            "key:abc@soon",
            "key:abc@17:00",
        ] {
            assert!(check(grant).is_err(), "{grant:?} is refused");
        }
    }
}
