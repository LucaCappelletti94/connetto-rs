//! connetto-client: the native local-first sync client.
//!
//! A transparent sync layer over a `connetto-server`. The application runs
//! ordinary diesel queries against a managed local SQLite connection; the client
//! does the rest.
//!
//! * **Local writes** are captured by a SQLite session hooked onto the
//!   application's connection ([`SqliteSessionExt`]). [`SyncClient::push`] drains
//!   that session into a changeset (which carries the old row image, so the
//!   server's conflict check works), compresses it, and uploads it as a
//!   `MutationHeader` plus `MutationPatch`.
//! * **Server patches** (the initial snapshot and live updates) apply to a
//!   sibling connection to the same database file. A session tracks only writes
//!   made on the connection it is attached to, so applying on the sibling
//!   bypasses the capture session and server-originated changes are never
//!   re-uploaded (no echo loop). The application's connection sees them through
//!   SQLite WAL.
//!
//! The server produces its patches with `sqlite-diff-rs`, whose output is the
//! native SQLite session patchset format, so the client applies them directly
//! with [`SqliteSessionExt::apply_patchset`]. No catalog or `subql` engine lives
//! on the client.
//!
//! The client is single-threaded ([`diesel_sqlite_session::Session`] holds a raw
//! SQLite handle and is `!Send`): drive it from one task with
//! [`SyncClient::pump_one`], interleaving [`SyncClient::push`] after local
//! writes.

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Handshake, MutationHeader, MutationPatch, Ping,
    Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use diesel::connection::SimpleConnection;
use diesel::{Connection, SqliteConnection};
use diesel_sqlite_session::{ConflictAction, ConflictType, Session, SqliteSessionExt};

/// Zstd level for outbound mutation payloads. Level 3 is the library default.
const ZSTD_LEVEL: i32 = 3;

/// Failure surfaced by the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The server violated the expected wire sequence.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// The SQLite capture session failed.
    #[error("session error: {0}")]
    Session(String),
    /// Applying a server patch to the local replica failed.
    #[error("apply error: {0}")]
    Apply(String),
    /// A local database operation failed.
    #[error(transparent)]
    Db(#[from] diesel::result::Error),
    /// Connecting the local database failed.
    #[error("database connection error: {0}")]
    Connect(String),
    /// Zstd compression or decompression failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
}

/// Client identity presented at handshake.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Stable client id, echoed for logging and correlation.
    pub client_id: String,
    /// Opaque auth token validated by the server at connect.
    pub auth_token: String,
}

/// One observable outcome of [`SyncClient::pump_one`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// The server began an initial snapshot for a subscription.
    SnapshotBegin {
        /// Subscription id.
        sub_id: String,
    },
    /// A snapshot chunk was applied to the local replica.
    SnapshotApplied {
        /// Subscription id.
        sub_id: String,
    },
    /// The server finished the initial snapshot; the resume cursor advanced.
    SnapshotEnd {
        /// Subscription id.
        sub_id: String,
    },
    /// A live patch was applied; the resume cursor advanced to `cursor`.
    LivePatch {
        /// Subscription id.
        sub_id: String,
        /// New resume cursor persisted after applying this patch.
        cursor: Cursor,
    },
    /// An aggregate result update.
    Aggregate {
        /// Subscription id.
        sub_id: String,
        /// JSON-encoded aggregate value.
        result_json: String,
    },
    /// The server requires a full resync for this subscription.
    FullResync {
        /// Subscription id.
        sub_id: String,
    },
    /// The server rejected a prior mutation.
    MutationRejected {
        /// The rejected mutation's sequence number.
        client_seq: u64,
    },
    /// The server reported a conflict on a prior mutation.
    MutationConflict {
        /// The conflicting mutation's sequence number.
        client_seq: u64,
    },
    /// A keepalive reply.
    Pong {
        /// Echoed nonce.
        nonce: u64,
    },
    /// The connection closed.
    Closed,
}

/// Conflict resolution for applying authoritative server patches: the server
/// wins on a data or version conflict, and a missing target is skipped so a
/// replayed delete or update is idempotent.
fn server_wins(conflict: ConflictType) -> ConflictAction {
    match conflict {
        ConflictType::Data | ConflictType::Conflict => ConflictAction::Replace,
        _ => ConflictAction::Omit,
    }
}

/// Count the ops in a captured changeset for the advisory `MutationHeader`.
fn count_ops(changeset: &[u8]) -> u32 {
    match sqlite_diff_rs::ParsedDiffSet::parse(changeset) {
        Ok(sqlite_diff_rs::ParsedDiffSet::Changeset(diff)) => {
            u32::try_from(diff.iter().count()).unwrap_or(u32::MAX)
        }
        Ok(sqlite_diff_rs::ParsedDiffSet::Patchset(diff)) => {
            u32::try_from(diff.iter().count()).unwrap_or(u32::MAX)
        }
        Err(_) => 0,
    }
}

/// A native sync client bound to one transport and one local SQLite database.
pub struct SyncClient<T: Transport> {
    transport: T,
    // `session` is declared before `dev` so it drops first: it holds a raw
    // pointer into the connection's SQLite handle and must not outlive it.
    session: Session,
    dev: SqliteConnection,
    apply: SqliteConnection,
    last_cursor: Option<Cursor>,
    next_seq: u64,
    session_id: String,
}

impl<T> SyncClient<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Connect: open the local database, hook the capture session, and run the
    /// handshake.
    ///
    /// `db_path` must be a real file path (not `:memory:`) so the capture and
    /// apply connections share it. `sqlite_ddl` creates the local schema. Pass
    /// `resume` to continue from a persisted cursor on reconnect.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, session, transport, or handshake failure.
    pub async fn connect(
        mut transport: T,
        db_path: &str,
        sqlite_ddl: &str,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut apply = SqliteConnection::establish(db_path)
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        apply.batch_execute("PRAGMA journal_mode=WAL")?;
        apply.batch_execute(sqlite_ddl)?;

        let mut dev = SqliteConnection::establish(db_path)
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        dev.batch_execute("PRAGMA journal_mode=WAL")?;
        let mut session = dev
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        session
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;

        let mut handshake = Handshake::new(
            PROTOCOL_VERSION,
            config.client_id.clone(),
            config.auth_token.clone(),
        );
        if let Some(cursor) = resume.clone() {
            handshake = handshake.with_cursor(cursor);
        }
        transport
            .send_control(ControlMessage::Handshake(handshake))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let session_id = match transport
            .recv()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
        {
            Some(IncomingFrame::Control(ControlMessage::HandshakeAck(ack))) => ack.session_id,
            Some(_) => return Err(ClientError::Protocol("expected handshake ack".into())),
            None => return Err(ClientError::Protocol("connection closed before ack".into())),
        };

        Ok(Self {
            transport,
            session,
            dev,
            apply,
            last_cursor: resume,
            next_seq: 0,
            session_id,
        })
    }

    /// The server-assigned session id from the handshake ack.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The application's local connection, for ordinary diesel reads and writes.
    /// Writes here are captured for upload on the next [`push`](Self::push).
    pub const fn conn(&mut self) -> &mut SqliteConnection {
        &mut self.dev
    }

    /// The highest resume cursor applied so far, if any.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.last_cursor.as_ref()
    }

    /// Declare a row subscription.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the subscribe frame cannot be sent.
    pub async fn subscribe(&mut self, sub_id: &str, query: &str) -> Result<(), ClientError> {
        self.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec: SubscriptionSpec::row(query),
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Read one inbound frame, apply it if it is a patch, and report what
    /// happened. Applying a bulk patch replenishes one delivery credit.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn pump_one(&mut self) -> Result<ClientEvent, ClientError> {
        match self
            .transport
            .recv()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
        {
            None => Ok(ClientEvent::Closed),
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd)?;
                self.ack_one().await?;
                Ok(ClientEvent::SnapshotApplied {
                    sub_id: patch.sub_id,
                })
            }
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd)?;
                self.last_cursor = Some(patch.cursor.clone());
                self.ack_one().await?;
                Ok(ClientEvent::LivePatch {
                    sub_id: patch.sub_id,
                    cursor: patch.cursor,
                })
            }
            Some(IncomingFrame::Bulk(_)) => Err(ClientError::Protocol(
                "unexpected bulk frame from server".into(),
            )),
            Some(IncomingFrame::Control(msg)) => self.handle_control(msg),
        }
    }

    /// Send a keepalive probe. The matching [`ClientEvent::Pong`] from a later
    /// [`pump_one`](Self::pump_one) doubles as a barrier: the server processes
    /// frames in order, so a pong proves every preceding frame was handled.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the ping cannot be sent.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), ClientError> {
        self.transport
            .send_control(ControlMessage::Ping(Ping { nonce }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Upload local writes captured since the last push as one mutation.
    ///
    /// Returns the assigned `client_seq`, or `None` when there was nothing to
    /// send. The capture session is reset afterward so the next push sees only
    /// subsequent writes.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a session, compression, or transport failure.
    pub async fn push(&mut self) -> Result<Option<u64>, ClientError> {
        let changeset = self
            .session
            .changeset()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if changeset.is_empty() {
            return Ok(None);
        }
        let op_count = count_ops(&changeset);
        let seq = self.next_seq;
        self.next_seq += 1;
        let payload = zstd::encode_all(changeset.as_slice(), ZSTD_LEVEL)?;
        self.transport
            .send_control(ControlMessage::MutationHeader(MutationHeader::new(
                seq, op_count,
            )))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.transport
            .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(seq, payload)))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        // Reset capture: a fresh session records only writes after this push.
        let mut fresh = self
            .dev
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        fresh
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        self.session = fresh;
        Ok(Some(seq))
    }

    /// Close the transport.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the close fails.
    pub async fn close(&mut self) -> Result<(), ClientError> {
        self.transport
            .close()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    fn handle_control(&mut self, msg: ControlMessage) -> Result<ClientEvent, ClientError> {
        match msg {
            ControlMessage::SnapshotBegin(begin) => Ok(ClientEvent::SnapshotBegin {
                sub_id: begin.sub_id,
            }),
            ControlMessage::SnapshotEnd(end) => {
                self.last_cursor = Some(end.cursor);
                Ok(ClientEvent::SnapshotEnd { sub_id: end.sub_id })
            }
            ControlMessage::AggregateUpdate(update) => Ok(ClientEvent::Aggregate {
                sub_id: update.sub_id,
                result_json: update.result_json,
            }),
            ControlMessage::FullResyncRequired(resync) => Ok(ClientEvent::FullResync {
                sub_id: resync.sub_id,
            }),
            ControlMessage::MutationReject(reject) => Ok(ClientEvent::MutationRejected {
                client_seq: reject.client_seq,
            }),
            ControlMessage::MutationConflict(conflict) => Ok(ClientEvent::MutationConflict {
                client_seq: conflict.client_seq,
            }),
            ControlMessage::Pong(pong) => Ok(ClientEvent::Pong { nonce: pong.nonce }),
            other => Err(ClientError::Protocol(format!(
                "unexpected control frame from server: {other:?}"
            ))),
        }
    }

    fn apply_patch(&mut self, payload_zstd: &[u8]) -> Result<(), ClientError> {
        let bytes = zstd::decode_all(payload_zstd)?;
        self.apply
            .apply_patchset(&bytes, server_wins)
            .map_err(|e| ClientError::Apply(e.to_string()))
    }

    async fn ack_one(&mut self) -> Result<(), ClientError> {
        self.transport
            .send_control(ControlMessage::AckCredits(AckCredits { credits: 1 }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}
