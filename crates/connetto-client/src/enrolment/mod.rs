//! Enrolling this device's key with the server (R74 step 3, decisions 18 and 19).

use core::time::Duration;
use std::time::SystemTime;

use connetto_core::device_cert::DeviceCertificate;
use connetto_core::messages::{ControlMessage, DeviceSummary, EnrolRefusal, SignedList};
use connetto_core::traits::Transport;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use tokio::sync::{mpsc, oneshot};

use crate::{ClientError, ConnettoConnection, SuspendedCapture};

mod task;

#[cfg(feature = "peer")]
pub(crate) use task::Peer;
pub use task::{CertificateError, DeviceEntry};
pub(crate) use task::{DeviceKeys, EnrolHandle, Enroller, Link, PlatformKeys, run};
#[cfg(test)]
use task::{Intake, intake};

diesel::table! {
    /// The device's certificate, one row, kept beside the replica's other bookkeeping.
    _connetto_device_certificate (id) {
        id -> Integer,
        certificate -> Binary,
        issuer -> Binary,
        lifetime_secs -> Nullable<BigInt>,
    }
}

diesel::table! {
    /// The verified revocation list kept per signer, the highest-numbered one.
    _connetto_revocation_list (signer_key) {
        signer_key -> Binary,
        number -> BigInt,
        list -> Binary,
        signer -> Binary,
    }
}

/// Creates the certificate and list tables on every open of a replica that enrols.
pub(crate) const CERTIFICATE_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_device_certificate \
     (id INTEGER PRIMARY KEY CHECK (id = 1), certificate BLOB NOT NULL, issuer BLOB NOT NULL, \
     lifetime_secs INTEGER); \
     CREATE TABLE IF NOT EXISTS _connetto_revocation_list \
     (signer_key BLOB PRIMARY KEY, number INTEGER NOT NULL, list BLOB NOT NULL, signer BLOB NOT NULL)";

/// Where the enrolment task receives the lists the server pushes.
pub(crate) type ListInbox = mpsc::UnboundedReceiver<Vec<SignedList>>;

/// How far a local clock may disagree before a certificate counts as outside its window.
pub(crate) const TOLERANCE: Duration = Duration::from_mins(5);

/// A server's answer to one enrolment request.
#[derive(Debug)]
pub(crate) enum Answer {
    /// The nonce the request must carry.
    Challenge([u8; 32]),
    /// The certificate, then its issuer, and the lists the device should hold.
    Grant(Vec<Vec<u8>>, Vec<SignedList>),
    /// The account's devices.
    Devices(Vec<DeviceSummary>),
    /// A device was revoked.
    Revoked,
    /// Why the server refused.
    Refused(EnrolRefusal),
}

impl Answer {
    /// Whether `msg` answers an enrolment request.
    pub(crate) const fn is_answer(msg: &ControlMessage) -> bool {
        matches!(
            msg,
            ControlMessage::EnrolChallenge(_)
                | ControlMessage::EnrolGrant(_)
                | ControlMessage::EnrolRefused(_)
                | ControlMessage::DevicesList(_)
                | ControlMessage::DeviceRevokedAck(_)
        )
    }

    /// The answer `msg` carries and the request it quotes, `None` when it is
    /// no enrolment answer.
    pub(crate) fn of(msg: ControlMessage) -> Option<(String, Self)> {
        match msg {
            ControlMessage::EnrolChallenge(challenge) => {
                Some((challenge.request_id, Self::Challenge(challenge.nonce)))
            }
            ControlMessage::EnrolGrant(grant) => Some((
                grant.request_id,
                Self::Grant(
                    grant
                        .chain
                        .into_iter()
                        .map(serde_bytes::ByteBuf::into_vec)
                        .collect(),
                    grant.revocation_lists,
                ),
            )),
            ControlMessage::DevicesList(list) => {
                Some((list.request_id, Self::Devices(list.devices)))
            }
            ControlMessage::DeviceRevokedAck(ack) => Some((ack.request_id, Self::Revoked)),
            ControlMessage::EnrolRefused(refused) => {
                Some((refused.request_id, Self::Refused(refused.reason)))
            }
            _ => None,
        }
    }
}

/// The certificate this device holds.
#[derive(Debug, Clone)]
pub(crate) struct Held {
    pub(crate) leaf: DeviceCertificate,
    pub(crate) certificate: Vec<u8>,
    pub(crate) issuer: Vec<u8>,
    /// The lifetime renewals ask for, the server's default when `None`.
    pub(crate) lifetime: Option<Duration>,
}

/// Where a held certificate stands by the local clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Standing {
    /// No certificate.
    NoKey,
    /// Valid and before half-life.
    Fresh,
    /// Valid and past half-life.
    Aging,
    /// Past its end plus the tolerance.
    Expired,
    /// Not yet valid by more than the tolerance, so the local clock is off.
    ClockOff,
}

impl Standing {
    pub(crate) fn of(held: Option<&Held>, now: SystemTime) -> Self {
        Self::of_leaf(held.map(|held| &held.leaf), now)
    }

    /// Where a bare certificate stands at `now`, for a caller that holds
    /// only the parsed leaf (R76).
    pub(crate) fn of_leaf(leaf: Option<&DeviceCertificate>, now: SystemTime) -> Self {
        let Some(leaf) = leaf else {
            return Self::NoKey;
        };
        let (start, end) = (leaf.not_before(), leaf.not_after());
        if now + TOLERANCE < start {
            return Self::ClockOff;
        }
        if now > end + TOLERANCE {
            return Self::Expired;
        }
        if now >= half_life_leaf(leaf) {
            Self::Aging
        } else {
            Self::Fresh
        }
    }
}

/// The moment `held` crosses half its lifetime.
pub(crate) fn half_life(held: &Held) -> SystemTime {
    half_life_leaf(&held.leaf)
}

/// The moment `leaf` crosses half its validity.
pub(crate) fn half_life_leaf(leaf: &DeviceCertificate) -> SystemTime {
    let (start, end) = (leaf.not_before(), leaf.not_after());
    start + end.duration_since(start).unwrap_or_default() / 2
}

fn load(db: &mut SqliteConnection) -> Result<Option<Held>, ClientError> {
    use _connetto_device_certificate::dsl;
    let row: Option<(Vec<u8>, Vec<u8>, Option<i64>)> = dsl::_connetto_device_certificate
        .select((dsl::certificate, dsl::issuer, dsl::lifetime_secs))
        .first(db)
        .optional()?;
    Ok(row.and_then(|(certificate, issuer, lifetime)| {
        let leaf = DeviceCertificate::parse(&certificate).ok()?;
        Some(Held {
            leaf,
            certificate,
            issuer,
            lifetime: lifetime
                .and_then(|secs| u64::try_from(secs).ok())
                .map(Duration::from_secs),
        })
    }))
}

fn store(db: &mut SqliteConnection, held: &Held) -> Result<(), ClientError> {
    use _connetto_device_certificate::dsl;
    let lifetime = held
        .lifetime
        .map(|lifetime| i64::try_from(lifetime.as_secs()).unwrap_or(i64::MAX));
    diesel::replace_into(dsl::_connetto_device_certificate)
        .values((
            dsl::id.eq(1),
            dsl::certificate.eq(&held.certificate),
            dsl::issuer.eq(&held.issuer),
            dsl::lifetime_secs.eq(lifetime),
        ))
        .execute(db)?;
    Ok(())
}

/// One kept list, by the key identifier of its signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptList {
    pub(crate) signer_key: Vec<u8>,
    pub(crate) number: u64,
    pub(crate) list: Vec<u8>,
    pub(crate) signer: Vec<u8>,
}

#[derive(Queryable)]
struct ListRow {
    signer_key: Vec<u8>,
    number: i64,
    list: Vec<u8>,
    signer: Vec<u8>,
}

fn load_lists(db: &mut SqliteConnection) -> Result<Vec<KeptList>, ClientError> {
    use _connetto_revocation_list::dsl;
    let rows: Vec<ListRow> = dsl::_connetto_revocation_list
        .select((dsl::signer_key, dsl::number, dsl::list, dsl::signer))
        .load(db)?;
    Ok(rows
        .into_iter()
        .map(|row| KeptList {
            signer_key: row.signer_key,
            number: u64::try_from(row.number).unwrap_or_default(),
            list: row.list,
            signer: row.signer,
        })
        .collect())
}

fn store_list(db: &mut SqliteConnection, kept: &KeptList) -> Result<(), ClientError> {
    use _connetto_revocation_list::dsl;
    diesel::replace_into(dsl::_connetto_revocation_list)
        .values((
            dsl::signer_key.eq(&kept.signer_key),
            dsl::number.eq(i64::try_from(kept.number).unwrap_or(i64::MAX)),
            dsl::list.eq(&kept.list),
            dsl::signer.eq(&kept.signer),
        ))
        .execute(db)?;
    Ok(())
}

fn delete(db: &mut SqliteConnection) -> Result<(), ClientError> {
    diesel::delete(_connetto_device_certificate::table).execute(db)?;
    Ok(())
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Hand `answer` to whoever waits on `request_id`. An answer nobody waits
    /// for arrived after its wait ended, and is dropped.
    pub(crate) fn answer_enrolment(&mut self, request_id: &str, answer: Answer) {
        if let Some(waiter) = self.enrol_waiters.remove(request_id) {
            let _ = waiter.send(answer);
        } else {
            tracing::debug!(request_id, "an enrolment answer arrived after its wait");
        }
    }

    /// Send `msg`, whose answer will quote `request_id`, and the receiver it arrives on.
    ///
    /// The receiver fails at once when the connection drops.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotConnected`] with no transport, [`ClientError::Transport`]
    /// when the send fails.
    pub(crate) async fn ask_enrolment(
        &mut self,
        request_id: String,
        msg: ControlMessage,
    ) -> Result<oneshot::Receiver<Answer>, ClientError> {
        self.wire()?;
        let (sender, receiver) = oneshot::channel();
        self.enrol_waiters.insert(request_id.clone(), sender);
        let sent = self.wire()?.transport.send_control(msg).await;
        if let Err(err) = sent {
            self.enrol_waiters.remove(&request_id);
            return Err(ClientError::Transport(err.to_string()));
        }
        Ok(receiver)
    }

    /// The certificate the replica holds.
    pub(crate) fn device_certificate(&mut self) -> Result<Option<Held>, ClientError> {
        load(&mut self.db)
    }

    /// Replace the certificate the replica holds.
    pub(crate) fn store_device_certificate(&mut self, held: &Held) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        store(&mut self.db, held)
    }

    /// Forget the certificate the replica holds.
    pub(crate) fn delete_device_certificate(&mut self) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        delete(&mut self.db)
    }

    /// The revocation lists the replica keeps, one per signer.
    pub(crate) fn revocation_lists(&mut self) -> Result<Vec<KeptList>, ClientError> {
        load_lists(&mut self.db)
    }

    /// Keep `kept` as its signer's list, replacing the one before.
    pub(crate) fn store_revocation_list(&mut self, kept: &KeptList) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        store_list(&mut self.db, kept)
    }

    /// The lists the server pushes from now on, for the enrolment task.
    pub(crate) fn subscribe_revocations(&mut self) -> ListInbox {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.list_sink = Some(sender);
        receiver
    }

    /// Hand pushed lists to the enrolment task, dropping them when none listens.
    pub(crate) fn push_revocations(&self, lists: Vec<SignedList>) {
        if let Some(sink) = &self.list_sink {
            let _ = sink.send(lists);
        }
    }
}

#[cfg(test)]
mod tests;
