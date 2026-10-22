//! R91: the bot's registration exchange over a scripted server, and the
//! person's client's skip of the leading challenge.
//!
//! The scripted servers here speak the wire by hand, so the assertions hold on
//! the frames themselves. The server side of the exchange is proven against
//! the real manager in `connetto-server`'s `bot_registration` suite.

use connetto_client::bot::{Registration, register};
use connetto_client::{ClientBuilder, ClientError, ClientEvent, SyncSchema, TransportFactory};
use connetto_core::messages::{
    BotListEntry, BotRegistered, BulkMessage, Challenge, ControlMessage, FatalErrorReason,
    HandshakeAck, SnapshotBegin, SnapshotEnd, SnapshotPatch, SubscriptionPriority,
    bot_registration_message,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, SchemaBundle, loopback};
use diesel::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use uuid::Uuid;

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, label TEXT);";

diesel::table! {
    /// The one synced table these builds read back.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Payload the snapshot carries.
        label -> Text,
    }
}

/// The translated bundle these builds present, one table and no policies.
fn bundle() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "schema",
        "policies",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// The refusal a one-shot dialer hands back after it has handed out its
/// transport.
#[derive(Debug, thiserror::Error)]
#[error("the one-shot dialer has no second transport")]
struct DialRefused;

/// A dialer that hands out exactly one transport, the one the test attached.
struct OneShot {
    transport: Option<LoopbackTransport>,
}

impl TransportFactory for OneShot {
    type Transport = LoopbackTransport;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<LoopbackTransport, DialRefused>> + Send {
        std::future::ready(self.transport.take().ok_or(DialRefused))
    }
}

/// Compressed one-row patchset bytes for the wire table shape.
fn payload(id: i64) -> Vec<u8> {
    let insert =
        Insert::<_, String, Vec<u8>>::from(SimpleTable::new("orders", &["id", "label"], &[0]))
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Text("seed".to_owned()))
            .expect("set label");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new().insert(insert);
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress payload")
}

/// A scripted server that opens the connection with the real manager's
/// leading challenge and then answers the handshake the way a settled session
/// does, with a one-row snapshot per subscription.
fn challenged_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    let nonce = [0x5a; 32];
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("open the connection with the challenge");
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "challenged".to_owned(),
                session_token: "challenged".to_owned(),
                resume_token: "challenged".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                writer: Some(connetto_core::messages::WriterGrant {
                    number: 1,
                    frontier: 0,
                }),
            }))
            .await
            .expect("ack the handshake");
        while let Ok(Some(frame)) = server.recv().await {
            if let IncomingFrame::Control(ControlMessage::Subscribe(sub)) = frame {
                server
                    .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                        sub_id: sub.sub_id.clone(),
                        priority: SubscriptionPriority::default(),
                    }))
                    .await
                    .expect("snapshot begin");
                server
                    .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                        sub_id: sub.sub_id.clone(),
                        patchset_zstd: payload(1),
                    }))
                    .await
                    .expect("snapshot patch");
                server
                    .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                        sub_id: sub.sub_id.clone(),
                        cursor: Cursor::new(vec![1]),
                    }))
                    .await
                    .expect("snapshot end");
            }
        }
    });
    client_end
}

/// The person's client reads the leading challenge, keeps nothing of it on the
/// wire, and completes the handshake and a snapshot as if the challenge were
/// not there. A scripted server that writes nothing first stays served, which
/// is the existing behavior the skip must not break.
#[tokio::test]
async fn a_persons_client_ignores_the_leading_challenge() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(challenged_server()),
        },
    );
    let mut conn = builder.connect_driven().await.expect("connect driven");
    conn.subscribe("sub", "SELECT * FROM orders")
        .await
        .expect("subscribe");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::SnapshotEnd { .. } => break,
            ClientEvent::Closed => panic!("closed before the snapshot ended"),
            _ => {}
        }
    }
    let rows: Vec<(i64, String)> = orders::table
        .select((orders::id, orders::label))
        .load(conn.conn())
        .expect("read the replica");
    assert_eq!(
        rows,
        vec![(1, "seed".to_owned())],
        "the snapshot's row landed behind the skipped challenge"
    );
}

/// A fresh Ed25519 key pair, through the PKCS#8 round trip an app would use.
fn mint_key_pair() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
    Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parse the key pair")
}

/// The one registration every bot test presents.
fn registration(key_pair: Ed25519KeyPair) -> Registration {
    Registration {
        code: "K7QX-2M9P-WF4D-8H3T-6CRN-A5".to_owned(),
        name: "bot-a".to_owned(),
        key_pair,
        list: vec![BotListEntry {
            table: "orders".to_owned(),
            verb: "read".to_owned(),
            optional: false,
        }],
    }
}

/// `register` waits for the challenge, signs the connection's nonce under the
/// registration's domain separator, and ends with the bot id the server names.
#[tokio::test]
async fn register_signs_the_domain_separated_nonce_and_lands_the_bot_id() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x42; 32];
    let key_pair = mint_key_pair();
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(key_pair.public_key().as_ref());
    let bare_signature = key_pair.sign(nonce.as_ref()).as_ref().to_vec();
    let bot_id = Uuid::new_v4();
    let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let received = server.recv().await.expect("recv the registration");
        let sent = match received {
            Some(IncomingFrame::Control(ControlMessage::RegisterBot(reg))) => reg,
            other => panic!("the registration arrived as {other:?}"),
        };
        server
            .send_control(ControlMessage::BotRegistered(BotRegistered {
                bot_id: bot_id.to_string(),
            }))
            .await
            .expect("send the settled registration");
        sent_tx.send(sent).expect("hand the frame back");
    });
    let id = register(&mut client_end, &registration(key_pair))
        .await
        .expect("the registration settles");
    assert_eq!(id, bot_id, "the bot id is what the server minted");
    let sent = sent_rx.await.expect("the frame came back");
    assert_eq!(sent.code, "K7QX-2M9P-WF4D-8H3T-6CRN-A5");
    assert_eq!(sent.name, "bot-a");
    assert_eq!(
        sent.public_key, public_key,
        "the key the bot goes by is the one it registered"
    );
    assert_eq!(sent.list.len(), 1);
    assert_eq!(sent.list[0].table, "orders");
    assert_eq!(sent.list[0].verb, "read");
    assert!(!sent.list[0].optional);
    let message = bot_registration_message(&nonce);
    let public = UnparsedPublicKey::new(&ED25519, &sent.public_key);
    public
        .verify(&message, &sent.signature)
        .expect("the signature covers the separator and the nonce");
    assert_ne!(
        sent.signature, bare_signature,
        "a signature over the bare nonce is not this exchange's signature"
    );
}

/// A refused registration ends `register` with the refusal, and the code is
/// the one the server's refusal maps to.
#[tokio::test]
async fn register_ending_in_a_refusal_reports_the_refusal() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x43; 32];
    let key_pair = mint_key_pair();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let Some(IncomingFrame::Control(ControlMessage::RegisterBot(_))) =
            server.recv().await.expect("recv the registration")
        else {
            panic!("the registration did not arrive");
        };
        server
            .send_control(ControlMessage::RegistrationRefused)
            .await
            .expect("refuse the registration");
    });
    let refused = register(&mut client_end, &registration(key_pair))
        .await
        .expect_err("the refusal ends the registration");
    match refused {
        ClientError::RegistrationRefused => {}
        other => panic!("the refusal arrived as {other:?}"),
    }
}

/// A fatal on the registration's answer ends `register` with its reason.
#[tokio::test]
async fn register_ending_in_a_fatal_reports_the_reason() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x44; 32];
    let key_pair = mint_key_pair();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let Some(IncomingFrame::Control(ControlMessage::RegisterBot(_))) =
            server.recv().await.expect("recv the registration")
        else {
            panic!("the registration did not arrive");
        };
        server
            .send_control(ControlMessage::FatalError(
                connetto_core::messages::FatalError::new(FatalErrorReason::ServerShuttingDown),
            ))
            .await
            .expect("send the fatal");
    });
    let refused = register(&mut client_end, &registration(key_pair))
        .await
        .expect_err("the fatal ends the registration");
    match refused {
        ClientError::Refused {
            reason: FatalErrorReason::ServerShuttingDown,
        } => {}
        other => panic!("the fatal arrived as {other:?}"),
    }
}

/// A connection that never opens with the challenge is a broken exchange, not
/// a registration that can be retried silently.
#[tokio::test]
async fn register_without_a_challenge_is_a_protocol_error() {
    // The peer closes the connection before ever opening it with a challenge,
    // which is the shape a non-registration peer takes, with no challenge to sign.
    let (server, mut client_end) = loopback();
    drop(server);
    let broken = register(&mut client_end, &registration(mint_key_pair()))
        .await
        .expect_err("no challenge is not a registerable exchange");
    assert!(
        matches!(broken, ClientError::Protocol(_)),
        "the broken exchange reports a protocol violation, got {broken:?}"
    );
}

/// The reset the wire reports when the socket dies mid handshake.
#[derive(Debug, thiserror::Error)]
#[error("the socket reset during the handshake")]
struct SocketReset;

/// A transport that carries the client's handshake and resets at a scripted
/// read, the way a socket that drops mid exchange does. Sends always
/// succeed; `recv` hands out the scripted challenge until it reaches the
/// reset.
struct ResetSocket {
    reads: usize,
    reset_after: usize,
    nonce: [u8; 32],
}

impl ResetSocket {
    /// The socket dies on the client's first read, before any frame.
    fn down_on_first_read() -> Self {
        Self {
            reads: 0,
            reset_after: 0,
            nonce: [0; 32],
        }
    }

    /// The socket hands out the challenge and dies on the read the answer
    /// would be.
    fn down_after_challenge(nonce: [u8; 32]) -> Self {
        Self {
            reads: 0,
            reset_after: 1,
            nonce,
        }
    }
}

impl Transport for ResetSocket {
    type Error = SocketReset;

    fn send_control(
        &mut self,
        _message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        self.reads += 1;
        if self.reads > self.reset_after {
            std::future::ready(Err(SocketReset))
        } else {
            std::future::ready(Ok(Some(IncomingFrame::Control(ControlMessage::Challenge(
                Challenge { nonce: self.nonce },
            )))))
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(Ok(()))
    }
}

/// A dialer that hands out exactly one transport, the one the test attached.
struct OneShotSocket {
    transport: Option<ResetSocket>,
}

impl TransportFactory for OneShotSocket {
    type Transport = ResetSocket;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<ResetSocket, DialRefused>> + Send {
        std::future::ready(self.transport.take().ok_or(DialRefused))
    }
}

/// A first frame that is a control frame other than the challenge is a broken
/// exchange, because the signature `register` mints binds the challenge's
/// nonce, and there is none.
#[tokio::test]
async fn register_with_a_wrong_control_first_frame_is_a_protocol_error() {
    let (mut server, mut client_end) = loopback();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "wrong".to_owned(),
                session_token: "wrong".to_owned(),
                resume_token: "wrong".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                writer: Some(connetto_core::messages::WriterGrant {
                    number: 1,
                    frontier: 0,
                }),
            }))
            .await
            .expect("send the wrong first frame");
    });
    let broken = register(&mut client_end, &registration(mint_key_pair()))
        .await
        .expect_err("a first frame other than the challenge breaks the exchange");
    let ClientError::Protocol(why) = broken else {
        panic!("the broken exchange is a protocol violation, got {broken:?}");
    };
    assert!(
        why.starts_with("expected the connection's challenge"),
        "the violation names the wrong first frame, got {why}"
    );
}

/// A bulk first frame is the same broken exchange, with the bulk plane
/// speaking before the challenge.
#[tokio::test]
async fn register_with_a_bulk_first_frame_is_a_protocol_error() {
    let (mut server, mut client_end) = loopback();
    tokio::spawn(async move {
        server
            .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                sub_id: "sub".to_owned(),
                patchset_zstd: vec![],
            }))
            .await
            .expect("send the wrong first frame");
    });
    let broken = register(&mut client_end, &registration(mint_key_pair()))
        .await
        .expect_err("a first frame other than the challenge breaks the exchange");
    let ClientError::Protocol(why) = broken else {
        panic!("the broken exchange is a protocol violation, got {broken:?}");
    };
    assert!(
        why.starts_with("expected the connection's challenge"),
        "the violation names the wrong first frame, got {why}"
    );
}

/// A settled answer whose bot id is not a UUID is a broken exchange, not a
/// bot the caller can be handed.
#[tokio::test]
async fn register_with_a_non_uuid_answer_is_a_protocol_error() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x46; 32];
    let key_pair = mint_key_pair();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let Some(IncomingFrame::Control(ControlMessage::RegisterBot(_))) =
            server.recv().await.expect("recv the registration")
        else {
            panic!("the registration did not arrive");
        };
        server
            .send_control(ControlMessage::BotRegistered(BotRegistered {
                bot_id: "not-a-uuid".to_owned(),
            }))
            .await
            .expect("send the broken answer");
    });
    let broken = register(&mut client_end, &registration(key_pair))
        .await
        .expect_err("an answer without a uuid breaks the exchange");
    let ClientError::Protocol(why) = broken else {
        panic!("the broken answer is a protocol violation, got {broken:?}");
    };
    assert!(
        why.starts_with("the registered bot id is not a uuid"),
        "the violation names the broken id, got {why}"
    );
}

/// An answer that is not the registration's is a broken exchange, because the
/// bot cannot be told whether its registration landed.
#[tokio::test]
async fn register_with_a_wrong_answer_is_a_protocol_error() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x47; 32];
    let key_pair = mint_key_pair();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let Some(IncomingFrame::Control(ControlMessage::RegisterBot(_))) =
            server.recv().await.expect("recv the registration")
        else {
            panic!("the registration did not arrive");
        };
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the wrong answer");
    });
    let broken = register(&mut client_end, &registration(key_pair))
        .await
        .expect_err("a second challenge is not the registration's answer");
    let ClientError::Protocol(why) = broken else {
        panic!("the wrong answer is a protocol violation, got {broken:?}");
    };
    assert_eq!(why, "expected the registration's answer");
}

/// A connection that closes before the registration's answer is a broken
/// exchange too: the bot cannot be told whether its registration landed.
#[tokio::test]
async fn register_with_the_connection_closed_first_is_a_protocol_error() {
    let (mut server, mut client_end) = loopback();
    let nonce = [0x48; 32];
    let key_pair = mint_key_pair();
    tokio::spawn(async move {
        server
            .send_control(ControlMessage::Challenge(Challenge { nonce }))
            .await
            .expect("send the challenge");
        let Some(IncomingFrame::Control(ControlMessage::RegisterBot(_))) =
            server.recv().await.expect("recv the registration")
        else {
            panic!("the registration did not arrive");
        };
        drop(server);
    });
    let broken = register(&mut client_end, &registration(key_pair))
        .await
        .expect_err("a closed connection is not the registration's answer");
    let ClientError::Protocol(why) = broken else {
        panic!("the closed connection is a protocol violation, got {broken:?}");
    };
    assert_eq!(
        why,
        "the connection closed before the registration's answer"
    );
}

/// A socket that dies while the client reads the challenge is a transport
/// error, not a protocol one, so the caller can tell the wire broke from a
/// server that broke the exchange.
#[tokio::test]
async fn a_socket_down_on_the_first_read_is_a_transport_error() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShotSocket {
            transport: Some(ResetSocket::down_on_first_read()),
        },
    );
    let Err(dead) = builder.connect_driven().await else {
        panic!("the socket dies mid handshake, so the connect fails")
    };
    let ClientError::Transport(why) = dead else {
        panic!("a dead socket is a transport error, got {dead:?}");
    };
    assert!(
        why.contains("socket reset"),
        "the reset is named, got {why}"
    );
}

/// The same reset one read later: the challenge arrived, and the socket died
/// on the read the challenge's answer would be.
#[tokio::test]
async fn a_socket_down_after_the_challenge_is_a_transport_error() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShotSocket {
            transport: Some(ResetSocket::down_after_challenge([0x49; 32])),
        },
    );
    let Err(dead) = builder.connect_driven().await else {
        panic!("the socket dies mid handshake, so the connect fails")
    };
    let ClientError::Transport(why) = dead else {
        panic!("a dead socket is a transport error, got {dead:?}");
    };
    assert!(
        why.contains("socket reset"),
        "the reset is named, got {why}"
    );
}
