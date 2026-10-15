//! The R76 slice 5 proofs, over chunk streams built on one channel each
//! way, with every certificate minted here.

use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{
    AttestationLevel, CertificateRequest, CertificateSerial, CertificateSigner, DeviceKey,
    DeviceKeyError, KeyHome, key_id,
};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, SigningKey as _};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{ExchangeError, Refusal};
use crate::exchange::{ChunkStream, EXCHANGE_BOUND, OfferFrame};
use crate::frame::{PeerFrame, read_frame, write_frame};
use crate::node::{client_config_for, server_config_for};
use crate::signer::{IdentityClientCert, IdentityServerCert};
use crate::tests::{Deployment, Peer, events, node, serve, whole_second};
use crate::{CloseReason, PeerEvent, SystemClock, Trust};

const DAY: Duration = Duration::from_hours(24);

/// Every attestation level, the deployment default.
fn all_levels() -> Vec<AttestationLevel> {
    AttestationLevel::ALL.into_iter().collect()
}

/// Two chunk streams over one channel each way, the two characteristics a
/// GATT transport is, so a write close ends only the peer's reads.
fn chunk_pair(chunk: usize) -> (ChunkStream, ChunkStream) {
    let (one_to_two, two_inbound) = mpsc::channel(64);
    let (two_to_one, one_inbound) = mpsc::channel(64);
    (
        ChunkStream::new(one_inbound, one_to_two, chunk),
        ChunkStream::new(two_inbound, two_to_one, chunk),
    )
}

/// A raw TLS joiner over a chunk stream, through the crate's own client
/// config, so a proof can stop answering after the handshake.
async fn raw_client(
    root_der: Vec<u8>,
    peer: &Peer,
    io: ChunkStream,
) -> tokio_rustls::client::TlsStream<ChunkStream> {
    let crls = Arc::new(parking_lot::RwLock::new(Arc::from(
        Vec::<crate::verify::Crl>::new().into_boxed_slice(),
    )));
    let config = client_config_for(
        &Trust {
            roots: vec![root_der],
            accepted: all_levels(),
        },
        Arc::new(SystemClock),
        Some(peer.key_id()),
        crls,
        &peer.identity(),
    );
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from("connetto-peer").expect("a valid dial name");
    connector
        .connect(domain, io)
        .await
        .expect("the handshake completes")
}

/// A raw TLS host over a chunk stream, through the crate's own server
/// config, so a proof can stop answering after the handshake.
async fn raw_server(
    root_der: Vec<u8>,
    peer: &Peer,
    io: ChunkStream,
) -> tokio_rustls::server::TlsStream<ChunkStream> {
    let crls = Arc::new(parking_lot::RwLock::new(Arc::from(
        Vec::<crate::verify::Crl>::new().into_boxed_slice(),
    )));
    let config = server_config_for(
        &Trust {
            roots: vec![root_der],
            accepted: all_levels(),
        },
        Arc::new(SystemClock),
        Some(peer.key_id()),
        crls,
        &peer.identity(),
    );
    TlsAcceptor::from(config)
        .accept(io)
        .await
        .expect("the handshake completes")
}

/// Wait for one delivered list, failing if ten seconds run out.
async fn await_list(rx: &mut mpsc::UnboundedReceiver<PeerEvent>) -> PeerEvent {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the list arrives")
        .expect("the channel stays open")
}

/// A trusted pair over a chunk stream of `chunk` bytes gets the offer and
/// swaps the lists either side lacks.
async fn a_trusted_pair(chunk: usize) {
    let now = whole_second();
    let deployment = Deployment::new(30, now);
    let host_issuer = deployment.add_issuer(now, [1; 16]);
    let joiner_issuer = deployment.add_issuer(now, [2; 16]);
    let host = deployment.device(
        &host_issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &joiner_issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (h_tx, mut h_rx) = events();
    let (j_tx, mut j_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&host_node, &host);
    serve(&joiner_node, &joiner);

    // Each side keeps a list the other lacks, so both lists cross.
    let (h_list, h_signer) = deployment.issuer_list(&host_issuer, 1, &[], now);
    let (j_list, j_signer) = deployment.issuer_list(&joiner_issuer, 1, &[], now);
    host_node.keep_list(h_list.clone(), h_signer.clone());
    joiner_node.keep_list(j_list.clone(), j_signer.clone());

    let (host_io, joiner_io) = chunk_pair(chunk);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, joiner_res) = tokio::join!(
        host_node.offer_over(host_io, offer),
        joiner_node.fetch_over(joiner_io)
    );
    let (peer, received) = joiner_res.expect("the exchange completes");
    assert_eq!(peer, host.identity);
    assert_eq!(received.ssid, "camp");
    assert_eq!(received.passphrase(), "opensesame");
    assert_eq!(received.security, 1);
    assert_eq!(received.port, Some(5678));
    assert_eq!(host_res.expect("the exchange completes"), joiner.identity);

    // The joiner's list reaches the host's intake, the host's the joiner's.
    assert_eq!(
        await_list(&mut h_rx).await,
        PeerEvent::ListReceived {
            list: j_list,
            signer: j_signer
        }
    );
    assert_eq!(
        await_list(&mut j_rx).await,
        PeerEvent::ListReceived {
            list: h_list,
            signer: h_signer
        }
    );

    host_node.stop(CloseReason::Closed);
    joiner_node.stop(CloseReason::Closed);
}

/// Proof.
#[tokio::test]
async fn a_trusted_pair_gets_the_offer_and_swaps_a_list() {
    // The smallest GATT MTU chunk size and a phone-sized one.
    for chunk in [20, 514] {
        a_trusted_pair(chunk).await;
    }
}

/// A refused exchange between `host` on `host_root` and `joiner` on
/// `joiner_root`, where each side trusts no chain the other presents.
async fn a_refused_exchange(
    chunk: usize,
    host: &Peer,
    host_root: Vec<u8>,
    joiner: &Peer,
    joiner_root: Vec<u8>,
) {
    let (h_tx, _h_rx) = events();
    let (j_tx, _j_rx) = events();
    let host_node = node(host_root, h_tx);
    let joiner_node = node(joiner_root, j_tx);
    serve(&host_node, host);
    serve(&joiner_node, joiner);

    let (host_io, joiner_io) = chunk_pair(chunk);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, joiner_res) = tokio::join!(
        host_node.offer_over(host_io, offer),
        joiner_node.fetch_over(joiner_io)
    );
    // The joiner's own verifier refuses the host's chain before any offer.
    assert!(matches!(
        joiner_res,
        Err(ExchangeError::Refused(Refusal::Untrusted))
    ));
    // The host refuses the joiner's chain with its own verifier or the
    // joiner's alert, and hands no offer either way.
    assert!(matches!(
        host_res,
        Err(ExchangeError::Refused(_) | ExchangeError::RefusedByPeer(_))
    ));
}

/// Proof.
#[tokio::test]
async fn a_foreign_root_is_refused_both_ways_with_no_offer() {
    let now = whole_second();
    let home = Deployment::new(31, now);
    let foreign = Deployment::new(32, now);
    let home_issuer = home.add_issuer(now, [1; 16]);
    let foreign_issuer = foreign.add_issuer(now, [1; 16]);
    let home_host = home.device(
        &home_issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let home_joiner = home.device(
        &home_issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let foreign_host = foreign.device(
        &foreign_issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let foreign_joiner = foreign.device(
        &foreign_issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    // The foreign joiner reaches the home host, and the home joiner the
    // foreign host.
    a_refused_exchange(
        20,
        &home_host,
        home.root_der(),
        &foreign_joiner,
        foreign.root_der(),
    )
    .await;
    a_refused_exchange(
        514,
        &foreign_host,
        foreign.root_der(),
        &home_joiner,
        home.root_der(),
    )
    .await;
}

/// Proof.
#[tokio::test]
async fn an_expired_joiner_gets_no_offer() {
    let now = whole_second();
    let deployment = Deployment::new(33, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    // The joiner's window closed a day ago, and the host's verifier refuses
    // it while the joiner's accepts the host's still-valid chain.
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now - 2 * DAY,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (h_tx, _h_rx) = events();
    let (j_tx, _j_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&host_node, &host);
    serve(&joiner_node, &joiner);

    let (host_io, joiner_io) = chunk_pair(20);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, joiner_res) = tokio::join!(
        host_node.offer_over(host_io, offer),
        joiner_node.fetch_over(joiner_io)
    );
    // The joiner's handshake completes and its first frame read meets the
    // host's alert, with no offer anywhere.
    assert!(matches!(joiner_res, Err(ExchangeError::RefusedByPeer(_))));
    assert!(matches!(
        host_res,
        Err(ExchangeError::Refused(Refusal::Expired))
    ));
}

/// Proof.
#[tokio::test]
async fn a_version_mismatch_is_refused() {
    let now = whole_second();
    let deployment = Deployment::new(34, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    // A joiner speaking version 2 gets no offer, and the host refuses it.
    let (h_tx, _h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    serve(&host_node, &host);
    let (host_io, joiner_io) = chunk_pair(20);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, ()) = tokio::join!(host_node.offer_over(host_io, offer), async {
        let mut raw = raw_client(deployment.root_der(), &joiner, joiner_io).await;
        let hello = PeerFrame::Hello {
            version: 2,
            dial: 1,
            numbers: Vec::new(),
        };
        write_frame(&mut raw, &hello)
            .await
            .expect("the hello writes");
        let _ = read_frame(&mut raw).await;
    });
    assert!(matches!(
        host_res,
        Err(ExchangeError::UnsupportedVersion { their: 2 })
    ));

    // A host speaking version 2 refuses the joiner the same way.
    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);
    let (host_io, joiner_io) = chunk_pair(514);
    let raw_host = tokio::spawn(async move {
        let mut raw = raw_server(deployment.root_der(), &host, host_io).await;
        let hello = PeerFrame::Hello {
            version: 2,
            dial: 1,
            numbers: Vec::new(),
        };
        write_frame(&mut raw, &hello)
            .await
            .expect("the hello writes");
        let _ = read_frame(&mut raw).await;
    });
    let result = joiner_node.fetch_over(joiner_io).await;
    assert!(matches!(
        result,
        Err(ExchangeError::UnsupportedVersion { their: 2 })
    ));
    raw_host.await.expect("the raw host ends");
}

/// Proof.
#[tokio::test]
async fn a_silent_host_times_out_at_the_bound() {
    let now = whole_second();
    let deployment = Deployment::new(35, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);
    let (host_io, joiner_io) = chunk_pair(20);

    // A host that completes the handshake and the hello and then stops
    // answering, holding the connection open.
    let silent = tokio::spawn(async move {
        let mut tls = raw_server(deployment.root_der(), &host, host_io).await;
        let hello = PeerFrame::Hello {
            version: 1,
            dial: 0,
            numbers: Vec::new(),
        };
        write_frame(&mut tls, &hello)
            .await
            .expect("the hello writes");
        let _ = read_frame(&mut tls).await;
        // The joiner's lists end with its write close, then the silence.
        while let Ok(Some(_)) = read_frame(&mut tls).await {}
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let result = joiner_node.fetch_over(joiner_io).await;
    let elapsed = started.elapsed();
    tokio::time::resume();
    silent.abort();
    assert!(matches!(result, Err(ExchangeError::Timeout)));
    assert!(elapsed >= EXCHANGE_BOUND);
}

/// Proof.
#[tokio::test]
async fn a_non_serving_node_refuses() {
    let now = whole_second();
    let deployment = Deployment::new(36, now);

    let (h_tx, _h_rx) = events();
    let (j_tx, _j_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let joiner_node = node(deployment.root_der(), j_tx);
    // Neither node serves an identity.
    let (host_io, joiner_io) = chunk_pair(20);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    assert!(matches!(
        host_node.offer_over(host_io, offer).await,
        Err(ExchangeError::NotServing)
    ));
    assert!(matches!(
        joiner_node.fetch_over(joiner_io).await,
        Err(ExchangeError::NotServing)
    ));
}

/// The exchange's chunk codec, over plain channels with no duplex behind.
#[tokio::test]
async fn a_chunk_stream_splits_writes_and_rejoins_reads() {
    let (outbound, mut outbound_rx) = mpsc::channel(4);
    let (inbound_tx, inbound_rx) = mpsc::channel(4);
    let mut stream = ChunkStream::new(inbound_rx, outbound, 20);

    // A 100-byte write crosses as five 20-byte chunks.
    let data: Vec<u8> = (0..100u8).collect();
    stream.write_all(&data).await.expect("the write lands");
    for expected in data.chunks(20) {
        let chunk = outbound_rx.recv().await.expect("the chunk arrives");
        assert_eq!(chunk, expected);
    }

    // A 10-byte and a 20-byte inbound chunk rejoin into one 30-byte read.
    inbound_tx
        .send(vec![100, 101, 102, 103, 104, 105, 106, 107, 108, 109])
        .await
        .expect("the chunk lands");
    inbound_tx
        .send((0..20u8).collect())
        .await
        .expect("the chunk lands");
    let mut buf = [0u8; 30];
    stream.read_exact(&mut buf).await.expect("the read lands");
    assert_eq!(
        &buf[..10],
        &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109]
    );
    assert_eq!(&buf[10..], &(0..20u8).collect::<Vec<_>>());

    // A closed inbound side ends the reads.
    drop(inbound_tx);
    let mut eof = [0u8; 8];
    let count = stream.read(&mut eof).await.expect("eof reads");
    assert_eq!(count, 0);
}

/// A write into a chunk stream whose reader is gone fails with a broken
/// pipe once the bridge reaches the closed channel, so a stale GATT
/// connection cannot wedge the exchange.
#[tokio::test]
async fn an_empty_chunk_is_skipped_and_never_read_as_the_end() {
    let (outbound, _outbound_rx) = mpsc::channel(4);
    let (inbound_tx, inbound_rx) = mpsc::channel(4);
    let mut stream = ChunkStream::new(inbound_rx, outbound, 20);
    inbound_tx.send(Vec::new()).await.expect("the chunk lands");
    inbound_tx.send(vec![7, 8]).await.expect("the chunk lands");
    let mut buf = [0u8; 8];
    let read = stream.read(&mut buf).await.expect("the read lands");
    assert_eq!(&buf[..read], &[7, 8]);
}

#[tokio::test]
async fn a_chunk_stream_errors_writes_after_the_reader_is_gone() {
    let (outbound, outbound_rx) = mpsc::channel(4);
    let (_inbound_tx, inbound_rx) = mpsc::channel(4);
    let mut stream = ChunkStream::new(inbound_rx, outbound, 16);
    // The peer's chunk channel closes.
    drop(outbound_rx);
    // A full chunk commits and the bridge sends it into the closed channel,
    // which ends the bridge. A further write into the dead bridge fails.
    stream
        .write_all(&[0u8; 16])
        .await
        .expect("a full chunk commits");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut failed = false;
    while tokio::time::Instant::now() < deadline {
        if stream.write_all(&[7u8; 16]).await.is_err() {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(failed, "a write into a closed channel fails");
}

/// A device key held in memory, standing in for a chip.
struct RcgenKey(Arc<KeyPair>);

impl DeviceKey for RcgenKey {
    fn public_point(&self) -> [u8; 65] {
        self.0
            .public_key_raw()
            .try_into()
            .expect("an uncompressed P-256 point")
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        self.0
            .sign(message)
            .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::Software
    }
}

/// A device key and the leaf the root signs for it, with no issuer between,
/// the chain a truncated peer presents (R76 slice 5a).
fn lone_leaf(deployment: &Deployment, now: SystemTime, serial: [u8; 16]) -> (RcgenKey, Vec<u8>) {
    let key = RcgenKey(Arc::new(
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("the key generates"),
    ));
    let csr =
        CertificateRequest::build(&CertificateSigner::new(&key), &[3; 32]).expect("the csr builds");
    let request = CertificateRequest::parse(&csr).expect("the request parses");
    let leaf = deployment
        .root_signer()
        .issue(
            &request,
            "lone",
            now,
            DAY,
            CertificateSerial::new(serial).expect("the serial is positive"),
            AttestationLevel::Unproven,
        )
        .expect("the leaf issues");
    (key, leaf)
}

/// A joiner that presents no issuer certificate is refused before the
/// offer, so a truncated chain cannot stand behind the exchange (R76 slice 5a).
#[tokio::test]
async fn a_joiner_that_presents_no_issuer_is_refused_without_the_offer() {
    let now = whole_second();
    let deployment = Deployment::new(37, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let (lone_key, lone_leaf) = lone_leaf(&deployment, now, [4; 16]);

    let (h_tx, _h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    serve(&host_node, &host);

    let (host_io, joiner_io) = chunk_pair(20);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, _client) = tokio::join!(host_node.offer_over(host_io, offer), async {
        // The config presents the lone leaf alone, the way a truncated
        // peer's resolver would, with the crate's own verifier.
        let crls = Arc::new(parking_lot::RwLock::new(Arc::from(
            Vec::<crate::verify::Crl>::new().into_boxed_slice(),
        )));
        let verifier = crate::verify::PeerVerifier::new(
            &Trust {
                roots: vec![deployment.root_der()],
                accepted: all_levels(),
            },
            Arc::new(SystemClock),
            Arc::new(parking_lot::RwLock::new(Some(key_id(&lone_key)))),
            crls,
        );
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring speaks TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(IdentityClientCert::new(
            vec![CertificateDer::from(lone_leaf.clone())],
            Arc::new(lone_key),
        )));
        let connector = TlsConnector::from(Arc::new(config));
        let domain = ServerName::try_from("connetto-peer").expect("a valid dial name");
        connector
            .connect(domain, joiner_io)
            .await
            .expect("the handshake completes")
    });
    assert!(matches!(
        &host_res,
        Err(ExchangeError::Protocol(message)) if *message == "the peer presented no issuer certificate"
    ));
    host_node.stop(CloseReason::Closed);
}

/// A host that presents no issuer certificate gets no fetch, so a truncated
/// chain cannot stand behind the exchange (R76 slice 5a).
#[tokio::test]
async fn a_host_that_presents_no_issuer_gets_no_fetch() {
    let now = whole_second();
    let deployment = Deployment::new(38, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let (lone_key, lone_leaf) = lone_leaf(&deployment, now, [5; 16]);

    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);

    let (host_io, joiner_io) = chunk_pair(20);
    let ((), joiner_res) = tokio::join!(
        async {
            // The config presents the lone leaf alone, the way a truncated
            // peer's resolver would, with the crate's own verifier.
            let crls = Arc::new(parking_lot::RwLock::new(Arc::from(
                Vec::<crate::verify::Crl>::new().into_boxed_slice(),
            )));
            let verifier = crate::verify::PeerVerifier::new(
                &Trust {
                    roots: vec![deployment.root_der()],
                    accepted: all_levels(),
                },
                Arc::new(SystemClock),
                Arc::new(parking_lot::RwLock::new(Some(key_id(&lone_key)))),
                crls,
            );
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring speaks TLS 1.3")
            .with_client_cert_verifier(Arc::new(verifier))
            .with_cert_resolver(Arc::new(IdentityServerCert::new(
                vec![CertificateDer::from(lone_leaf.clone())],
                Arc::new(lone_key),
            )));
            let _ = TlsAcceptor::from(Arc::new(config))
                .accept(host_io)
                .await
                .expect("the handshake completes");
        },
        joiner_node.fetch_over(joiner_io)
    );
    assert!(matches!(
        &joiner_res,
        Err(ExchangeError::Protocol(message)) if *message == "the peer presented no issuer certificate"
    ));
    joiner_node.stop(CloseReason::Closed);
}

/// A joiner that breaks the frame protocol where its lists come gets no
/// offer, with the break named (R76 slice 5a).
#[tokio::test]
async fn a_joiner_that_breaks_the_frame_protocol_where_its_lists_come() {
    let now = whole_second();
    let deployment = Deployment::new(39, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    // An over-long frame names the ceiling.
    let (h_tx, _h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    serve(&host_node, &host);
    let (host_io, joiner_io) = chunk_pair(20);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, ()) = tokio::join!(host_node.offer_over(host_io, offer), async {
        let mut raw = raw_client(deployment.root_der(), &joiner, joiner_io).await;
        let hello = PeerFrame::Hello {
            version: 1,
            dial: 1,
            numbers: Vec::new(),
        };
        write_frame(&mut raw, &hello)
            .await
            .expect("the hello writes");
        let _ = read_frame(&mut raw).await;
        raw.write_all(&[0xff, 0xff, 0xff, 0xff])
            .await
            .expect("the bytes write");
    });
    assert!(matches!(
        &host_res,
        Err(ExchangeError::Protocol(message)) if *message == "the frame exceeds the ceiling"
    ));
    host_node.stop(CloseReason::Closed);

    // A frame that is not a list names itself.
    let (h_tx, _h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    serve(&host_node, &host);
    let (host_io, joiner_io) = chunk_pair(514);
    let offer = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let (host_res, ()) = tokio::join!(host_node.offer_over(host_io, offer), async {
        let mut raw = raw_client(deployment.root_der(), &joiner, joiner_io).await;
        let hello = PeerFrame::Hello {
            version: 1,
            dial: 1,
            numbers: Vec::new(),
        };
        write_frame(&mut raw, &hello)
            .await
            .expect("the hello writes");
        let _ = read_frame(&mut raw).await;
        write_frame(&mut raw, &PeerFrame::Ping)
            .await
            .expect("the probe writes");
    });
    assert!(matches!(
        &host_res,
        Err(ExchangeError::Protocol(message)) if *message == "the joiner sent a Ping frame where its lists end"
    ));
    host_node.stop(CloseReason::Closed);
}

/// A host that breaks the frame protocol where the offer comes gets a named
/// refusal from the joiner (R76 slice 5a).
#[tokio::test]
async fn a_host_that_breaks_the_frame_protocol_where_the_offer_comes() {
    let now = whole_second();
    let deployment = Deployment::new(40, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);

    let (host_io, joiner_io) = chunk_pair(20);
    let (_host, joiner_res) = tokio::join!(
        async {
            let mut raw = raw_server(deployment.root_der(), &host, host_io).await;
            let _hello = read_frame(&mut raw).await.expect("the hello reads");
            raw.write_all(&[0xff, 0xff, 0xff, 0xff])
                .await
                .expect("the bytes write");
        },
        joiner_node.fetch_over(joiner_io)
    );
    assert!(matches!(
        &joiner_res,
        Err(ExchangeError::Protocol(message)) if *message == "the frame exceeds the ceiling"
    ));
    joiner_node.stop(CloseReason::Closed);
}

/// A host that sends a ping where the offer comes gets a named refusal from
/// the joiner (R76 slice 5a).
#[tokio::test]
async fn a_host_that_sends_a_ping_where_the_offer_comes() {
    let now = whole_second();
    let deployment = Deployment::new(41, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);

    let (host_io, joiner_io) = chunk_pair(514);
    let (_host, joiner_res) = tokio::join!(
        async {
            let mut raw = raw_server(deployment.root_der(), &host, host_io).await;
            let hello = PeerFrame::Hello {
                version: 1,
                dial: 0,
                numbers: Vec::new(),
            };
            write_frame(&mut raw, &hello)
                .await
                .expect("the hello writes");
            let _ = read_frame(&mut raw).await.expect("the hello reads");
            while read_frame(&mut raw).await.expect("the swap ends").is_some() {}
            write_frame(&mut raw, &PeerFrame::Ping)
                .await
                .expect("the probe writes");
        },
        joiner_node.fetch_over(joiner_io)
    );
    assert!(matches!(
        &joiner_res,
        Err(ExchangeError::Protocol(message)) if message.starts_with("the host sent a Ping")
    ));
    joiner_node.stop(CloseReason::Closed);
}

/// A host that closes before its offer gets a named refusal from the
/// joiner (R76 slice 5a).
#[tokio::test]
async fn a_host_that_closes_before_its_offer_refuses_the_fetch() {
    let now = whole_second();
    let deployment = Deployment::new(42, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let joiner = deployment.device(
        &issuer,
        "joiner",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (j_tx, _j_rx) = events();
    let joiner_node = node(deployment.root_der(), j_tx);
    serve(&joiner_node, &joiner);

    let (host_io, joiner_io) = chunk_pair(20);
    let (_host, joiner_res) = tokio::join!(
        async {
            let mut raw = raw_server(deployment.root_der(), &host, host_io).await;
            let hello = PeerFrame::Hello {
                version: 1,
                dial: 0,
                numbers: Vec::new(),
            };
            write_frame(&mut raw, &hello)
                .await
                .expect("the hello writes");
            let _ = read_frame(&mut raw).await.expect("the hello reads");
            // The host ends the swap, without its offer, and drops.
            while read_frame(&mut raw).await.expect("the swap ends").is_some() {}
        },
        joiner_node.fetch_over(joiner_io)
    );
    assert!(matches!(
        &joiner_res,
        Err(ExchangeError::Protocol(message)) if *message == "the host closed before its offer"
    ));
    joiner_node.stop(CloseReason::Closed);
}

/// An empty write into a chunk stream yields zero bytes, so a flush that
/// carries nothing ends cleanly (R76 slice 5a).
#[tokio::test]
async fn an_empty_write_into_a_chunk_stream_yields_zero() {
    let (outbound, _outbound_rx) = mpsc::channel(4);
    let (_inbound_tx, inbound_rx) = mpsc::channel(4);
    let mut stream = ChunkStream::new(inbound_rx, outbound, 16);
    let written = stream.write(&[]).await.expect("an empty write");
    assert_eq!(written, 0, "nothing crosses for an empty write");
}

/// A shutdown chunk stream refuses the next write and the next flush, so a
/// torn exchange cannot queue bytes into a closed pipe (R76 slice 5a).
#[tokio::test]
async fn a_shutdown_chunk_stream_refuses_writes_and_flushes() {
    let (outbound, _outbound_rx) = mpsc::channel(4);
    let (_inbound_tx, inbound_rx) = mpsc::channel(4);
    let mut stream = ChunkStream::new(inbound_rx, outbound, 16);
    stream
        .shutdown()
        .await
        .expect("the shutdown ends the writes");
    let error = stream
        .write(b"late")
        .await
        .expect_err("the writes are done");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "the chunk reader is gone");
    let error = stream.flush().await.expect_err("the flush is done too");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(error.to_string(), "the chunk reader is gone");
}

/// The offer frame's debug form redacts its passphrase, so a log that names
/// a frame never carries the network key (R76 slice 5a).
#[test]
fn an_offer_frame_redacts_its_passphrase_in_its_debug_form() {
    let frame = OfferFrame::new("camp", "opensesame", 1, Some(5678));
    let debug = format!("{frame:?}");
    assert!(
        !debug.contains("opensesame"),
        "the passphrase stays out of the log"
    );
    assert!(
        debug.contains("<redacted>"),
        "the redaction stands in its place"
    );
    assert!(debug.contains("camp"), "the network name stays");
    assert!(debug.contains("5678"), "the port stays");
}
