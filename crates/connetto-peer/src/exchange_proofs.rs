//! The R76 slice 5 proofs, over chunk streams built on one channel each
//! way, with every certificate minted here.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::device_cert::AttestationLevel;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{ExchangeError, Refusal};
use crate::exchange::{ChunkStream, EXCHANGE_BOUND, OfferFrame};
use crate::frame::{PeerFrame, read_frame, write_frame};
use crate::node::{client_config_for, server_config_for};
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
