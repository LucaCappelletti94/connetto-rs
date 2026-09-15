//! The native transport's idle bound and its redirect refusal, against local
//! listeners that control the timing of every byte.
//!
//! A bound of a few hundred milliseconds stands in for the shipped thirty
//! seconds, and the bodies are large enough that a pull cannot outrun the
//! socket buffers, which is what makes a stalled send observable at all.

use core::time::Duration;
use std::net::SocketAddr;
use std::time::Instant;

use connetto_file_client::{ContentHttp, HttpFailure, HttpReply, ReqwestHttp, ReqwestHttpError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The bound every test here injects, in place of the shipped thirty seconds.
const BOUND: Duration = Duration::from_millis(500);

/// How long a stage that must abort is given, which no transport keeping a
/// bound of its own could answer inside.
const CEILING: Duration = Duration::from_secs(4);

/// A body past any socket buffer, so a server that stops reading stalls the
/// pulls the watchdog observes.
const UNBUFFERABLE: usize = 32 * 1024 * 1024;

/// How much a trickling server takes per read, which sets the rate a moving
/// upload runs at.
const TRICKLE_READ: usize = 1024 * 1024;

/// How long a trickling server waits between reads, well inside the bound.
const TRICKLE_PAUSE: Duration = Duration::from_millis(25);

/// A trickled body, sized so the transfer outlasts several bounds at the
/// trickle rate, which is what a total deadline would have aborted.
const TRICKLED: usize = 64 * 1024 * 1024;

/// A reply that closes the connection, so no test waits on a reused one.
const NO_CONTENT: &str =
    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// A transport under the test bound.
fn transport() -> ReqwestHttp {
    ReqwestHttp::new().with_idle_bound(BOUND)
}

/// A local listener and the address to send it requests at.
async fn local_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("a bound address");
    (listener, address)
}

/// Reads one request head, which is all a test needs to know what arrived.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Drains a chunked body, taking `step` bytes at a time and pausing `pause`
/// between reads, and answers how many payload bytes arrived.
///
/// Both parameters are what a test sets its link rate with. A pause inside the
/// bound keeps the pulls coming, and a step that leaves the socket buffers
/// drainable in a few reads keeps the buffered tail inside the bound as well.
async fn drain_body(stream: &mut TcpStream, step: usize, pause: Duration) -> usize {
    let mut buffer = vec![0_u8; step];
    let mut body = Vec::new();
    while !body.ends_with(b"0\r\n\r\n") {
        let read = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        body.extend_from_slice(&buffer[..read]);
        tokio::time::sleep(pause).await;
    }
    chunked_payload(&body)
}

/// How many payload bytes a chunked body carries, framing removed, so a
/// transport that dropped payload cannot pass for one that sent it.
fn chunked_payload(body: &[u8]) -> usize {
    let mut rest = body;
    let mut payload = 0;
    while let Some(line) = rest.windows(2).position(|pair| pair == b"\r\n") {
        let size = core::str::from_utf8(&rest[..line])
            .ok()
            .and_then(|size| usize::from_str_radix(size, 16).ok())
            .unwrap_or(0);
        if size == 0 {
            break;
        }
        payload += size;
        let next = line.saturating_add(4).saturating_add(size);
        if next >= rest.len() {
            break;
        }
        rest = &rest[next..];
    }
    payload
}

/// Answers one request head with `reply`, once the request has fully arrived.
async fn write_reply(stream: &mut TcpStream, reply: &str) {
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.flush().await;
}

/// A server that reads a request at the trickle rate and then answers it.
fn trickling_server(listener: TcpListener) -> JoinHandle<usize> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        let received = drain_body(&mut stream, TRICKLE_READ, TRICKLE_PAUSE).await;
        write_reply(&mut stream, NO_CONTENT).await;
        received
    })
}

/// A server that answers one request head with `reply` and reads no body.
fn deaf_server(listener: TcpListener, reply: Option<&'static str>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        if let Some(reply) = reply {
            write_reply(&mut stream, reply).await;
        }
        core::future::pending::<()>().await;
    })
}

/// The stage each abort test drives, named by what it aborts.
async fn put_unbufferable(address: SocketAddr) -> Result<HttpReply, HttpFailure<ReqwestHttpError>> {
    transport()
        .put(&chunk_url(address), vec![7_u8; UNBUFFERABLE])
        .await
}

/// Where one chunk's bytes go on a local listener.
fn chunk_url(address: SocketAddr) -> String {
    format!("http://{address}/chunks/deadbeef?t=ticket")
}

/// Where an upload declares its manifest on a local listener.
fn intent_url(address: SocketAddr) -> String {
    format!("http://{address}/files/deadbeef/intent?t=ticket")
}

/// Drives one stage that must abort, and answers the failure it aborted with.
///
/// The ceiling is what makes the injected bound load-bearing, because a
/// transport that kept a bound of its own would answer nowhere near it, and
/// the floor is the bound itself, which a transport may never abort before.
async fn abort_of<T>(
    work: impl Future<Output = Result<T, HttpFailure<ReqwestHttpError>>>,
    what: &str,
) -> HttpFailure<ReqwestHttpError> {
    let started = Instant::now();
    let answer = tokio::time::timeout(CEILING, work)
        .await
        .unwrap_or_else(|_| panic!("{what} must abort under the injected bound, not its own"));
    let Err(failure) = answer else {
        panic!("{what} must abort");
    };
    assert!(
        matches!(
            failure,
            HttpFailure::Transport(ReqwestHttpError::Idle { .. })
        ),
        "{what} must abort as the transport's idle failure, got {failure}"
    );
    assert!(
        started.elapsed() >= BOUND,
        "{what} must not abort before the bound, aborted after {:?}",
        started.elapsed()
    );
    failure
}

/// An upload that keeps moving is never aborted, however long it runs, and
/// this one runs several times the bound at a rate a total deadline of one
/// bound would have failed.
#[tokio::test]
async fn a_trickling_upload_is_never_aborted() {
    let (listener, address) = local_listener().await;
    let server = trickling_server(listener);
    let started = Instant::now();

    let status = transport()
        .put(&chunk_url(address), vec![7_u8; TRICKLED])
        .await
        .map(|reply| reply.status)
        .expect("a moving upload is never aborted");

    assert_eq!(status, 204, "the server answered the chunk");
    assert!(
        started.elapsed() > BOUND,
        "the upload must outlast the bound for this to prove anything, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        server.await.expect("server"),
        TRICKLED,
        "every payload byte arrived, framing aside"
    );
}

/// A server that stops reading stalls the send, and the send aborts.
#[tokio::test]
async fn a_stalled_upload_aborts_after_the_bound() {
    let (listener, address) = local_listener().await;
    let server = deaf_server(listener, None);

    abort_of(put_unbufferable(address), "a stalled send").await;

    server.abort();
}

/// Silence while the server holds the answer back aborts the same way.
#[tokio::test]
async fn a_stalled_status_wait_aborts_after_the_bound() {
    let (listener, address) = local_listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        drain_body(&mut stream, TRICKLE_READ, Duration::ZERO).await;
        core::future::pending::<()>().await;
    });

    abort_of(
        transport().put(&chunk_url(address), b"a small chunk".to_vec()),
        "a withheld status line",
    )
    .await;

    server.abort();
}

/// A reply that stops before its length is reached aborts the download.
#[tokio::test]
async fn a_stalled_download_aborts_after_the_bound() {
    let (listener, address) = local_listener().await;
    let server = deaf_server(
        listener,
        Some("HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nfour"),
    );

    abort_of(
        transport().get(&format!("http://{address}/files/deadbeef?t=ticket"), None),
        "a stalled reply body",
    )
    .await;

    server.abort();
}

/// The transport's own client follows nothing, so a `3xx` arrives as a reply
/// for the negotiation to refuse.
#[tokio::test]
async fn a_redirect_reply_is_answered_rather_than_followed() {
    let (listener, address) = local_listener().await;
    let (elsewhere, elsewhere_address) = local_listener().await;
    let elsewhere_server = tokio::spawn(async move {
        tokio::time::timeout(BOUND, elsewhere.accept())
            .await
            .is_ok()
    });
    let reply = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{elsewhere_address}/chunks/deadbeef?t=ticket\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        drain_body(&mut stream, TRICKLE_READ, Duration::ZERO).await;
        write_reply(&mut stream, &reply).await;
    });

    let status = transport()
        .put(&chunk_url(address), b"a small chunk".to_vec())
        .await
        .expect("a redirect reply is a reply")
        .status;

    assert_eq!(status, 302, "the hop is answered rather than taken");
    assert!(
        !elsewhere_server.await.expect("second listener"),
        "nothing reached the address the hop named"
    );
    server.await.expect("server");
}

/// An application client whose policy follows lands its reply elsewhere, and
/// the transport refuses that reply by the address it landed on.
///
/// A `302` on a `POST` becomes a bodiless `GET`, which is a request the
/// redirect layer can replay, so the hop is taken and the manifest is dropped
/// on the way. The refusal is what stops the negotiation from reading an
/// answer another origin wrote.
#[tokio::test]
async fn a_followed_redirect_is_refused_by_the_address_it_landed_on() {
    let (listener, address) = local_listener().await;
    let (elsewhere, elsewhere_address) = local_listener().await;
    let elsewhere_server = tokio::spawn(async move {
        let (mut stream, _) = elsewhere.accept().await.expect("accept");
        let head = read_head(&mut stream).await;
        write_reply(&mut stream, NO_CONTENT).await;
        head
    });
    let reply = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{elsewhere_address}/chunks/deadbeef?t=ticket\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        drain_body(&mut stream, TRICKLE_READ, Duration::ZERO).await;
        write_reply(&mut stream, &reply).await;
    });

    let failure = ReqwestHttp::with_client(reqwest::Client::new())
        .with_idle_bound(BOUND)
        .post(&intent_url(address), Some(br#"{"total_len":13}"#.to_vec()))
        .await
        .map(|reply| reply.status)
        .expect_err("a reply from another address is refused");

    match failure {
        HttpFailure::Redirected { origin } => assert_eq!(
            origin.as_deref(),
            Some(format!("http://{elsewhere_address}").as_str()),
            "the refusal names the origin the reply landed on"
        ),
        other @ HttpFailure::Transport(_) => {
            panic!("a followed redirect must be refused, got {other}")
        }
    }
    assert!(
        elsewhere_server
            .await
            .expect("second listener")
            .starts_with("GET "),
        "a 302 lands as a bodiless GET, which is why the origin is what is refused"
    );
    server.await.expect("server");
}

/// A streamed body is never replayed to a hop, so a `307` on a chunk upload
/// arrives as its own reply and nothing reaches the address it named.
#[tokio::test]
async fn a_streamed_body_never_lands_on_the_address_a_hop_named() {
    let (listener, address) = local_listener().await;
    let (elsewhere, elsewhere_address) = local_listener().await;
    let elsewhere_server = tokio::spawn(async move {
        tokio::time::timeout(BOUND, elsewhere.accept())
            .await
            .is_ok()
    });
    let reply = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{elsewhere_address}/chunks/deadbeef?t=ticket\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        drain_body(&mut stream, TRICKLE_READ, Duration::ZERO).await;
        write_reply(&mut stream, &reply).await;
    });

    let status = ReqwestHttp::with_client(reqwest::Client::new())
        .with_idle_bound(BOUND)
        .put(&chunk_url(address), b"a small chunk".to_vec())
        .await
        .expect("an unreplayable body ends the chain")
        .status;

    assert_eq!(status, 307, "the reply of the hop is what arrives");
    assert!(
        !elsewhere_server.await.expect("second listener"),
        "no byte of a streamed body reaches the address the hop named"
    );
    server.await.expect("server");
}

/// A hop to another path on the same origin is refused as well, because the
/// ticket points at one address and only that address answers for it.
#[tokio::test]
async fn a_same_origin_redirect_is_refused_too() {
    let (listener, address) = local_listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        let reply = "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        write_reply(&mut stream, reply).await;
        let (mut second, _) = listener.accept().await.expect("second accept");
        read_head(&mut second).await;
        write_reply(&mut second, NO_CONTENT).await;
    });

    let failure = ReqwestHttp::with_client(reqwest::Client::new())
        .with_idle_bound(BOUND)
        .get(&format!("http://{address}/files/deadbeef?t=ticket"), None)
        .await
        .map(|reply| reply.status)
        .expect_err("a reply from another path is refused");

    match failure {
        HttpFailure::Redirected { origin } => assert_eq!(
            origin.as_deref(),
            Some(format!("http://{address}").as_str()),
            "the refusal names the origin, which here is the one asked"
        ),
        other @ HttpFailure::Transport(_) => {
            panic!("a same-origin hop must be refused, got {other}")
        }
    }
    server.await.expect("server");
}

/// A bound that never elapses is what an ordinary exchange runs under, so the
/// watchdog costs a completed request nothing.
#[tokio::test]
async fn an_answered_request_reports_what_the_server_sent() {
    let (listener, address) = local_listener().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        read_head(&mut stream).await;
        let reply = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nneeded!";
        write_reply(&mut stream, reply).await;
    });

    let reply = transport()
        .get(&format!("http://{address}/files/deadbeef?t=ticket"), None)
        .await
        .expect("an answered request");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"needed!");
    server.await.expect("server");
}
