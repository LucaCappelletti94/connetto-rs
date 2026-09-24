//! A TCP relay a device proof owns between an app and a server, so the proof
//! can take the app offline and back without touching the device. A relay can
//! also terminate TLS, which is how a stack serves a server that speaks plain
//! HTTP to devices that insist on HTTPS.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

/// Forwards every connection accepted on one address to `upstream` while it
/// runs.
pub struct Relay {
    listen: SocketAddr,
    upstream: String,
    tls: Option<TlsAcceptor>,
    task: Option<JoinHandle<()>>,
}

impl Relay {
    /// Listen on `listen` and forward to `upstream`.
    ///
    /// # Errors
    ///
    /// When `listen` cannot be bound.
    pub async fn start(listen: &str, upstream: &str) -> Result<Self> {
        Self::launch(listen, upstream, None).await
    }

    /// Listen on `listen`, terminate TLS with the PEM certificate chain and
    /// key at `cert` and `key`, and forward the plain stream to `upstream`.
    ///
    /// # Errors
    ///
    /// When the certificate or key cannot be read or used, or `listen`
    /// cannot be bound.
    pub async fn start_tls(listen: &str, upstream: &str, cert: &Path, key: &Path) -> Result<Self> {
        let chain = CertificateDer::pem_file_iter(cert)
            .with_context(|| format!("reading {}", cert.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("parsing {}", cert.display()))?;
        let key = PrivateKeyDer::from_pem_file(key)
            .with_context(|| format!("reading {}", key.display()))?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .context("the TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("the TLS certificate and key")?;
        Self::launch(listen, upstream, Some(TlsAcceptor::from(Arc::new(config)))).await
    }

    async fn launch(listen: &str, upstream: &str, tls: Option<TlsAcceptor>) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the relay on {listen}"))?;
        let listen = listener.local_addr().context("the relay's address")?;
        let upstream = upstream.to_owned();
        let task = Some(tokio::spawn(serve(listener, upstream.clone(), tls.clone())));
        Ok(Self {
            listen,
            upstream,
            tls,
            task,
        })
    }

    /// The address the relay listens on.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.listen
    }

    /// Stop listening and drop every connection through the relay, returning
    /// once the listener is closed.
    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    /// Listen again on the same address.
    ///
    /// # Errors
    ///
    /// When the address cannot be bound again.
    pub async fn resume(&mut self) -> Result<()> {
        self.stop().await;
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("binding the relay on {} again", self.listen))?;
        self.task = Some(tokio::spawn(serve(
            listener,
            self.upstream.clone(),
            self.tls.clone(),
        )));
        Ok(())
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Accept and forward until aborted. The connections live in a set this task
/// owns, so aborting it aborts every one of them.
async fn serve(listener: TcpListener, upstream: String, tls: Option<TlsAcceptor>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { continue };
                let upstream = upstream.clone();
                let tls = tls.clone();
                connections.spawn(async move {
                    let Ok(mut server) = TcpStream::connect(&upstream).await else { return };
                    if let Some(tls) = tls {
                        if let Ok(mut client) = tls.accept(client).await {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        }
                    } else {
                        let mut client = client;
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::Relay;

    /// An upstream that echoes every byte back.
    async fn echo() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let address = listener.local_addr().expect("echo address").to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        address
    }

    async fn round_trip(stream: &mut TcpStream) -> std::io::Result<u8> {
        stream.write_all(&[7]).await?;
        let mut byte = [0];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .map_err(|_| std::io::Error::other("no echo"))??;
        Ok(byte[0])
    }

    /// Stopping drops a connection already through the relay and refuses new
    /// ones, which is what the app sees as losing the network, and resuming
    /// forwards new connections again on the same address.
    #[tokio::test]
    async fn stopping_drops_live_connections_and_resuming_forwards_again() {
        let mut relay = Relay::start("127.0.0.1:0", &echo().await)
            .await
            .expect("start");
        let mut live = TcpStream::connect(relay.address()).await.expect("connect");
        assert_eq!(
            round_trip(&mut live).await.expect("echo through the relay"),
            7
        );

        relay.stop().await;
        assert!(
            round_trip(&mut live).await.is_err(),
            "the live connection survived"
        );
        assert!(
            TcpStream::connect(relay.address()).await.is_err(),
            "a stopped relay accepted a connection"
        );

        relay.resume().await.expect("resume");
        let mut again = TcpStream::connect(relay.address())
            .await
            .expect("reconnect");
        assert_eq!(
            round_trip(&mut again).await.expect("echo after resuming"),
            7
        );
    }
}
