use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::transport::config::ConnectConfig;
use anyhow::{Context, bail};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

type TlsTcpStream = TlsStream<TcpStream>;

#[derive(Default)]
pub struct TlsTcpTransport {
    framed: Option<Framed<TlsTcpStream, LengthDelimitedCodec>>,
}

impl TlsTcpTransport {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn disconnect(&mut self) {
        self.framed = None;
    }
    pub async fn graceful_disconnect(&mut self) {
        if let Some(mut framed) = self.framed.take() {
            // `SinkExt::close` flushes the length-delimited sink and shuts down
            // the rustls writer, which sends TLS close_notify before dropping
            // the underlying TCP stream.
            let _ = framed.close().await;
        }
    }
    pub async fn connect(&mut self, config: &ConnectConfig) -> anyhow::Result<()> {
        if self.framed.is_some() {
            bail!("Already connected");
        }
        let framed = connect_tls_tcp(config).await?;
        self.framed = Some(framed);
        Ok(())
    }
    pub async fn send(&mut self, buf: Bytes) -> anyhow::Result<()> {
        let Some(framed) = self.framed.as_mut() else {
            bail!("Not connected");
        };
        framed.send(buf).await.context("send to server failed")
    }
    pub async fn next(&mut self) -> anyhow::Result<TransmissionBytes> {
        let Some(framed) = self.framed.as_mut() else {
            bail!("Not connected");
        };
        framed
            .next()
            .await
            .context("EOF")?
            .context("receive from server failed")
            .map(TransmissionBytes::from)
    }
}

pub async fn connect_tls_tcp(
    config: &ConnectConfig,
) -> anyhow::Result<Framed<TlsTcpStream, LengthDelimitedCodec>> {
    let server_addr = config.server_addr();
    let server_name = config.server_name().clone();

    let rustls_config = config.cert_mode.create_tls_client_config()?;
    let connector = TlsConnector::from(Arc::new(rustls_config));

    let tcp_stream =
        crate::utils::socket::connect_tcp(server_addr, config.default_interface.as_ref())
            .await
            .context("Failed to establish underlying TCP connection")?;
    if let Err(e) = tcp_stream.set_nodelay(true) {
        log::error!("Failed to set TCP_NODELAY: {}", e);
    }
    let dns_name = server_name
        .try_into()
        .context("Invalid server name for TLS")?;

    let tls_stream = connector
        .connect(dns_name, tcp_stream)
        .await
        .context("Failed to perform TLS handshake")?;

    let framed = Framed::new(tls_stream, LengthDelimitedCodec::new());

    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cert::generate_deterministic_cert;
    use crate::tls::verifier::CertValidationMode;
    use rustls::pki_types::ServerName;
    use sha2::{Digest, Sha256};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn graceful_disconnect_sends_tls_close_notify() {
        let (certificate, key) = generate_deterministic_cert("graceful-close-test").unwrap();
        let fingerprint: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .unwrap();
            let mut framed = Framed::new(tls, LengthDelimitedCodec::new());
            assert!(
                framed.next().await.is_none(),
                "graceful TLS shutdown must be observed as EOF, not a read error"
            );
        });

        let client_config = CertValidationMode::VerifyFingerprint(fingerprint)
            .create_tls_client_config()
            .unwrap();
        let tcp = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(Arc::new(client_config))
            .connect(
                ServerName::try_from("deterministic-node")
                    .unwrap()
                    .to_owned(),
                tcp,
            )
            .await
            .unwrap();
        let mut transport = TlsTcpTransport {
            framed: Some(Framed::new(tls, LengthDelimitedCodec::new())),
        };
        transport.graceful_disconnect().await;
        server.await.unwrap();
    }
}
