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

    let tcp_stream = TcpStream::connect(server_addr)
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
