use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::transport::config::ConnectConfig;
use anyhow::{Context, bail};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::{WebSocketStream, client_async, tungstenite::Message};

type WssStream = WebSocketStream<TlsStream<TcpStream>>;

#[derive(Default)]
pub struct WssTransport {
    stream: Option<WssStream>,
}

impl WssTransport {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn disconnect(&mut self) {
        self.stream = None;
    }
    pub async fn connect(&mut self, config: &ConnectConfig) -> anyhow::Result<()> {
        if self.stream.is_some() {
            bail!("Already connected");
        }
        let stream = connect_wss(config).await?;
        self.stream = Some(stream);
        Ok(())
    }
    pub async fn send(&mut self, buf: Bytes) -> anyhow::Result<()> {
        let Some(framed) = self.stream.as_mut() else {
            bail!("Not connected");
        };
        framed
            .send(Message::Binary(buf))
            .await
            .context("send to server failed")
    }
    pub async fn next(&mut self) -> anyhow::Result<TransmissionBytes> {
        let Some(framed) = self.stream.as_mut() else {
            bail!("Not connected");
        };
        loop {
            let message = framed
                .next()
                .await
                .context("EOF")?
                .context("receive from server failed")?;
            match message {
                Message::Binary(buf) => {
                    return Ok(TransmissionBytes::from(buf));
                }
                Message::Close(_) => {
                    bail!("Disconnected");
                }
                _ => {
                    continue;
                }
            }
        }
    }
}

pub async fn connect_wss(config: &ConnectConfig) -> anyhow::Result<WssStream> {
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
    let url = format!("wss://{}", server_name);

    let dns_name = server_name
        .try_into()
        .context("Invalid server name for TLS")?;

    let tls_stream = connector
        .connect(dns_name, tcp_stream)
        .await
        .context("Failed to perform TLS handshake")?;

    let (ws_stream, _response) = client_async(url, tls_stream)
        .await
        .context("Failed to perform WebSocket handshake")?;

    Ok(ws_stream)
}
