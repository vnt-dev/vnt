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

    let tcp_stream =
        crate::utils::socket::connect_tcp(server_addr, config.default_interface.as_ref())
            .await
            .context("Failed to establish underlying TCP connection")?;
    if let Err(e) = tcp_stream.set_nodelay(true) {
        log::error!("Failed to set TCP_NODELAY: {}", e);
    }
    let url = wss_url(&server_name, server_addr.port());

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

/// Build the WebSocket URL authority from the configured server name.
///
/// `ConnectConfig::server_name` intentionally stores IPv6 literals without
/// brackets so it can be used as a TLS `ServerName`. URLs, however, require
/// brackets around an IPv6 host and must include the configured port.
fn wss_url(server_name: &str, port: u16) -> String {
    let host = if server_name.contains(':') {
        format!("[{server_name}]")
    } else {
        server_name.to_owned()
    };
    format!("wss://{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::wss_url;

    #[test]
    fn url_preserves_port_and_brackets_ipv6_literal() {
        assert_eq!(wss_url("example.com", 8443), "wss://example.com:8443");
        assert_eq!(wss_url("192.0.2.1", 8443), "wss://192.0.2.1:8443");
        assert_eq!(wss_url("2001:db8::1", 8443), "wss://[2001:db8::1]:8443");
    }
}
