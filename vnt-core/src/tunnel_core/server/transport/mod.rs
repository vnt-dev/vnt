use crate::protocol::ip_packet_protocol::NetPacket;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::transport::config::{ConnectConfig, ProtocolType};
use crate::tunnel_core::server::transport::quic::QuicTransport;
use crate::tunnel_core::server::transport::tcp::TlsTcpTransport;
use crate::tunnel_core::server::transport::wss::WssTransport;
use anyhow::{Context, bail};
use bytes::Bytes;
use std::time::Duration;

pub mod config;
pub(crate) mod quic;
pub(crate) mod tcp;
pub(crate) mod wss;

#[derive(Default)]
pub(crate) enum TransportClient {
    Quic(QuicTransport),
    TlsTcp(TlsTcpTransport),
    Wss(WssTransport),
    #[default]
    Pending,
}

impl TransportClient {
    pub fn new() -> Self {
        TransportClient::default()
    }
    pub fn disconnect(&mut self) {
        match self {
            TransportClient::Quic(c) => c.disconnect(),
            TransportClient::TlsTcp(c) => c.disconnect(),
            TransportClient::Wss(c) => c.disconnect(),
            TransportClient::Pending => {}
        };
        *self = TransportClient::Pending;
    }
    pub async fn connect_timeout(
        &mut self,
        config: &ConnectConfig,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, self.connect(config))
            .await
            .context("timeout")?
    }
    pub async fn connect(&mut self, config: &ConnectConfig) -> anyhow::Result<()> {
        match self {
            TransportClient::Quic(c) => c.connect(config).await?,
            TransportClient::TlsTcp(c) => c.connect(config).await?,
            TransportClient::Wss(c) => c.connect(config).await?,
            TransportClient::Pending => match config.protocol_type {
                ProtocolType::Quic => {
                    let mut transport = QuicTransport::new();
                    transport.connect(config).await?;
                    *self = TransportClient::Quic(transport);
                }
                ProtocolType::TlsTcp => {
                    let mut transport = TlsTcpTransport::new();
                    transport.connect(config).await?;
                    *self = TransportClient::TlsTcp(transport);
                }
                ProtocolType::Wss => {
                    let mut transport = WssTransport::new();
                    transport.connect(config).await?;
                    *self = TransportClient::Wss(transport);
                }
                ProtocolType::Dynamic => {
                    bail!("unreachable connect")
                }
            },
        };
        Ok(())
    }

    pub async fn send(&mut self, buf: Bytes) -> anyhow::Result<()> {
        match self {
            TransportClient::Quic(c) => c.send(buf).await,
            TransportClient::TlsTcp(c) => c.send(buf).await,
            TransportClient::Wss(c) => c.send(buf).await,
            TransportClient::Pending => {
                bail!("Not connected");
            }
        }
    }
    pub async fn next(&mut self) -> anyhow::Result<TransmissionBytes> {
        match self {
            TransportClient::Quic(c) => c.next().await,
            TransportClient::TlsTcp(c) => c.next().await,
            TransportClient::Wss(c) => c.next().await,

            TransportClient::Pending => {
                bail!("Not connected");
            }
        }
    }
    pub async fn next_timeout(&mut self, timeout: Duration) -> anyhow::Result<TransmissionBytes> {
        tokio::time::timeout(timeout, self.next())
            .await
            .context("timeout")?
    }
    pub async fn send_turn(&mut self, buf: NetPacket<TransmissionBytes>) -> anyhow::Result<()> {
        self.send(buf.into_buffer().into_bytes().freeze()).await
    }
}
