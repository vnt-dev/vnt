use crate::enhanced_tunnel::quic_over::enhanced_io::enhanced_inbound::QuicDataInbound;
use bytes::Bytes;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct EnhancedQuicInbound {
    quic_data_inbound: QuicDataInbound,
}

impl EnhancedQuicInbound {
    pub fn new(quic_data_inbound: QuicDataInbound) -> Self {
        Self { quic_data_inbound }
    }
    pub async fn inbound(&self, data: Bytes, src: Ipv4Addr) -> anyhow::Result<()> {
        self.quic_data_inbound.send(data, src).await?;
        Ok(())
    }
}
