use crate::context::SharedNetworkAddr;
use crate::enhanced_tunnel::quic_over::quic_outbound::EnhancedQuicOutbound;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::HybridOutbound;
use pnet_packet::ipv4::Ipv4Packet;

pub struct EnhancedOutbound {
    network: SharedNetworkAddr,
    enhanced_quic_outbound: EnhancedQuicOutbound,
    hybrid_outbound: HybridOutbound,
}

impl EnhancedOutbound {
    pub fn new(
        network: SharedNetworkAddr,
        enhanced_quic_outbound: EnhancedQuicOutbound,
        hybrid_outbound: HybridOutbound,
    ) -> Self {
        Self {
            network,
            enhanced_quic_outbound,
            hybrid_outbound,
        }
    }
    pub async fn ipv4_outbound(&self, data: TransmissionBytes) {
        if data.is_empty() || data[0] >> 4 != 4 {
            return;
        }
        if let Err(e) = self.ipv4_outbound_impl(data).await {
            log::warn!("EnhancedOutbound error: {:?}", e);
        }
    }
    async fn ipv4_outbound_impl(&self, data: TransmissionBytes) -> anyhow::Result<()> {
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let Some(net) = self.network.get() else {
            return Ok(());
        };
        let src = ipv4.get_source();

        let dest = ipv4.get_destination();
        if dest == src || dest.is_unspecified() {
            return Ok(());
        }
        if dest == net.gateway {
            // 发送到网关
            return self.hybrid_outbound.ipv4_gateway_outbound(net, data).await;
        }
        if dest.is_multicast() || dest == net.broadcast || dest.is_broadcast() {
            // 广播
            return self
                .hybrid_outbound
                .ipv4_broadcast_outbound(net, data)
                .await;
        }
        if self
            .enhanced_quic_outbound
            .outbound(&net, data.as_ref())
            .await
        {
            // 使用quic 通道传输
            return Ok(());
        }
        // 使用通用通道传输
        self.hybrid_outbound.ipv4_outbound(net, data).await
    }
}
