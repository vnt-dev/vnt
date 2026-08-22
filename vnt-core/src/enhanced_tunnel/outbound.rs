use crate::context::SharedNetworkAddr;
use crate::enhanced_tunnel::quic_over::quic_outbound::EnhancedQuicOutbound;
use crate::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, build_arp_reply, ip_from_mac, is_broadcast_or_multicast,
    parse_arp_ipv4, parse_frame,
};
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
    pub async fn ethernet_outbound(&self, data: TransmissionBytes) -> Option<TransmissionBytes> {
        match self.ethernet_outbound_impl(data).await {
            Ok(reply) => reply,
            Err(e) => {
                log::warn!("EnhancedOutbound Ethernet error: {e:?}");
                None
            }
        }
    }
    async fn ethernet_outbound_impl(
        &self,
        data: TransmissionBytes,
    ) -> anyhow::Result<Option<TransmissionBytes>> {
        let Some(frame) = parse_frame(data.as_ref()) else {
            return Ok(None);
        };
        let Some(net) = self.network.get() else {
            return Ok(None);
        };
        match frame.ethertype {
            ETHERTYPE_IPV4 => {
                let Some(ipv4) = Ipv4Packet::new(&data[frame.payload_offset..]) else {
                    return Ok(None);
                };
                let src = ipv4.get_source();
                let dest = ipv4.get_destination();
                if dest == src || dest.is_unspecified() {
                    return Ok(None);
                }
                self.hybrid_outbound
                    .ethernet_ipv4_outbound(net, data, dest)
                    .await?;
            }
            ETHERTYPE_ARP => {
                let Some(arp) = parse_arp_ipv4(data.as_ref()) else {
                    return Ok(None);
                };
                if arp.operation == 1 && arp.target_ip == net.gateway {
                    return Ok(build_arp_reply(data.as_ref(), net.gateway));
                }
                if arp.operation == 2 {
                    let dest = ip_from_mac(frame.destination).unwrap_or(arp.target_ip);
                    self.hybrid_outbound
                        .ethernet_unicast_outbound(net, dest, data)
                        .await?;
                } else {
                    self.hybrid_outbound
                        .ethernet_broadcast_outbound(net, data)
                        .await?;
                }
            }
            _ => {
                if !is_broadcast_or_multicast(frame.destination)
                    && let Some(dest) = ip_from_mac(frame.destination)
                    && net.network().contains(&dest)
                {
                    self.hybrid_outbound
                        .ethernet_unicast_outbound(net, dest, data)
                        .await?;
                } else {
                    self.hybrid_outbound
                        .ethernet_broadcast_outbound(net, data)
                        .await?;
                }
            }
        }
        Ok(None)
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
