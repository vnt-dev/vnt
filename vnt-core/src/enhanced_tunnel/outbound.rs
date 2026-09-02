use crate::context::SharedNetworkAddr;
use crate::enhanced_tunnel::quic_over::quic_outbound::EnhancedQuicOutbound;
use crate::ethernet::{
    MacTable, build_arp_reply, is_broadcast_or_multicast, mac_from_ip, parse_arp_ipv4, parse_frame,
};
use crate::nat::SubnetMappingTable;
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::HybridOutbound;
use pnet_base::MacAddr;
use pnet_packet::arp::ArpOperations;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;

fn learned_unicast_peer(
    mac_table: &MacTable,
    destination: MacAddr,
    local_peer: Ipv4Addr,
    route_exists: impl FnOnce(&Ipv4Addr) -> bool,
) -> Option<Ipv4Addr> {
    if is_broadcast_or_multicast(destination) {
        return None;
    }
    let peer = mac_table.lookup(destination)?;
    if peer != local_peer && route_exists(&peer) {
        return Some(peer);
    }
    mac_table.remove_peer(peer);
    None
}

pub struct EnhancedOutbound {
    network: SharedNetworkAddr,
    enhanced_quic_outbound: EnhancedQuicOutbound,
    hybrid_outbound: HybridOutbound,
    subnet_mapping: SubnetMappingTable,
    subnet_packet_mapper: SubnetPacketMapper,
    mac_table: MacTable,
}

impl EnhancedOutbound {
    pub fn new(
        network: SharedNetworkAddr,
        enhanced_quic_outbound: EnhancedQuicOutbound,
        hybrid_outbound: HybridOutbound,
        subnet_mapping: SubnetMappingTable,
        subnet_packet_mapper: SubnetPacketMapper,
        mac_table: MacTable,
    ) -> Self {
        Self {
            network,
            enhanced_quic_outbound,
            hybrid_outbound,
            subnet_mapping,
            subnet_packet_mapper,
            mac_table,
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
        self.ethernet_outbound_impl(data).await.unwrap_or_else(|e| {
            log::warn!("EnhancedOutbound Ethernet error: {e:?}");
            None
        })
    }
    async fn ethernet_outbound_impl(
        &self,
        data: TransmissionBytes,
    ) -> anyhow::Result<Option<TransmissionBytes>> {
        let Some(frame) = parse_frame(data.as_ref()) else {
            return Ok(None);
        };
        self.mac_table.observe_local_source(frame.source);
        let Some(net) = self.network.get() else {
            return Ok(None);
        };

        if frame.ethertype == EtherTypes::Arp
            && let Some(arp) = parse_arp_ipv4(data.as_ref())
            && arp.operation == ArpOperations::Request
            && arp.target_ip == net.gateway
        {
            return Ok(build_arp_reply(data.as_ref(), net.gateway));
        }

        // Only frames explicitly addressed to our proxy-ARP gateway enter the
        // existing L3 path. Every other Ethernet frame is switched by MAC.
        if frame.ethertype == EtherTypes::Ipv4 && frame.destination == mac_from_ip(net.gateway) {
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
            return Ok(None);
        }

        if let Some(peer) =
            learned_unicast_peer(&self.mac_table, frame.destination, net.ip, |peer| {
                self.hybrid_outbound.has_route(peer)
            })
        {
            self.hybrid_outbound
                .ethernet_unicast_outbound(net, peer, data)
                .await?;
            return Ok(None);
        }

        // Broadcast, multicast and unknown unicast use the overlay flood path,
        // matching a normal learning bridge.
        self.hybrid_outbound
            .ethernet_broadcast_outbound(net, data)
            .await?;
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
            // 广播或组播
            if self.hybrid_outbound.no_broadcast() {
                return Ok(());
            }
            return self
                .hybrid_outbound
                .ipv4_broadcast_outbound(net, data)
                .await;
        }
        let packets = if net.network().contains(&dest) {
            if let Some(mapped) = self.subnet_mapping.reverse(src) {
                self.subnet_packet_mapper
                    .map_source(dest, data, 0, src, mapped)?
            } else {
                vec![data]
            }
        } else {
            vec![data]
        };
        for data in packets {
            if self
                .enhanced_quic_outbound
                .outbound(&net, data.as_ref())
                .await
            {
                // 使用quic 通道传输
                continue;
            }
            // 使用通用通道传输
            self.hybrid_outbound.ipv4_outbound(net, data).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_learned_mac_is_unicast_and_unknown_mac_is_flooded() {
        let mac_table = MacTable::default();
        let local_peer = Ipv4Addr::new(10, 26, 0, 9);
        let remote_peer = Ipv4Addr::new(10, 26, 0, 8);
        let bridged_mac = MacAddr::new(0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        assert_eq!(
            learned_unicast_peer(&mac_table, bridged_mac, local_peer, |_| true),
            None
        );

        mac_table.learn_remote(bridged_mac, remote_peer);
        assert_eq!(
            learned_unicast_peer(&mac_table, bridged_mac, local_peer, |_| true),
            Some(remote_peer)
        );
        assert_eq!(
            learned_unicast_peer(&mac_table, MacAddr::broadcast(), local_peer, |_| true),
            None
        );
    }

    #[test]
    fn unreachable_peer_is_removed_from_mac_table() {
        let mac_table = MacTable::default();
        let local_peer = Ipv4Addr::new(10, 26, 0, 9);
        let remote_peer = Ipv4Addr::new(10, 26, 0, 8);
        let remote_mac = MacAddr::new(0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        mac_table.learn_remote(remote_mac, remote_peer);

        assert_eq!(
            learned_unicast_peer(&mac_table, remote_mac, local_peer, |_| false),
            None
        );
        assert_eq!(mac_table.lookup(remote_mac), None);
    }
}
