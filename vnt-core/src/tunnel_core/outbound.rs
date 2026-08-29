use crate::compression::PacketCompression;
use crate::context::config::{TurnRule, is_turn_ip, turn_ip_for};
use crate::context::{NetworkAddr, ServerInfoCollection, SharedNetworkAddr, TrafficStats};
use crate::crypto::PacketCrypto;
use crate::fec::FecEncoder;
use crate::nat::SubnetExternalRoute;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use bytes::Bytes;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PreferredTurn {
    Server,
    Peer(Ipv4Addr),
}

fn preferred_turn(net: NetworkAddr, rules: &[TurnRule], dest: &Ipv4Addr) -> Option<PreferredTurn> {
    if is_turn_ip(rules, dest) {
        return None;
    }
    let turn_ip = turn_ip_for(rules, dest)?;
    if net.gateway == turn_ip {
        Some(PreferredTurn::Server)
    } else {
        Some(PreferredTurn::Peer(turn_ip))
    }
}

#[derive(Clone)]
pub(crate) struct BasicOutbound {
    server_outbound: ServerOutbound,
    p2p_outbound: Option<P2pOutbound>,
    packet_crypto: PacketCrypto,
    turn: Arc<Vec<TurnRule>>,
}

impl BasicOutbound {
    pub fn new(
        server_outbound: ServerOutbound,
        p2p_outbound: Option<P2pOutbound>,
        packet_crypto: PacketCrypto,
        turn: Arc<Vec<TurnRule>>,
    ) -> Self {
        Self {
            server_outbound,
            p2p_outbound,
            packet_crypto,
            turn,
        }
    }

    /// 获取加密保留空间大小
    pub fn encrypt_reserve(&self) -> usize {
        self.packet_crypto.encrypt_reserve()
    }

    pub fn fec_auth_reserve(&self) -> usize {
        self.packet_crypto.fec_auth_reserve()
    }

    /// 加密数据包
    pub fn encrypt_in_place(
        &self,
        packet: &mut NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        Ok(self.packet_crypto.encrypt_in_place(packet)?)
    }

    /// 发送原始数据包到指定目标（通过P2P或服务器）
    pub async fn send_raw(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let packet = packet.into_bytes();
        if let Some(p2p) = self.p2p_outbound.as_ref() {
            match preferred_turn(net, &self.turn, &dest) {
                Some(PreferredTurn::Server) => {
                    self.server_outbound.send_raw(dest, packet).await?;
                    return Ok(());
                }
                Some(PreferredTurn::Peer(turn_ip))
                    if let Some(route) = p2p.get_direct_route_by_id(&turn_ip) =>
                {
                    p2p.send_raw_to(packet, &route.route_key()).await?;
                    return Ok(());
                }
                _ => {}
            }
            if let Some(route) = p2p.get_route_by_id(&dest) {
                p2p.send_raw_to(packet, &route.route_key()).await?;
                return Ok(());
            }
        }
        self.server_outbound.send_raw(dest, packet).await?;
        Ok(())
    }

    /// 发送到默认服务器
    pub async fn send_default_raw(
        &self,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let bytes = packet.into_buffer().into_bytes().freeze();
        self.server_outbound
            .send_default_raw(NetPacket::new(bytes)?)
            .await
    }

    /// 广播发送
    pub async fn send_raw_broadcast(
        &self,
        exclude_ips: Option<Vec<Ipv4Addr>>,
        packet: NetPacket<Bytes>,
    ) -> anyhow::Result<()> {
        self.server_outbound
            .send_raw_broadcast(exclude_ips, packet)
            .await
    }

    /// 检查是否存在到目标的路由
    pub fn exists_route(&self, dest: &Ipv4Addr) -> bool {
        if let Some(p2p) = self.p2p_outbound.as_ref()
            && p2p.exists_route_by_id(dest)
        {
            return true;
        }
        self.server_outbound.exists_route(dest)
    }

    /// P2P广播（内部转换类型）
    pub fn p2p_broadcast_transmission(
        &self,
        list: &[Ipv4Addr],
        max_count: usize,
        packet: &NetPacket<Bytes>,
    ) -> Option<Vec<Ipv4Addr>> {
        if let Some(p2p) = self.p2p_outbound.as_ref() {
            let vec = p2p.p2p_broadcast(list, max_count, packet);
            if vec.is_empty() { None } else { Some(vec) }
        } else {
            None
        }
    }

    /// 发送加密后的数据包
    pub async fn send_encrypted_packet(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        // 加密
        self.packet_crypto.encrypt_in_place(&mut packet)?;
        self.send_raw(net, dest, packet).await
    }

    /// 认证并发送 FEC 外层包。FEC 内层已经是普通 AEAD 密文或 QUIC 密文，
    /// 外层只追加认证标签，不再重复加密。
    pub async fn send_fec_packet(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.packet_crypto.authenticate_fec_in_place(&mut packet)?;
        self.send_raw(net, dest, packet).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_gateway_turn_forces_server_and_peer_turn_stays_p2p() {
        let rules = vec!["10.26.1.0/24,10.26.0.1".parse().unwrap()];
        let target = Ipv4Addr::new(10, 26, 1, 9);
        let network = NetworkAddr {
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            broadcast: Ipv4Addr::new(10, 26, 255, 255),
            ip: Ipv4Addr::new(10, 26, 0, 8),
            prefix_len: 16,
        };
        assert_eq!(
            preferred_turn(network, &rules, &target),
            Some(PreferredTurn::Server)
        );
        let peer_network = NetworkAddr {
            gateway: Ipv4Addr::new(10, 26, 0, 254),
            ..network
        };
        assert_eq!(
            preferred_turn(peer_network, &rules, &target),
            Some(PreferredTurn::Peer(Ipv4Addr::new(10, 26, 0, 1)))
        );
        assert_eq!(preferred_turn(network, &rules, &network.gateway), None);
    }
}

#[derive(Clone)]
pub(crate) struct HybridOutbound {
    network: SharedNetworkAddr,
    server_info: ServerInfoCollection,
    traffic_stats: TrafficStats,
    basic_outbound: BasicOutbound,
    packet_compression: PacketCompression,
    external_route: SubnetExternalRoute,
    fec_encoder: Option<FecEncoder>,
    no_broadcast: bool,
}
impl HybridOutbound {
    pub fn new(
        network: SharedNetworkAddr,
        server_info: ServerInfoCollection,
        traffic_stats: TrafficStats,
        basic_outbound: BasicOutbound,
        packet_compression: PacketCompression,
        external_route: SubnetExternalRoute,
        fec_encoder: Option<FecEncoder>,
    ) -> Self {
        Self {
            network,
            server_info,
            traffic_stats,
            basic_outbound,
            packet_compression,
            external_route,
            fec_encoder,
            no_broadcast: false,
        }
    }

    pub fn with_no_broadcast(mut self, no_broadcast: bool) -> Self {
        self.no_broadcast = no_broadcast;
        self
    }
    pub async fn outbound_raw(
        &self,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let Some(net) = self.network.get() else {
            bail!("Not src ip")
        };
        if packet.src_id() == 0 {
            packet.set_src_id(net.ip.into());
        }

        let len = packet.buffer().len() as u64;

        if let Some(fec_encoder) = &self.fec_encoder {
            packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound.send_raw(net, dest, packet).await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }
    pub async fn ipv4_outbound_common(&self, data: TransmissionBytes) -> anyhow::Result<()> {
        let Some(net) = self.network.get() else {
            bail!("Not src ip")
        };
        self.ipv4_outbound(net, data).await
    }
    pub async fn ipv4_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let mut dest = ipv4.get_destination();
        let len = data.len() as u64;
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_ttl(5);
        // 路由
        if !net.network().contains(&dest) {
            if let Some(v) = self.external_route.route(&dest) {
                dest = v;
            } else {
                return Ok(());
            }
        }
        packet.set_dest_id(dest.into());

        packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;

        if let Some(fec_encoder) = &self.fec_encoder {
            self.basic_outbound.encrypt_in_place(&mut packet)?;
            packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound
                .send_encrypted_packet(net, dest, packet)
                .await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }

    pub async fn ethernet_ipv4_outbound(
        &self,
        net: NetworkAddr,
        data: TransmissionBytes,
        mut dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        if dest == net.gateway {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.ipv4_gateway_outbound(net, ip).await;
        }
        if dest.is_multicast() || dest == net.broadcast || dest.is_broadcast() {
            if self.no_broadcast {
                return Ok(());
            }
            return self.ethernet_broadcast_outbound(net, data).await;
        }
        if !net.network().contains(&dest) {
            if let Some(route) = self.external_route.route(&dest) {
                dest = route;
            } else {
                return Ok(());
            }
        }
        self.ethernet_unicast_outbound(net, dest, data).await
    }

    pub async fn ethernet_unicast_outbound(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let len = data.len() as u64;
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(dest.into());
        packet.set_ttl(5);
        packet.set_ethernet_flag(true);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        if let Some(fec_encoder) = &self.fec_encoder {
            self.basic_outbound.encrypt_in_place(&mut packet)?;
            let packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound
                .send_encrypted_packet(net, dest, packet)
                .await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }
    pub async fn ipv4_gateway_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(net.gateway.into());
        packet.set_ttl(5);
        packet.set_gateway_flag(true);
        self.basic_outbound.send_default_raw(packet).await?;
        Ok(())
    }
    pub async fn ipv4_broadcast_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Broadcast);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(Ipv4Addr::BROADCAST.into());
        packet.set_ttl(5);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        let list = self.server_info.client_online_ips();
        let exclude_ips = self
            .basic_outbound
            .p2p_broadcast_transmission(&list, 16, &packet_bytes);
        if let Some(exclude_ips) = &exclude_ips
            && exclude_ips.len() == list.len()
        {
            return Ok(());
        }

        self.basic_outbound
            .send_raw_broadcast(exclude_ips, packet_bytes)
            .await
    }

    pub async fn ethernet_broadcast_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Broadcast);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(Ipv4Addr::BROADCAST.into());
        packet.set_ttl(5);
        packet.set_ethernet_flag(true);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        let list = self.server_info.client_online_ips();
        let exclude_ips = self
            .basic_outbound
            .p2p_broadcast_transmission(&list, 16, &packet_bytes);
        if let Some(exclude_ips) = &exclude_ips
            && exclude_ips.len() == list.len()
        {
            return Ok(());
        }
        self.basic_outbound
            .send_raw_broadcast(exclude_ips, packet_bytes)
            .await
    }
    pub fn has_route(&self, dest: &Ipv4Addr) -> bool {
        self.basic_outbound.exists_route(dest)
    }

    pub fn no_broadcast(&self) -> bool {
        self.no_broadcast
    }
}
