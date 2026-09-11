use crate::compression::PacketCompression;
use crate::context::config::{TurnRule, is_turn_ip, turn_ip_for};
use crate::context::{NetworkAddr, ServerInfoCollection, SharedNetworkAddr, TrafficStats};
use crate::crypto::PacketCrypto;
use crate::fec::FecEncoder;
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::nat::{AllowSubnetExternalRoute, SubnetExternalRoute, SubnetMappingTable};
use crate::protocol::client_message::{NodeDiscovery, NodeIdentityTemplate};
use crate::protocol::control_message::ClientType;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use bytes::Bytes;
use parking_lot::Mutex;
use pnet_packet::ipv4::Ipv4Packet;
use rustp2p_core::route_table::RouteKey;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_PER_NODE: usize = 8;
const MAX_PENDING_BYTES_PER_NODE: usize = 64 * 1024;
const MAX_PENDING_BYTES: usize = 2 * 1024 * 1024;
const GRAPH_DEDUP_TTL: Duration = Duration::from_secs(60);
const GRAPH_DEDUP_CAPACITY: usize = 8192;
const PROBE_BACKOFF: [Duration; 5] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(300),
];
type GraphMessageKey = (u8, Ipv4Addr, u32);
type GraphSeen = Arc<Mutex<HashMap<GraphMessageKey, Instant>>>;

#[derive(Default)]
struct PendingDiscovery {
    targets: HashMap<Ipv4Addr, PendingTarget>,
    backoff: HashMap<Ipv4Addr, ProbeBackoff>,
    total_bytes: usize,
    probe_times: VecDeque<Instant>,
}

struct PendingTarget {
    packets: Vec<Bytes>,
    bytes: usize,
    started: Instant,
}

struct ProbeBackoff {
    next_attempt: Instant,
    step: usize,
    touched: Instant,
}

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
    if net.gateway == Some(turn_ip) {
        Some(PreferredTurn::Server)
    } else {
        Some(PreferredTurn::Peer(turn_ip))
    }
}

fn relay_msg_type_for(
    client_type: Option<ClientType>,
    allow_ikev2: bool,
    allow_wireguard: bool,
) -> Option<MsgType> {
    match client_type {
        Some(ClientType::Ikev2) if allow_ikev2 => Some(MsgType::Ikev2Relay),
        Some(ClientType::Wireguard) if allow_wireguard => Some(MsgType::WireGuardRelay),
        _ => None,
    }
}

#[derive(Clone)]
pub(crate) struct BasicOutbound {
    server_outbound: ServerOutbound,
    p2p_outbound: Option<P2pOutbound>,
    packet_crypto: PacketCrypto,
    turn: Arc<Vec<TurnRule>>,
    identity: NodeIdentityTemplate,
    pending: Arc<Mutex<PendingDiscovery>>,
    graph_seen: GraphSeen,
}

impl BasicOutbound {
    pub fn new(
        server_outbound: ServerOutbound,
        p2p_outbound: Option<P2pOutbound>,
        packet_crypto: PacketCrypto,
        turn: Arc<Vec<TurnRule>>,
        identity: NodeIdentityTemplate,
    ) -> Self {
        Self {
            server_outbound,
            p2p_outbound,
            packet_crypto,
            turn,
            identity,
            pending: Arc::new(Mutex::new(PendingDiscovery::default())),
            graph_seen: Arc::new(Mutex::new(HashMap::new())),
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
        let p2p_route = self.p2p_outbound.as_ref().is_some_and(|p2p| {
            match preferred_turn(net, &self.turn, &dest) {
                Some(PreferredTurn::Peer(turn_ip)) => {
                    p2p.get_direct_route_by_id(&turn_ip).is_some()
                }
                Some(PreferredTurn::Server) => false,
                None => p2p.get_route_by_id(&dest).is_some(),
            }
        });
        if !p2p_route && !self.server_outbound.exists_route(&dest) {
            return self
                .queue_unknown_and_probe(net, dest, packet.into_bytes())
                .await;
        }
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

    pub async fn send_server_raw(
        &self,
        dest: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.server_outbound
            .send_raw(dest, packet.into_bytes())
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

    /// Floods an already encrypted graph-control packet over all direct
    /// tunnels. The ingress tunnel is excluded to prevent immediate
    /// reflection; sequence based deduplication handles graph cycles.
    pub fn flood_direct_p2p(&self, packet: &NetPacket<Bytes>, exclude: Option<&RouteKey>) -> usize {
        self.p2p_outbound
            .as_ref()
            .map(|p2p| p2p.flood_direct(packet, exclude))
            .unwrap_or(0)
    }

    pub fn p2p_outbound(&self) -> Option<&P2pOutbound> {
        self.p2p_outbound.as_ref()
    }

    pub async fn flood_connected_servers(
        &self,
        packet: NetPacket<Bytes>,
        exclude_server: Option<u32>,
    ) -> usize {
        self.server_outbound
            .flood_connected_raw(packet, exclude_server)
            .await
    }

    pub fn graph_first_seen(&self, msg_type: MsgType, source: Ipv4Addr, seq: u32) -> bool {
        let now = Instant::now();
        let mut seen = self.graph_seen.lock();
        seen.retain(|_, time| now.duration_since(*time) < GRAPH_DEDUP_TTL);
        let key = (msg_type as u8, source, seq);
        if seen.contains_key(&key) {
            return false;
        }
        if seen.len() >= GRAPH_DEDUP_CAPACITY
            && let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, time)| **time)
                .map(|(key, _)| *key)
        {
            seen.remove(&oldest);
        }
        seen.insert(key, now);
        true
    }

    /// 发送加密后的数据包
    pub async fn send_encrypted_packet(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut packet)?;
        self.send_raw(net, dest, packet).await
    }

    async fn queue_unknown_and_probe(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        packet: NetPacket<Bytes>,
    ) -> anyhow::Result<()> {
        let bytes = packet.into_buffer();
        let packet_len = bytes.len();
        let now = Instant::now();
        let mut start_probe = false;
        {
            let mut pending = self.pending.lock();
            pending
                .probe_times
                .retain(|time| now.duration_since(*time) < Duration::from_secs(1));
            pending
                .backoff
                .retain(|_, state| now.duration_since(state.touched) < Duration::from_secs(600));
            if packet_len > MAX_PENDING_BYTES_PER_NODE
                || pending.total_bytes + packet_len > MAX_PENDING_BYTES
            {
                bail!("pending packet byte limit reached for {dest}")
            }
            if !pending.targets.contains_key(&dest) {
                if pending
                    .backoff
                    .get(&dest)
                    .is_some_and(|state| now < state.next_attempt)
                {
                    bail!("node discovery for {dest} is backing off")
                }
                if pending.probe_times.len() >= 30 {
                    bail!("node discovery rate limit reached")
                }
                pending.probe_times.push_back(now);
                pending.targets.insert(
                    dest,
                    PendingTarget {
                        packets: Vec::new(),
                        bytes: 0,
                        started: now,
                    },
                );
                start_probe = true;
            }
            let target = pending.targets.get(&dest).expect("pending target inserted");
            if target.packets.len() >= MAX_PENDING_PER_NODE
                || target.bytes + packet_len > MAX_PENDING_BYTES_PER_NODE
            {
                bail!("pending packet limit reached for {dest}")
            }
            let target = pending
                .targets
                .get_mut(&dest)
                .expect("pending target inserted");
            target.packets.push(bytes);
            target.bytes += packet_len;
            pending.total_bytes += packet_len;
        }

        if start_probe {
            if let Err(error) = self.publish_node_probe(net, dest) {
                self.remove_pending(dest);
                return Err(error);
            }
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if this.exists_route(&dest) {
                        this.flush_pending(net, dest).await;
                        break;
                    }
                    let expired = this
                        .pending
                        .lock()
                        .targets
                        .get(&dest)
                        .is_none_or(|target| target.started.elapsed() >= PROBE_TIMEOUT);
                    if expired {
                        this.drop_pending_with_backoff(dest, "node discovery timed out");
                        break;
                    }
                }
            });
        }
        Ok(())
    }

    fn publish_node_probe(&self, net: NetworkAddr, dest: Ipv4Addr) -> anyhow::Result<()> {
        let payload = NodeDiscovery {
            identity: self.identity.with_ip(net.ip),
            request_id: rand::random(),
        }
        .encode();
        let mut probe = NetPacket::new(TransmissionBytes::zeroed_size(
            HEAD_LENGTH + payload.len(),
            self.encrypt_reserve(),
        ))?;
        probe.set_msg_type(MsgType::NodeProbe);
        probe.set_ttl(15);
        probe.set_src_id(net.ip.into());
        probe.set_dest_id(dest.into());
        probe.set_payload(&payload)?;
        self.packet_crypto.encrypt_in_place(&mut probe)?;
        let probe = probe.into_bytes();
        self.graph_first_seen(MsgType::NodeProbe, net.ip, probe.seq());
        self.flood_direct_p2p(&probe, None);
        let server = self.server_outbound.clone();
        tokio::spawn(async move {
            let _ = server.flood_connected_raw(probe, None).await;
        });
        Ok(())
    }

    async fn flush_pending(&self, _net: NetworkAddr, dest: Ipv4Addr) {
        let Some(target) = ({
            let mut pending = self.pending.lock();
            let target = pending.targets.remove(&dest);
            pending.backoff.remove(&dest);
            if let Some(target) = target.as_ref() {
                pending.total_bytes = pending.total_bytes.saturating_sub(target.bytes);
            }
            target
        }) else {
            return;
        };
        for bytes in target.packets {
            let Ok(packet) = NetPacket::new(bytes) else {
                continue;
            };
            if let Some(p2p) = self.p2p_outbound.as_ref()
                && let Some(route) = p2p.get_route_by_id(&dest)
            {
                if let Err(error) = p2p.send_raw_to(packet, &route.route_key()).await {
                    log::debug!("failed to flush discovered P2P packet for {dest}: {error}");
                }
                continue;
            }
            if let Err(error) = self.server_outbound.send_raw(dest, packet).await {
                log::debug!("failed to flush discovered server packet for {dest}: {error}");
            }
        }
    }

    fn remove_pending(&self, dest: Ipv4Addr) {
        let mut pending = self.pending.lock();
        if let Some(target) = pending.targets.remove(&dest) {
            pending.total_bytes = pending.total_bytes.saturating_sub(target.bytes);
        }
    }

    fn drop_pending_with_backoff(&self, dest: Ipv4Addr, reason: &str) {
        let mut pending = self.pending.lock();
        if let Some(target) = pending.targets.remove(&dest) {
            pending.total_bytes = pending.total_bytes.saturating_sub(target.bytes);
            let now = Instant::now();
            let state = pending.backoff.entry(dest).or_insert(ProbeBackoff {
                next_attempt: now,
                step: 0,
                touched: now,
            });
            let delay = PROBE_BACKOFF[state.step.min(PROBE_BACKOFF.len() - 1)];
            state.next_attempt = now + delay;
            state.step = (state.step + 1).min(PROBE_BACKOFF.len() - 1);
            state.touched = now;
            log::debug!(
                "drop {} queued packets ({} bytes) for {dest}: {reason}",
                target.packets.len(),
                target.bytes
            );
        }
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
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
            broadcast: Ipv4Addr::new(10, 26, 255, 255),
            ip: Ipv4Addr::new(10, 26, 0, 8),
            prefix_len: 16,
        };
        assert_eq!(
            preferred_turn(network, &rules, &target),
            Some(PreferredTurn::Server)
        );
        let peer_network = NetworkAddr {
            gateway: Some(Ipv4Addr::new(10, 26, 0, 254)),
            ..network
        };
        assert_eq!(
            preferred_turn(peer_network, &rules, &target),
            Some(PreferredTurn::Peer(Ipv4Addr::new(10, 26, 0, 1)))
        );
        assert_eq!(
            preferred_turn(network, &rules, &network.gateway.unwrap()),
            None
        );
    }

    #[test]
    fn relay_message_type_respects_independent_capabilities() {
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Ikev2), true, false),
            Some(MsgType::Ikev2Relay)
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Wireguard), false, true),
            Some(MsgType::WireGuardRelay)
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Ikev2), false, true),
            None
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Wireguard), true, false),
            None
        );
        assert_eq!(relay_msg_type_for(Some(ClientType::Vnt), true, true), None);
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
    subnet_mapping: SubnetMappingTable,
    subnet_packet_mapper: SubnetPacketMapper,
    relay_subnets: AllowSubnetExternalRoute,
    fec_encoder: Option<FecEncoder>,
    no_broadcast: bool,
    allow_ikev2: bool,
    allow_wireguard: bool,
}
impl HybridOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: SharedNetworkAddr,
        server_info: ServerInfoCollection,
        traffic_stats: TrafficStats,
        basic_outbound: BasicOutbound,
        packet_compression: PacketCompression,
        external_route: SubnetExternalRoute,
        subnet_mapping: SubnetMappingTable,
        subnet_packet_mapper: SubnetPacketMapper,
        relay_subnets: AllowSubnetExternalRoute,
        fec_encoder: Option<FecEncoder>,
    ) -> Self {
        Self {
            network,
            server_info,
            traffic_stats,
            basic_outbound,
            packet_compression,
            external_route,
            subnet_mapping,
            subnet_packet_mapper,
            relay_subnets,
            fec_encoder,
            no_broadcast: false,
            allow_ikev2: false,
            allow_wireguard: false,
        }
    }

    pub fn with_no_broadcast(mut self, no_broadcast: bool) -> Self {
        self.no_broadcast = no_broadcast;
        self
    }
    pub fn with_allow_ikev2(mut self, allow_ikev2: bool) -> Self {
        self.allow_ikev2 = allow_ikev2;
        self
    }

    pub fn with_allow_wireguard(mut self, allow_wireguard: bool) -> Self {
        self.allow_wireguard = allow_wireguard;
        self
    }
    pub fn is_relay_client(&self, ip: &Ipv4Addr) -> bool {
        self.relay_msg_type(ip).is_some()
    }
    fn relay_msg_type(&self, ip: &Ipv4Addr) -> Option<MsgType> {
        relay_msg_type_for(
            self.server_info.client_type(ip),
            self.allow_ikev2,
            self.allow_wireguard,
        )
    }
    pub async fn server_relay_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let Some(msg_type) = self.relay_msg_type(&dest) else {
            return Ok(());
        };
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let header_length = ipv4.get_header_length() as usize * 4;
        let total_length = ipv4.get_total_length() as usize;
        if header_length < Ipv4Packet::minimum_packet_size()
            || total_length < header_length
            || total_length > data.len()
            || (ipv4.get_source() != net.ip && !self.relay_subnets.allow(&ipv4.get_source()))
            || (ipv4.get_destination() != dest
                && self.external_route.route(&ipv4.get_destination()) != Some(dest))
        {
            return Ok(());
        }
        if total_length < data.len() {
            let trailing = data.len() - total_length;
            data.shrink_end(trailing);
        }
        let len = data.len() as u64;
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(msg_type);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(dest.into());
        packet.set_ttl(15);
        self.basic_outbound.send_server_raw(dest, packet).await?;
        self.traffic_stats.record_tx(dest, len);
        Ok(())
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
        data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let source = ipv4.get_source();
        let mut dest = ipv4.get_destination();
        let len = data.len() as u64;
        let dest_is_overlay = net.network().contains(&dest);
        if !dest_is_overlay {
            if let Some(v) = self.external_route.route(&dest) {
                dest = v;
            } else {
                return Ok(());
            }
        }
        // On an output node, replies leave the physical network with their real
        // source. Restore the mapped source immediately before tunnelling them
        // back to the overlay peer. Access-side packets remain untouched.
        let packets = if dest_is_overlay {
            if let Some(mapped) = self.subnet_mapping.reverse(source) {
                self.subnet_packet_mapper
                    .map_source(dest, data, 0, source, mapped)?
            } else {
                vec![data]
            }
        } else {
            vec![data]
        };
        if self.is_relay_client(&dest) {
            for data in packets {
                self.server_relay_outbound(net, data, dest).await?;
            }
            return Ok(());
        }
        for data in packets {
            self.ipv4_outbound_to(net, data, dest).await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }

    async fn ipv4_outbound_to(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_ttl(15);
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
        Ok(())
    }

    pub async fn ethernet_ipv4_outbound(
        &self,
        net: NetworkAddr,
        data: TransmissionBytes,
        mut dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        if self.is_relay_client(&dest) {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.server_relay_outbound(net, ip, dest).await;
        }
        if net.gateway == Some(dest) {
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
        let dest_is_overlay = net.network().contains(&dest);
        if !dest_is_overlay {
            if let Some(route) = self.external_route.route(&dest) {
                dest = route;
            } else {
                return Ok(());
            }
        }
        if self.is_relay_client(&dest) {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.server_relay_outbound(net, ip, dest).await;
        }
        let packets = if dest_is_overlay {
            let Some(frame) = crate::ethernet::parse_frame(data.as_ref()) else {
                return Ok(());
            };
            let Some(ipv4) = Ipv4Packet::new(&data[frame.payload_offset..]) else {
                return Ok(());
            };
            let source = ipv4.get_source();
            if let Some(mapped) = self.subnet_mapping.reverse(source) {
                self.subnet_packet_mapper.map_source(
                    dest,
                    data,
                    frame.payload_offset,
                    source,
                    mapped,
                )?
            } else {
                vec![data]
            }
        } else {
            vec![data]
        };
        for packet in packets {
            self.ethernet_unicast_outbound(net, dest, packet).await?;
        }
        Ok(())
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
        packet.set_ttl(15);
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
        let Some(gateway) = net.gateway else {
            return Ok(());
        };
        packet.set_dest_id(gateway.into());
        packet.set_ttl(15);
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
        packet.set_ttl(15);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        self.basic_outbound
            .graph_first_seen(MsgType::Broadcast, net.ip, packet_bytes.seq());
        let p2p_sent = self.basic_outbound.flood_direct_p2p(&packet_bytes, None);
        match self
            .basic_outbound
            .send_raw_broadcast(None, packet_bytes)
            .await
        {
            Ok(()) => Ok(()),
            Err(_) if p2p_sent > 0 => Ok(()),
            Err(error) => Err(error),
        }
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
        packet.set_ttl(15);
        packet.set_ethernet_flag(true);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        self.basic_outbound
            .graph_first_seen(MsgType::Broadcast, net.ip, packet_bytes.seq());
        let p2p_sent = self.basic_outbound.flood_direct_p2p(&packet_bytes, None);
        match self
            .basic_outbound
            .send_raw_broadcast(None, packet_bytes)
            .await
        {
            Ok(()) => Ok(()),
            Err(_) if p2p_sent > 0 => Ok(()),
            Err(error) => Err(error),
        }
    }
    pub fn has_route(&self, dest: &Ipv4Addr) -> bool {
        self.basic_outbound.exists_route(dest)
    }

    pub fn no_broadcast(&self) -> bool {
        self.no_broadcast
    }
}
