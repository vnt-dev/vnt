use crate::compression::PacketCompression;
use crate::context::config::{TurnRule, allow_punch};
use crate::context::nat::PunchBackoff;
use crate::context::{NetworkAddr, NetworkRoute, PacketLossStats, PeerInfoMap};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::fec::FecDecoder;
use crate::protocol::client_message::{
    NETWORK_CODE_HASH_LEN, NodeIdentityTemplate, PeerHandshake, PunchInfo, network_code_hash,
    network_code_hash_matches,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::node_info::{NodeInfo, NodeInfoMap};
use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
use crate::tunnel_core::p2p::transport::punch::{NatPuncher, PunchInfoGetter};
use anyhow::bail;
use rustp2p_core::endpoint::TunnelWriteHalf;
use rustp2p_core::route_table::RouteKey;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
const GOSSIP_TTL: u8 = 15;

#[derive(Clone, Copy)]
struct PacketContext {
    msg_type: MsgType,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    max_ttl: u8,
    ttl: u8,
}

fn valid_punch_source(net: &NetworkAddr, source: Ipv4Addr) -> bool {
    !source.is_unspecified() && source != net.ip && net.network().contains(&source)
}

fn gossip_relay_targets(
    net: &NetworkAddr,
    source: Ipv4Addr,
    source_metric: u8,
    advertised: &[Ipv4Addr],
) -> Vec<Ipv4Addr> {
    if source_metric != 1 {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    advertised
        .iter()
        .copied()
        .filter(|target| {
            *target != net.ip
                && *target != source
                && !target.is_unspecified()
                && !target.is_broadcast()
                && *target != net.broadcast
                && net.network().contains(target)
                && seen.insert(*target)
        })
        .collect()
}

fn learn_gossip_relay_routes(
    route_table: &RouteTable,
    net: &NetworkAddr,
    source: Ipv4Addr,
    source_metric: u8,
    route_key: RouteKey,
    advertised: &[Ipv4Addr],
) {
    let relay_metric = source_metric.saturating_add(1);
    for target in gossip_relay_targets(net, source, source_metric, advertised) {
        route_table.add_gossip_relay_route(target, Route::from_default_rt(route_key, relay_metric));
    }
}

fn build_direct_handshake_response(
    msg_type: MsgType,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    encrypt_reserve: usize,
    identity: Option<(&NodeIdentityTemplate, u64)>,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let payload = if let Some((identity, request_id)) = identity {
        PeerHandshake {
            identity: identity.with_ip(local_ip),
            request_id,
        }
        .encode()
        .to_vec()
    } else {
        crate::utils::time::now_ts_ms().to_be_bytes().to_vec()
    };
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + payload.len(),
        encrypt_reserve,
    ))?;
    packet.set_msg_type(msg_type);
    packet.set_ttl(1);
    packet.set_src_id(local_ip.into());
    packet.set_dest_id(peer_ip.into());
    packet.set_payload(&payload)?;
    Ok(packet)
}

fn direct_identity(
    net: &NetworkAddr,
    source: Ipv4Addr,
    payload: &[u8],
    local: &NodeIdentityTemplate,
) -> anyhow::Result<Option<(NodeInfo, u64)>> {
    if payload.len() == 8 {
        return Ok(None);
    }
    let handshake = PeerHandshake::from_slice(payload)?;
    if handshake.identity.ip != source
        || handshake.identity.network_code != local.network_code
        || !net.network().contains(&source)
    {
        bail!("peer identity does not match packet source or local network")
    }
    Ok(Some((
        NodeInfo {
            ip: source,
            name: handshake.identity.name,
            version: handshake.identity.version,
            advertised_subnets: handshake.identity.advertised_subnets,
        },
        handshake.request_id,
    )))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PunchPayloadKind {
    Legacy,
    Current,
}

fn validate_punch_payload(payload: &[u8], network_code: &str) -> anyhow::Result<PunchPayloadKind> {
    match payload.len() {
        8 => Ok(PunchPayloadKind::Legacy),
        NETWORK_CODE_HASH_LEN if network_code_hash_matches(network_code, payload) => {
            Ok(PunchPayloadKind::Current)
        }
        NETWORK_CODE_HASH_LEN => bail!("punch network code hash mismatch"),
        length => bail!("invalid punch payload length: {length}"),
    }
}

fn build_punch_response(
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    encrypt_reserve: usize,
    kind: PunchPayloadKind,
    network_code: &str,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let payload = match kind {
        PunchPayloadKind::Legacy => crate::utils::time::now_ts_ms().to_be_bytes().to_vec(),
        PunchPayloadKind::Current => network_code_hash(network_code).to_vec(),
    };
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + payload.len(),
        encrypt_reserve,
    ))?;
    packet.set_msg_type(MsgType::PunchRes);
    packet.set_ttl(1);
    packet.set_src_id(local_ip.into());
    packet.set_dest_id(peer_ip.into());
    packet.set_payload(&payload)?;
    Ok(packet)
}

fn build_destination_unreachable(
    local_ip: Ipv4Addr,
    upstream_ip: Ipv4Addr,
    destination: Ipv4Addr,
    encrypt_reserve: usize,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + 4,
        encrypt_reserve,
    ))?;
    packet.set_msg_type(MsgType::DestinationUnreachable);
    packet.set_ttl(1);
    packet.set_src_id(local_ip.into());
    packet.set_dest_id(upstream_ip.into());
    packet.set_payload(&destination.octets())?;
    Ok(packet)
}

fn parse_destination_unreachable(net: &NetworkAddr, payload: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = payload.try_into().ok()?;
    let destination = Ipv4Addr::from(octets);
    (destination != net.ip
        && !destination.is_unspecified()
        && !destination.is_broadcast()
        && destination != net.broadcast
        && net.network().contains(&destination))
    .then_some(destination)
}

pub(crate) struct P2pInboundConfig {
    pub network_route: NetworkRoute,
    pub route_table: RouteTable,
    pub node_info_map: NodeInfoMap,
    pub packet_loss_stats: PacketLossStats,
    pub packet_crypto: PacketCrypto,
    pub packet_compression: PacketCompression,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
    pub turn: Arc<Vec<TurnRule>>,
    pub basic_outbound: BasicOutbound,
    pub punch_backoff: PunchBackoff,
    pub identity: NodeIdentityTemplate,
    pub auto_sync_subnet: bool,
    pub puncher: NatPuncher,
    pub punch_info_getter: PunchInfoGetter,
    pub peer_map: PeerInfoMap,
}

#[derive(Clone)]
pub(crate) struct P2pInboundHandler {
    network_route: NetworkRoute,
    route_table: RouteTable,
    node_info_map: NodeInfoMap,
    packet_loss_stats: PacketLossStats,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
    turn: Arc<Vec<TurnRule>>,
    basic_outbound: BasicOutbound,
    punch_backoff: PunchBackoff,
    identity: NodeIdentityTemplate,
    auto_sync_subnet: bool,
    puncher: NatPuncher,
    punch_info_getter: PunchInfoGetter,
    peer_map: PeerInfoMap,
}

impl P2pInboundHandler {
    pub fn new(config: P2pInboundConfig) -> Self {
        Self {
            network_route: config.network_route,
            route_table: config.route_table,
            node_info_map: config.node_info_map,
            packet_loss_stats: config.packet_loss_stats,
            packet_crypto: config.packet_crypto,
            packet_compression: config.packet_compression,
            enhanced_inbound: config.enhanced_inbound,
            fec_decoder: config.fec_decoder,
            turn: config.turn,
            basic_outbound: config.basic_outbound,
            punch_backoff: config.punch_backoff,
            identity: config.identity,
            auto_sync_subnet: config.auto_sync_subnet,
            puncher: config.puncher,
            punch_info_getter: config.punch_info_getter,
            peer_map: config.peer_map,
        }
    }
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        self.network_route.network_contains(ip)
    }
    pub async fn next_handle(
        &self,
        buf: TransmissionBytes,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
    ) {
        if let Err(e) = self.next_handle_impl(buf, route_key, tunnel).await {
            log::warn!(
                "Error while handling P2pInboundHandler: {:?},route={route_key:?}",
                e
            );
        }
    }
    async fn next_handle_impl(
        &self,
        buf: TransmissionBytes,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
    ) -> anyhow::Result<()> {
        let mut net_packet = NetPacket::new(buf)?;
        let msg_type = net_packet.msg_type()?;
        let src_ip = Ipv4Addr::from(net_packet.src_id());
        let dest_ip = Ipv4Addr::from(net_packet.dest_id());
        if src_ip == dest_ip {
            return Ok(());
        }
        net_packet.decr_ttl();

        let max_ttl = net_packet.max_ttl();
        let ttl = net_packet.ttl();
        if max_ttl <= ttl {
            return Ok(());
        }
        let Some(net) = self.network_route.network.get() else {
            bail!("未找到自身IP")
        };
        if src_ip == net.ip {
            return Ok(());
        }
        if matches!(msg_type, MsgType::NodeAnnouncement | MsgType::Broadcast) {
            return self
                .process_graph_packet(&net, route_key, tunnel, net_packet)
                .await;
        }
        if net.ip != dest_ip
            && !dest_ip.is_broadcast()
            && !dest_ip.is_unspecified()
            && dest_ip != net.broadcast
        {
            // An unreachable notification is strictly one hop. A malformed or
            // stale notification addressed elsewhere must never recurse into
            // another unreachable notification.
            if msg_type == MsgType::DestinationUnreachable {
                return Ok(());
            }
            // 帮忙转发数据包
            if ttl >= 1
                && self
                    .basic_outbound
                    .try_send_raw(net, dest_ip, net_packet, Some(&route_key))
                    .await?
            {
                return Ok(());
            }
            self.send_destination_unreachable(net, dest_ip, route_key, tunnel)
                .await?;
            return Ok(());
        }

        // FEC 外层只有认证、没有 AEAD 加密，必须先验证认证并恢复内层密文包。
        if net_packet.is_fec() {
            let packets = self.fec_decoder.receive(net_packet)?;
            if let Some(packets) = packets {
                for pkt in packets {
                    self.process_inner_packet(&net, route_key, tunnel, pkt)
                        .await?;
                }
            }
            return Ok(());
        }

        self.process_inner_packet(&net, route_key, tunnel, net_packet)
            .await
    }

    async fn process_graph_packet(
        &self,
        net: &NetworkAddr,
        route_key: RouteKey,
        _tunnel: &TunnelWriteHalf,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let encrypted = NetPacket::new(packet.source_buf().clone())?.into_bytes();
        let msg_type = packet.msg_type()?;
        let source = Ipv4Addr::from(packet.src_id());
        let seq = packet.seq();
        let metric = packet.max_ttl().saturating_sub(packet.ttl()).max(1);
        self.packet_crypto.decrypt_in_place(&mut packet)?;

        if msg_type == MsgType::Broadcast {
            if !self.basic_outbound.graph_first_seen(msg_type, source, seq) {
                return Ok(());
            }
            if packet.ttl() >= 1 {
                self.basic_outbound
                    .flood_direct_p2p(&encrypted, Some(&route_key));
                self.basic_outbound
                    .flood_connected_servers(encrypted.clone(), None)
                    .await;
            }
            let packet = self.packet_compression.decompress(packet)?;
            self.enhanced_inbound
                .inbound(net, msg_type, source, packet)
                .await?;
            return Ok(());
        }

        let announcement = crate::protocol::client_message::NodeAnnouncement::from_slice(
            packet.payload(),
            source,
        )?;
        if !net.network().contains(&source) {
            bail!("invalid gossip node identity from {source}")
        }
        let node = NodeInfo {
            ip: source,
            name: announcement.identity.name,
            version: announcement.identity.version,
            advertised_subnets: announcement.identity.advertised_subnets,
        };
        // Learning is deliberately done before deduplication: a duplicate
        // arriving on another edge is a useful backup next hop.
        let accepted = self
            .route_table
            .add_gossip_route(node.ip, Route::from_default_rt(route_key, metric));
        let identity_changed = accepted && self.node_info_map.upsert(node);
        if identity_changed {
            self.sync_gossip_subnets();
        }
        learn_gossip_relay_routes(
            &self.route_table,
            net,
            source,
            metric,
            route_key,
            &announcement.direct_peer_ips,
        );
        if !self.basic_outbound.graph_first_seen(msg_type, source, seq) {
            return Ok(());
        }

        if msg_type == MsgType::NodeAnnouncement && packet.ttl() >= 1 {
            self.basic_outbound
                .flood_direct_p2p(&encrypted, Some(&route_key));
            self.basic_outbound
                .flood_connected_servers(encrypted, None)
                .await;
        }
        Ok(())
    }

    /// 处理网络直接收到或由 FEC 恢复的内层包。普通包在进入 FEC 前已经完成
    /// AEAD 加密，需要在这里解密；QUIC payload 由 QUIC 自己负责解密。
    async fn process_inner_packet(
        &self,
        net: &crate::context::NetworkAddr,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
        mut net_packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        if net_packet.msg_type()? != MsgType::Quic {
            self.packet_crypto.decrypt_in_place(&mut net_packet)?;
            let source = Ipv4Addr::from(net_packet.src_id());
            if let Some(next_hop) = self.route_table.route_owner(&route_key) {
                self.route_table.clear_suppressed_path(source, next_hop);
            }
        }
        self.process_plain_packet(net, route_key, tunnel, net_packet)
            .await
    }

    /// 处理已经完成普通包解密/FEC 解码的原始 NetPacket。
    async fn process_plain_packet(
        &self,
        net: &crate::context::NetworkAddr,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
        net_packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let msg_type = net_packet.msg_type()?;
        let src_ip = Ipv4Addr::from(net_packet.src_id());
        let dest_ip = Ipv4Addr::from(net_packet.dest_id());

        if msg_type == MsgType::Quic {
            return self
                .enhanced_inbound
                .inbound(net, msg_type, src_ip, net_packet)
                .await;
        }

        let ctx = PacketContext {
            msg_type,
            src_ip,
            dest_ip,
            max_ttl: net_packet.max_ttl(),
            ttl: net_packet.ttl(),
        };
        let net_packet = self.packet_compression.decompress(net_packet)?;
        self.process_decompressed_packet(net, route_key, tunnel, net_packet, &ctx)
            .await
    }

    async fn process_decompressed_packet(
        &self,
        net: &crate::context::NetworkAddr,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
        net_packet: NetPacket<TransmissionBytes>,
        ctx: &PacketContext,
    ) -> anyhow::Result<()> {
        match ctx.msg_type {
            MsgType::Turn | MsgType::Broadcast | MsgType::ExcludeBroadcast => {
                self.enhanced_inbound
                    .inbound(net, ctx.msg_type, ctx.src_ip, net_packet)
                    .await?;
            }
            MsgType::Ping => {
                let metric = ctx.max_ttl - ctx.ttl;
                self.route_table.add_route(
                    ctx.src_ip,
                    Route::from_default_rt(route_key, metric),
                    true,
                );
                let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH + 8,
                    self.packet_crypto.encrypt_reserve(),
                ))?;
                packet.set_msg_type(MsgType::Pong);
                packet.set_ttl(metric);
                packet.set_src_id(ctx.dest_ip.into());
                packet.set_dest_id(ctx.src_ip.into());
                packet.set_payload(net_packet.payload())?;
                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel.send(packet.into_bytes().into_buffer()).await?;
            }
            MsgType::Pong => {
                if net_packet.payload().len() >= 8 {
                    let metric = ctx.max_ttl - ctx.ttl;
                    let time = i64::from_be_bytes(net_packet.payload()[..8].try_into()?);
                    let now = crate::utils::time::now_ts_ms();
                    if now >= time {
                        // 记录接收并获取丢包率
                        let loss_rate_f64 = self
                            .packet_loss_stats
                            .record_received(ctx.src_ip, route_key);
                        // 转换为万分率
                        let loss_rate = (loss_rate_f64 * 10000.0).round() as u16;

                        self.route_table.add_route(
                            ctx.src_ip,
                            Route::from_with_loss(route_key, metric, (now - time) as _, loss_rate),
                            false,
                        );
                    }
                }
            }
            MsgType::DestinationUnreachable => {
                if ctx.dest_ip != net.ip {
                    return Ok(());
                }
                let Some(next_hop) = self.route_table.route_owner(&route_key) else {
                    return Ok(());
                };
                if next_hop != ctx.src_ip {
                    return Ok(());
                }
                let Some(destination) = parse_destination_unreachable(net, net_packet.payload())
                else {
                    return Ok(());
                };
                self.route_table.suppress_path(destination, next_hop);
                log::debug!(
                    "temporarily suppress route to {destination} through direct peer {next_hop}"
                );
            }
            MsgType::PunchStart1 => {
                if !allow_punch(&self.turn, &ctx.src_ip) {
                    return Ok(());
                }
                let peer_info = PunchInfo::from_slice(net_packet.payload())?;
                if self
                    .peer_map
                    .update_nat_info(ctx.src_ip, peer_info.nat_info.clone())
                {
                    self.punch_backoff.cap(ctx.src_ip);
                }
                let Some(mut self_info) = (self.punch_info_getter)(ctx.src_ip) else {
                    return Ok(());
                };
                if let Some(effective) = self.puncher.punch(ctx.src_ip, peer_info)? {
                    self_info.punch_model = effective;
                    let payload = self_info.encode();
                    let mut response = NetPacket::new(TransmissionBytes::zeroed_size(
                        HEAD_LENGTH + payload.len(),
                        self.packet_crypto.encrypt_reserve(),
                    ))?;
                    response.set_msg_type(MsgType::PunchStart2);
                    response.set_ttl(GOSSIP_TTL);
                    response.set_src_id(net.ip.into());
                    response.set_dest_id(ctx.src_ip.into());
                    response.set_payload(&payload)?;
                    self.basic_outbound
                        .send_encrypted_packet(*net, ctx.src_ip, response)
                        .await?;
                }
            }
            MsgType::PunchStart2 => {
                if !allow_punch(&self.turn, &ctx.src_ip) {
                    return Ok(());
                }
                let peer_info = PunchInfo::from_slice(net_packet.payload())?;
                if self
                    .peer_map
                    .update_nat_info(ctx.src_ip, peer_info.nat_info.clone())
                {
                    self.punch_backoff.cap(ctx.src_ip);
                }
                self.puncher.punch_uncheck(ctx.src_ip, peer_info)?;
            }
            MsgType::PunchReq => {
                if !allow_punch(&self.turn, &ctx.src_ip) {
                    log::debug!("ignore configured turn target PunchReq from {}", ctx.src_ip);
                    return Ok(());
                }
                if !valid_punch_source(net, ctx.src_ip) {
                    log::debug!(
                        "ignore invalid PunchReq from {} via {route_key:?}",
                        ctx.src_ip
                    );
                    return Ok(());
                }
                if let IpAddr::V4(ip) = route_key.peer_addr().ip()
                    && self.network_contains(&ip)
                {
                    log::info!("===========loop PunchReq {route_key:?} {:?}", ctx.src_ip);
                    return Ok(());
                }
                log::info!(
                    "PunchReq 打洞成功 {}->{},route={route_key:?}",
                    ctx.src_ip,
                    ctx.dest_ip
                );
                let kind =
                    match validate_punch_payload(net_packet.payload(), &self.identity.network_code)
                    {
                        Ok(kind) => kind,
                        Err(error) => {
                            log::warn!("reject PunchReq from {}: {error}", ctx.src_ip);
                            return Ok(());
                        }
                    };
                let first = self.route_table.add_owner_route(ctx.src_ip, route_key);
                if first {
                    self.punch_backoff.reset(ctx.src_ip);
                }
                let mut packet = build_punch_response(
                    net.ip,
                    ctx.src_ip,
                    self.packet_crypto.encrypt_reserve(),
                    kind,
                    &self.identity.network_code,
                )?;

                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel.send(packet.into_bytes().into_buffer()).await?;
            }
            MsgType::PunchRes => {
                if !allow_punch(&self.turn, &ctx.src_ip) {
                    log::debug!("ignore configured turn target PunchRes from {}", ctx.src_ip);
                    return Ok(());
                }
                if !valid_punch_source(net, ctx.src_ip) {
                    log::debug!(
                        "ignore invalid PunchRes from {} via {route_key:?}",
                        ctx.src_ip
                    );
                    return Ok(());
                }
                if let IpAddr::V4(ip) = route_key.peer_addr().ip()
                    && self.network_contains(&ip)
                {
                    log::info!("===========loop PunchRes {route_key:?} {:?}", ctx.src_ip);
                    return Ok(());
                }
                log::info!(
                    "PunchRes 打洞成功 {}->{},route={route_key:?}",
                    ctx.src_ip,
                    ctx.dest_ip
                );
                if let Err(error) =
                    validate_punch_payload(net_packet.payload(), &self.identity.network_code)
                {
                    log::warn!("reject PunchRes from {}: {error}", ctx.src_ip);
                    return Ok(());
                }
                let first = self.route_table.add_owner_route(ctx.src_ip, route_key);
                if first {
                    self.punch_backoff.reset(ctx.src_ip);
                }
            }
            MsgType::DirectConnectReq => {
                if !valid_punch_source(net, ctx.src_ip) {
                    log::debug!(
                        "ignore invalid DirectConnectReq from {} via {route_key:?}",
                        ctx.src_ip
                    );
                    return Ok(());
                }
                log::info!(
                    "直接连接成功 {}->{},route={route_key:?}",
                    ctx.src_ip,
                    net.ip
                );
                let identity =
                    match direct_identity(net, ctx.src_ip, net_packet.payload(), &self.identity) {
                        Ok(identity) => identity,
                        Err(error) => {
                            log::warn!(
                                "reject DirectConnectReq identity from {}: {error}",
                                ctx.src_ip
                            );
                            return Ok(());
                        }
                    };
                let (first, identity_changed) = if let Some((node, _)) = identity.as_ref() {
                    let first = self.route_table.add_owner_route(node.ip, route_key);
                    let changed = self.node_info_map.upsert(node.clone());
                    (first, changed)
                } else {
                    (
                        self.route_table.add_owner_route(ctx.src_ip, route_key),
                        false,
                    )
                };
                if identity_changed {
                    self.sync_gossip_subnets();
                }
                if first {
                    self.punch_backoff.reset(ctx.src_ip);
                }
                let mut packet = build_direct_handshake_response(
                    MsgType::DirectConnectRes,
                    net.ip,
                    ctx.src_ip,
                    self.packet_crypto.encrypt_reserve(),
                    identity
                        .as_ref()
                        .map(|(_, request_id)| (&self.identity, *request_id)),
                )?;
                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel.send(packet.into_bytes().into_buffer()).await?;
            }
            MsgType::DirectConnectRes => {
                if !valid_punch_source(net, ctx.src_ip) {
                    log::debug!(
                        "ignore invalid DirectConnectRes from {} via {route_key:?}",
                        ctx.src_ip
                    );
                    return Ok(());
                }
                log::info!(
                    "直接连接响应 {}->{},route={route_key:?}",
                    ctx.src_ip,
                    ctx.dest_ip
                );
                let identity =
                    match direct_identity(net, ctx.src_ip, net_packet.payload(), &self.identity) {
                        Ok(identity) => identity,
                        Err(error) => {
                            log::warn!(
                                "reject DirectConnectRes identity from {}: {error}",
                                ctx.src_ip
                            );
                            return Ok(());
                        }
                    };
                let (first, identity_changed) = if let Some((node, _)) = identity {
                    let first = self.route_table.add_owner_route(node.ip, route_key);
                    let changed = self.node_info_map.upsert(node);
                    (first, changed)
                } else {
                    (
                        self.route_table.add_owner_route(ctx.src_ip, route_key),
                        false,
                    )
                };
                if identity_changed {
                    self.sync_gossip_subnets();
                }
                if first {
                    self.punch_backoff.reset(ctx.src_ip);
                }
            }
            MsgType::PingTurn => {}
            MsgType::PongTurn => {}
            _ => {}
        }
        Ok(())
    }

    async fn send_destination_unreachable(
        &self,
        net: NetworkAddr,
        destination: Ipv4Addr,
        route_key: RouteKey,
        tunnel: &TunnelWriteHalf,
    ) -> anyhow::Result<()> {
        let Some(upstream_ip) = self.route_table.route_owner(&route_key) else {
            return Ok(());
        };
        let mut response = build_destination_unreachable(
            net.ip,
            upstream_ip,
            destination,
            self.packet_crypto.encrypt_reserve(),
        )?;
        self.packet_crypto.encrypt_in_place(&mut response)?;
        tunnel
            .send(response.into_buffer().into_bytes().freeze())
            .await?;
        Ok(())
    }

    pub fn tunnel_disconnect(&self, route_key: RouteKey) {
        cleanup_tunnel_routes(
            &self.route_table,
            &self.node_info_map,
            &self.packet_loss_stats,
            &route_key,
        );
        self.sync_gossip_subnets();
    }

    fn sync_gossip_subnets(&self) {
        if !self.auto_sync_subnet {
            return;
        }
        let routes = self
            .node_info_map
            .list()
            .into_iter()
            .flat_map(|node| {
                node.advertised_subnets
                    .into_iter()
                    .map(move |net| crate::nat::NetInput {
                        net,
                        target_ip: node.ip,
                    })
            })
            .collect();
        self.network_route.subnet_route.set_gossip_routes(routes);
    }
}

fn cleanup_tunnel_routes(
    route_table: &RouteTable,
    node_info_map: &NodeInfoMap,
    packet_loss_stats: &PacketLossStats,
    route_key: &RouteKey,
) {
    let removed = route_table.remove_route_key(route_key);
    packet_loss_stats.remove_batch(&removed);
    for (ip, _) in removed {
        if !route_table.exists(&ip) {
            node_info_map.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustp2p_core::route_table::Protocol;

    fn network() -> NetworkAddr {
        NetworkAddr {
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
            ip: Ipv4Addr::new(10, 26, 0, 2),
            prefix_len: 24,
        }
    }

    fn identity(network_code: &str) -> NodeIdentityTemplate {
        NodeIdentityTemplate {
            name: "node".to_string(),
            version: "2".to_string(),
            network_code: network_code.to_string(),
            advertised_subnets: Vec::new(),
        }
    }

    #[test]
    fn direct_identity_accepts_full_identity_and_legacy_payload() {
        let net = network();
        let peer: Ipv4Addr = "10.26.0.3".parse().unwrap();
        let local = identity("mesh");
        let payload = PeerHandshake {
            identity: local.with_ip(peer),
            request_id: 7,
        }
        .encode();
        let (node, request_id) = direct_identity(&net, peer, &payload, &local)
            .unwrap()
            .unwrap();
        assert_eq!(node.ip, peer);
        assert_eq!(request_id, 7);
        assert!(
            direct_identity(&net, peer, &[0; 8], &local)
                .unwrap()
                .is_none()
        );

        let wrong = PeerHandshake {
            identity: identity("other-mesh").with_ip(peer),
            request_id: 8,
        }
        .encode();
        assert!(direct_identity(&net, peer, &wrong, &local).is_err());
    }

    #[test]
    fn punch_source_must_be_another_member_of_the_virtual_network() {
        let net = network();
        assert!(valid_punch_source(&net, Ipv4Addr::new(10, 26, 0, 3)));
        assert!(!valid_punch_source(&net, Ipv4Addr::UNSPECIFIED));
        assert!(!valid_punch_source(&net, net.ip));
        assert!(!valid_punch_source(&net, Ipv4Addr::new(10, 27, 0, 3)));
    }

    #[test]
    fn direct_handshake_response_identifies_the_local_virtual_ip() {
        let local = Ipv4Addr::new(10, 26, 0, 2);
        let peer = Ipv4Addr::new(10, 26, 0, 3);
        let packet =
            build_direct_handshake_response(MsgType::DirectConnectRes, local, peer, 0, None)
                .unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::DirectConnectRes);
        assert_eq!(Ipv4Addr::from(packet.src_id()), local);
        assert_eq!(Ipv4Addr::from(packet.dest_id()), peer);
        assert_eq!(packet.payload().len(), 8);
    }

    #[test]
    fn punch_payload_accepts_matching_hash_and_legacy_timestamp_only() {
        let hash = network_code_hash("mesh");
        assert_eq!(
            validate_punch_payload(&hash, "mesh").unwrap(),
            PunchPayloadKind::Current
        );
        assert_eq!(
            validate_punch_payload(&[0; 8], "mesh").unwrap(),
            PunchPayloadKind::Legacy
        );
        assert!(validate_punch_payload(&hash, "other").is_err());
        assert!(validate_punch_payload(&[0; 7], "mesh").is_err());
        assert!(validate_punch_payload(&[0; 17], "mesh").is_err());
    }

    #[test]
    fn punch_response_preserves_legacy_format_or_uses_only_hash() {
        let local = Ipv4Addr::new(10, 26, 0, 2);
        let peer = Ipv4Addr::new(10, 26, 0, 3);
        let current =
            build_punch_response(local, peer, 0, PunchPayloadKind::Current, "mesh").unwrap();
        assert_eq!(current.msg_type().unwrap(), MsgType::PunchRes);
        assert_eq!(current.payload(), network_code_hash("mesh"));
        assert_eq!(current.payload().len(), NETWORK_CODE_HASH_LEN);

        let legacy =
            build_punch_response(local, peer, 0, PunchPayloadKind::Legacy, "mesh").unwrap();
        assert_eq!(legacy.payload().len(), 8);
    }

    #[test]
    fn direct_announcement_filters_and_deduplicates_relay_hints() {
        let net = network();
        let source = Ipv4Addr::new(10, 26, 0, 3);
        let target = Ipv4Addr::new(10, 26, 0, 4);
        let advertised = [
            target,
            target,
            source,
            net.ip,
            net.broadcast,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(10, 27, 0, 4),
        ];

        assert_eq!(
            gossip_relay_targets(&net, source, 1, &advertised),
            vec![target]
        );
        assert!(gossip_relay_targets(&net, source, 2, &advertised).is_empty());
    }

    #[test]
    fn direct_announcement_bootstraps_exactly_two_hop_route() {
        let net = network();
        let source = Ipv4Addr::new(10, 26, 0, 3);
        let target = Ipv4Addr::new(10, 26, 0, 4);
        let route_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:1998".parse().unwrap(),
            "127.0.0.1:2998".parse().unwrap(),
        );
        let direct_table = RouteTable::new();
        learn_gossip_relay_routes(&direct_table, &net, source, 1, route_key, &[target]);

        let route = direct_table.get_route_by_id(&target).unwrap();
        assert_eq!(route.route_key(), route_key);
        assert_eq!(route.metric(), 2);

        let multihop_table = RouteTable::new();
        learn_gossip_relay_routes(&multihop_table, &net, source, 2, route_key, &[target]);
        assert!(!multihop_table.exists(&target));
    }

    #[test]
    fn tunnel_cleanup_removes_all_packet_loss_stats_for_the_route_key() {
        let route_table = RouteTable::new();
        let node_info_map = NodeInfoMap::default();
        let packet_loss_stats = PacketLossStats::default();
        let direct = Ipv4Addr::new(10, 26, 0, 3);
        let relayed = Ipv4Addr::new(10, 26, 0, 4);
        let route_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );

        route_table.add_owner_route(direct, route_key);
        route_table.add_gossip_relay_route(relayed, Route::from_default_rt(route_key, 2));
        node_info_map.upsert(NodeInfo {
            ip: direct,
            name: "direct".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        });
        node_info_map.upsert(NodeInfo {
            ip: relayed,
            name: "relayed".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        });
        packet_loss_stats.record_sent(direct, route_key);
        packet_loss_stats.record_sent(relayed, route_key);

        cleanup_tunnel_routes(&route_table, &node_info_map, &packet_loss_stats, &route_key);

        assert!(!route_table.exists(&direct));
        assert!(!route_table.exists(&relayed));
        assert!(node_info_map.list().is_empty());
        assert!(
            packet_loss_stats
                .get_loss_info(&direct, &route_key)
                .is_none()
        );
        assert!(
            packet_loss_stats
                .get_loss_info(&relayed, &route_key)
                .is_none()
        );
    }

    #[test]
    fn tunnel_cleanup_keeps_identity_until_the_last_peer_route_is_removed() {
        let route_table = RouteTable::new();
        let node_info_map = NodeInfoMap::default();
        let packet_loss_stats = PacketLossStats::default();
        let peer = Ipv4Addr::new(10, 26, 0, 3);
        let first_key = RouteKey::new(
            Protocol::TCP,
            "127.0.0.1:2001".parse().unwrap(),
            "127.0.0.1:3001".parse().unwrap(),
        );
        let second_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2002".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
        );
        let node = NodeInfo {
            ip: peer,
            name: "peer".to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        };

        route_table.add_owner_route(peer, first_key);
        route_table.add_owner_route(peer, second_key);
        node_info_map.upsert(node.clone());

        cleanup_tunnel_routes(&route_table, &node_info_map, &packet_loss_stats, &first_key);
        assert_eq!(node_info_map.get(&peer), Some(node));

        cleanup_tunnel_routes(
            &route_table,
            &node_info_map,
            &packet_loss_stats,
            &second_key,
        );
        assert!(node_info_map.get(&peer).is_none());
    }

    #[test]
    fn destination_unreachable_packet_has_fixed_payload_and_one_hop_ttl() {
        let local = Ipv4Addr::new(10, 26, 0, 2);
        let upstream = Ipv4Addr::new(10, 26, 0, 1);
        let destination = Ipv4Addr::new(10, 26, 0, 9);
        let packet = build_destination_unreachable(local, upstream, destination, 0).unwrap();

        assert_eq!(packet.msg_type().unwrap(), MsgType::DestinationUnreachable);
        assert_eq!(packet.ttl(), 1);
        assert_eq!(Ipv4Addr::from(packet.src_id()), local);
        assert_eq!(Ipv4Addr::from(packet.dest_id()), upstream);
        assert_eq!(packet.payload(), destination.octets());
    }

    #[test]
    fn destination_unreachable_payload_rejects_invalid_targets_and_sizes() {
        let net = network();
        let target = Ipv4Addr::new(10, 26, 0, 9);
        assert_eq!(
            parse_destination_unreachable(&net, &target.octets()),
            Some(target)
        );
        assert!(parse_destination_unreachable(&net, &[10, 26, 0]).is_none());
        assert!(parse_destination_unreachable(&net, &net.ip.octets()).is_none());
        assert!(parse_destination_unreachable(&net, &[192, 168, 1, 1]).is_none());
        assert!(parse_destination_unreachable(&net, &[255, 255, 255, 255]).is_none());
    }
}
