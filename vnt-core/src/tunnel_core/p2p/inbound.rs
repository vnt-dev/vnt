use crate::compression::PacketCompression;
use crate::context::config::{TurnRule, allow_punch};
use crate::context::{NetworkAddr, NetworkRoute, PacketLossStats};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::fec::FecDecoder;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
use anyhow::bail;
use rustp2p_core::endpoint::TunnelWriteHalf;
use rustp2p_core::route_table::RouteKey;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

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

fn valid_relay_probe(net: &NetworkAddr, ctx: &PacketContext) -> bool {
    valid_punch_source(net, ctx.src_ip) && ctx.dest_ip == net.ip && ctx.max_ttl == 2 && ctx.ttl == 0
}

fn build_handshake_response(
    msg_type: MsgType,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    encrypt_reserve: usize,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + 8,
        encrypt_reserve,
    ))?;
    packet.set_msg_type(msg_type);
    packet.set_ttl(1);
    packet.set_src_id(local_ip.into());
    packet.set_dest_id(peer_ip.into());
    packet.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())?;
    Ok(packet)
}

pub(crate) struct P2pInboundConfig {
    pub network_route: NetworkRoute,
    pub route_table: RouteTable,
    pub packet_loss_stats: PacketLossStats,
    pub packet_crypto: PacketCrypto,
    pub packet_compression: PacketCompression,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
    pub turn: Arc<Vec<TurnRule>>,
    pub basic_outbound: BasicOutbound,
}

#[derive(Clone)]
pub(crate) struct P2pInboundHandler {
    network_route: NetworkRoute,
    route_table: RouteTable,
    packet_loss_stats: PacketLossStats,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
    turn: Arc<Vec<TurnRule>>,
    basic_outbound: BasicOutbound,
}

impl P2pInboundHandler {
    pub fn new(config: P2pInboundConfig) -> Self {
        Self {
            network_route: config.network_route,
            route_table: config.route_table,
            packet_loss_stats: config.packet_loss_stats,
            packet_crypto: config.packet_crypto,
            packet_compression: config.packet_compression,
            enhanced_inbound: config.enhanced_inbound,
            fec_decoder: config.fec_decoder,
            turn: config.turn,
            basic_outbound: config.basic_outbound,
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
        let _ = net_packet.msg_type()?;
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
        if net.ip != dest_ip
            && !dest_ip.is_broadcast()
            && !dest_ip.is_unspecified()
            && dest_ip != net.broadcast
        {
            // 帮忙转发数据包
            if ttl >= 1 {
                self.basic_outbound
                    .send_raw(net, dest_ip, net_packet)
                    .await?;
            }
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
            MsgType::PunchStart1 => {}
            MsgType::PunchStart2 => {}
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
                self.route_table.add_owner_route(ctx.src_ip, route_key);
                let mut packet = build_handshake_response(
                    MsgType::PunchRes,
                    net.ip,
                    ctx.src_ip,
                    self.packet_crypto.encrypt_reserve(),
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
                self.route_table.add_owner_route(ctx.src_ip, route_key);
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
                self.route_table.add_owner_route(ctx.src_ip, route_key);
                let mut packet = build_handshake_response(
                    MsgType::DirectConnectRes,
                    net.ip,
                    ctx.src_ip,
                    self.packet_crypto.encrypt_reserve(),
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
                self.route_table.add_owner_route(ctx.src_ip, route_key);
            }
            MsgType::PingTurn => {}
            MsgType::PongTurn => {}
            MsgType::RelayProbe => {
                if !valid_relay_probe(net, ctx) {
                    log::debug!(
                        "ignore invalid RelayProbe from {} to {} with ttl {}/{}",
                        ctx.src_ip,
                        ctx.dest_ip,
                        ctx.ttl,
                        ctx.max_ttl
                    );
                    return Ok(());
                }
                let metric = ctx.max_ttl - ctx.ttl;
                self.route_table
                    .add_relay_route(ctx.src_ip, Route::from_default_rt(route_key, metric));
                let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH,
                    self.packet_crypto.encrypt_reserve(),
                ))?;
                packet.set_msg_type(MsgType::RelayProbeReply);
                // 与 RelayProbe 对称：允许中继一次，到达发起方时 curr_ttl 为 0，metric = 2
                packet.set_ttl(2);
                packet.set_src_id(ctx.dest_ip.into());
                packet.set_dest_id(ctx.src_ip.into());
                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel.send(packet.into_bytes().into_buffer()).await?;
            }
            MsgType::RelayProbeReply => {
                if !valid_relay_probe(net, ctx) {
                    log::debug!(
                        "ignore invalid RelayProbeReply from {} to {} with ttl {}/{}",
                        ctx.src_ip,
                        ctx.dest_ip,
                        ctx.ttl,
                        ctx.max_ttl
                    );
                    return Ok(());
                }
                let metric = ctx.max_ttl - ctx.ttl;
                self.route_table
                    .add_relay_route(ctx.src_ip, Route::from_default_rt(route_key, metric));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn tunnel_disconnect(&self, route_key: RouteKey) {
        cleanup_tunnel_routes(&self.route_table, &self.packet_loss_stats, &route_key);
    }
}

fn cleanup_tunnel_routes(
    route_table: &RouteTable,
    packet_loss_stats: &PacketLossStats,
    route_key: &RouteKey,
) {
    let removed = route_table.remove_route_key(route_key);
    packet_loss_stats.remove_batch(&removed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustp2p_core::route_table::Protocol;

    fn network() -> NetworkAddr {
        NetworkAddr {
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
            ip: Ipv4Addr::new(10, 26, 0, 2),
            prefix_len: 24,
        }
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
    fn handshake_responses_identify_the_local_virtual_ip() {
        let local = Ipv4Addr::new(10, 26, 0, 2);
        let peer = Ipv4Addr::new(10, 26, 0, 3);
        for msg_type in [MsgType::PunchRes, MsgType::DirectConnectRes] {
            let packet = build_handshake_response(msg_type, local, peer, 0).unwrap();
            assert_eq!(packet.msg_type().unwrap(), msg_type);
            assert_eq!(Ipv4Addr::from(packet.src_id()), local);
            assert_eq!(Ipv4Addr::from(packet.dest_id()), peer);
            assert_eq!(packet.payload().len(), 8);
        }
    }

    #[test]
    fn relay_probe_requires_valid_virtual_endpoints_and_exactly_two_hops() {
        let net = network();
        let valid = PacketContext {
            msg_type: MsgType::RelayProbe,
            src_ip: Ipv4Addr::new(10, 26, 0, 3),
            dest_ip: net.ip,
            max_ttl: 2,
            ttl: 0,
        };
        assert!(valid_relay_probe(&net, &valid));

        for invalid in [
            PacketContext {
                src_ip: Ipv4Addr::UNSPECIFIED,
                ..valid
            },
            PacketContext {
                src_ip: net.ip,
                ..valid
            },
            PacketContext {
                src_ip: Ipv4Addr::new(10, 27, 0, 3),
                ..valid
            },
            PacketContext {
                dest_ip: Ipv4Addr::new(10, 26, 0, 4),
                ..valid
            },
            PacketContext {
                max_ttl: 1,
                ttl: 0,
                ..valid
            },
            PacketContext { ttl: 1, ..valid },
        ] {
            assert!(!valid_relay_probe(&net, &invalid));
        }
    }

    #[test]
    fn tunnel_cleanup_removes_all_packet_loss_stats_for_the_route_key() {
        let route_table = RouteTable::new();
        let packet_loss_stats = PacketLossStats::default();
        let direct = Ipv4Addr::new(10, 26, 0, 3);
        let relayed = Ipv4Addr::new(10, 26, 0, 4);
        let route_key = RouteKey::new(
            Protocol::UDP,
            "127.0.0.1:2000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        );

        route_table.add_owner_route(direct, route_key);
        route_table.add_relay_route(relayed, Route::from_default_rt(route_key, 2));
        packet_loss_stats.record_sent(direct, route_key);
        packet_loss_stats.record_sent(relayed, route_key);

        cleanup_tunnel_routes(&route_table, &packet_loss_stats, &route_key);

        assert!(!route_table.exists(&direct));
        assert!(!route_table.exists(&relayed));
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
}
