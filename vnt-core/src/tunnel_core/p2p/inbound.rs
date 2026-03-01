use crate::compression::PacketCompression;
use crate::context::{NetworkRoute, PacketLossStats};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::fec::FecDecoder;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
use anyhow::bail;
use rust_p2p_core::route::RouteKey;
use rust_p2p_core::tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr};

struct PacketContext {
    msg_type: MsgType,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    max_ttl: u8,
    ttl: u8,
}

pub(crate) struct P2pInboundConfig {
    pub network_route: NetworkRoute,
    pub route_table: RouteTable,
    pub packet_loss_stats: PacketLossStats,
    pub packet_crypto: PacketCrypto,
    pub packet_compression: PacketCompression,
    pub enhanced_inbound: EnhancedInbound,
    pub fec_decoder: FecDecoder,
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
        }
    }
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        self.network_route.network_contains(ip)
    }
    pub async fn next_handle(
        &self,
        buf: TransmissionBytes,
        route_key: RouteKey,
        p2p_socket_manager: &P2pOutbound,
        tunnel: &mut Tunnel,
    ) {
        if let Err(e) = self
            .next_handle_impl(buf, route_key, p2p_socket_manager, tunnel)
            .await
        {
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
        p2p_socket_manager: &P2pOutbound,
        tunnel: &mut Tunnel,
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
        if net.ip != dest_ip
            && !dest_ip.is_broadcast()
            && !dest_ip.is_unspecified()
            && dest_ip != net.broadcast
        {
            // 帮忙转发数据包
            if ttl >= 1 {
                if let Some(route) = p2p_socket_manager.get_route_by_id(&dest_ip) {
                    p2p_socket_manager
                        .send_raw_to(net_packet.into_bytes(), &route.route_key())
                        .await?;
                } else {
                    log::debug!("未找到到 {} 的路由，无法转发", dest_ip);
                }
            }
            return Ok(());
        }

        if msg_type == MsgType::Quic {
            if net_packet.is_fec() {
                let packets = self.fec_decoder.receive(net_packet)?;
                if let Some(packets) = packets {
                    for pkt in packets {
                        self.enhanced_inbound
                            .inbound(&net, msg_type, src_ip, pkt)
                            .await?;
                    }
                }
                return Ok(());
            }
            self.enhanced_inbound
                .inbound(&net, msg_type, src_ip, net_packet)
                .await?;
            return Ok(());
        }

        // 解密
        self.packet_crypto.decrypt_in_place(&mut net_packet)?;

        let ctx = PacketContext {
            msg_type,
            src_ip,
            dest_ip,
            max_ttl,
            ttl,
        };

        // FEC 解码（始终尝试解码，如果有 FEC 标志）
        if net_packet.is_fec() {
            let packets = self.fec_decoder.receive(net_packet)?;
            if let Some(packets) = packets {
                for pkt in packets {
                    let pkt = self.packet_compression.decompress(pkt)?;
                    self.process_decompressed_packet(&net, route_key, tunnel, pkt, &ctx)
                        .await?;
                }
            }
            return Ok(());
        }

        // 解压缩
        let net_packet = self.packet_compression.decompress(net_packet)?;
        self.process_decompressed_packet(&net, route_key, tunnel, net_packet, &ctx)
            .await
    }

    async fn process_decompressed_packet(
        &self,
        net: &crate::context::NetworkAddr,
        route_key: RouteKey,
        tunnel: &mut Tunnel,
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
                self.route_table
                    .add_route_if_absent(ctx.src_ip, Route::from_default_rt(route_key, metric));
                let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH + 8,
                    self.packet_crypto.encrypt_reserve(),
                ))?;
                packet.set_msg_type(MsgType::Pong);
                packet.set_ttl(1);
                packet.set_src_id(ctx.dest_ip.into());
                packet.set_dest_id(ctx.src_ip.into());
                packet.set_payload(net_packet.payload())?;
                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel
                    .send_to(packet.into_bytes().into_buffer(), route_key.addr())
                    .await?;
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
                        );
                    }
                }
            }
            MsgType::PunchStart1 => {}
            MsgType::PunchStart2 => {}
            MsgType::PunchReq => {
                if let IpAddr::V4(ip) = route_key.addr().ip()
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
                let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH + 8,
                    self.packet_crypto.encrypt_reserve(),
                ))?;
                packet.set_msg_type(MsgType::PunchRes);
                packet.set_ttl(1);
                packet.set_src_id(ctx.dest_ip.into());
                packet.set_dest_id(ctx.src_ip.into());
                packet.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())?;

                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel
                    .send_to(packet.into_bytes().into_buffer(), route_key.addr())
                    .await?;
            }
            MsgType::PunchRes => {
                if let IpAddr::V4(ip) = route_key.addr().ip()
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
            MsgType::PingTurn => {}
            MsgType::PongTurn => {}
            MsgType::RelayProbe => {
                let metric = ctx.max_ttl - ctx.ttl;
                self.route_table
                    .add_route_if_absent(ctx.src_ip, Route::from_default_rt(route_key, metric));
                let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH,
                    self.packet_crypto.encrypt_reserve(),
                ))?;
                packet.set_msg_type(MsgType::RelayProbeReply);
                packet.set_ttl(1);
                packet.set_src_id(ctx.dest_ip.into());
                packet.set_dest_id(ctx.src_ip.into());
                self.packet_crypto.encrypt_in_place(&mut packet)?;
                tunnel
                    .send_to(packet.into_bytes().into_buffer(), route_key.addr())
                    .await?;
            }
            MsgType::RelayProbeReply => {
                let metric = ctx.max_ttl - ctx.ttl;
                self.route_table.add_route(
                    ctx.src_ip,
                    Route::from_default_rt(route_key, metric),
                );
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn tcp_disconnect(&self, route_key: RouteKey) {
        if let Some(ip) = self.route_table.get_id_by_route_key(&route_key) {
            self.route_table.remove_route(&ip, &route_key);
        }
    }
}
