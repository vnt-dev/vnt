use crate::compression::PacketCompression;
use crate::context::nat::{MyNatInfo, PunchBackoff};
use crate::context::{NetworkAddr, NetworkRoute, PeerInfoMap, ServerInfoCollection};
use crate::crypto::PacketCrypto;
use crate::enhanced_tunnel::inbound::EnhancedInbound;
use crate::fec::FecDecoder;
use crate::protocol::client_message::PunchInfo;
use crate::protocol::control_message::ClientSimpleInfoList;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::rpc_message::RpcMessageResponse;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::transport::punch::NatPuncher;
use crate::tunnel_core::server::rpc::RpcNotifier;
use crate::tunnel_core::server::transport::TransportClient;
use anyhow::bail;
use pnet_packet::Packet;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ipv4::Ipv4Packet;
use prost::Message;
use rust_p2p_core::nat::NatInfo;
use std::net::Ipv4Addr;

pub(crate) struct ServerTurnInboundHandler {
    server_id: u32,
    network_addr: Option<NetworkAddr>,
    network_route: NetworkRoute,
    server_info: ServerInfoCollection,
    nat_info: MyNatInfo,
    peer_map: PeerInfoMap,
    punch_backoff: PunchBackoff,
    puncher: NatPuncher,
    packet_crypto: PacketCrypto,
    packet_compression: PacketCompression,
    enhanced_inbound: EnhancedInbound,
    fec_decoder: FecDecoder,
}
impl ServerTurnInboundHandler {
    pub fn new(
        server_id: u32,
        network_addr: NetworkAddr,
        config: Box<super::connection_manager::InboundHandlerConfig>,
    ) -> Self {
        let config = *config;
        Self {
            server_id,
            network_addr: Some(network_addr),
            network_route: config.network_route,
            server_info: config.server_info,
            nat_info: config.nat_info,
            peer_map: config.peer_map,
            punch_backoff: config.punch_backoff,
            puncher: config.puncher,
            packet_crypto: config.packet_crypto,
            packet_compression: config.packet_compression,
            enhanced_inbound: config.enhanced_inbound,
            fec_decoder: config.fec_decoder,
        }
    }
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        self.network_route.network_contains(ip)
    }
    fn filter_ip(&self, mut info: NatInfo) -> NatInfo {
        if self.network_contains(&info.local_ipv4) {
            info.local_ipv4 = Ipv4Addr::UNSPECIFIED;
        }
        info.local_ipv4s.retain(|ip| !self.network_contains(ip));
        info
    }
    fn get_punch_info(&self) -> Option<PunchInfo> {
        self.nat_info.get().map(|info| PunchInfo {
            nat_info: self.filter_ip(info),
        })
    }
    fn update_peer_nat_info(&self, ip: Ipv4Addr, nat_info: NatInfo) {
        self.peer_map.update_nat_info(ip, nat_info);
    }

    pub async fn handle_server_data(
        &self,
        transport_client: &mut TransportClient,
        network_addr: NetworkAddr,
        data: TransmissionBytes,
        rpc_notifier: &RpcNotifier,
        now: i64,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(data)?;
        let src = net_packet.src_id().into();
        let msg_type = net_packet.msg_type()?;
        let mut net_packet = self.packet_compression.decompress(net_packet)?;

        match msg_type {
            MsgType::Turn => {
                // 只允许icmp EchoReply
                let Some(ipv4) = Ipv4Packet::new(net_packet.payload()) else {
                    return Ok(());
                };
                if ipv4.get_version() != 4 {
                    return Ok(());
                }
                if ipv4.get_next_level_protocol() != pnet_packet::ip::IpNextHeaderProtocols::Icmp {
                    return Ok(());
                }
                let Some(icmp) = IcmpPacket::new(ipv4.payload()) else {
                    return Ok(());
                };
                if icmp.get_icmp_type() != IcmpTypes::EchoReply {
                    return Ok(());
                }
                self.enhanced_inbound
                    .inbound(&network_addr, msg_type, src, net_packet)
                    .await?;
            }
            MsgType::Ping => {
                net_packet.set_ttl(2);
                net_packet.set_msg_type(MsgType::Pong);
                net_packet.set_src_id(network_addr.ip.into());
                net_packet.set_dest_id(src.into());
                transport_client.send_turn(net_packet).await?;
            }
            MsgType::PongTurn => {
                // 服务端ping 回复，记录延迟
                if net_packet.payload().len() == 8 + 8 {
                    let time = i64::from_be_bytes(net_packet.payload()[..8].try_into()?);
                    // let data_version = u64::from_be_bytes(net_packet.payload()[8..].try_into()?);
                    if now >= time {
                        self.server_info
                            .set_server_rtt(self.server_id, (now - time) as u32);
                    }
                }
            }
            MsgType::PushClientIps => {
                let list = ClientSimpleInfoList::from_slice(net_packet.payload())?;
                self.server_info.update_client_simple_list(
                    self.server_id,
                    network_addr.ip,
                    list,
                    now,
                );
            }
            MsgType::RpcRes => {
                // 设置rpc响应
                let response = RpcMessageResponse::decode(net_packet.payload())?;
                rpc_notifier.notify_response(response);
            }
            _ => {}
        }
        Ok(())
    }
    pub async fn handle_client_data(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let mut net_packet = NetPacket::new(data)?;
        let msg_type = net_packet.msg_type()?;
        let src = Ipv4Addr::from(net_packet.src_id());
        let dest = Ipv4Addr::from(net_packet.dest_id());

        if msg_type == MsgType::Quic {
            // QUIC 数据不加密不压缩，但可能有 FEC
            if net_packet.is_fec() {
                let packets = self.fec_decoder.receive(net_packet)?;
                if let Some(packets) = packets {
                    for pkt in packets {
                        self.enhanced_inbound
                            .inbound(&network_addr, msg_type, src, pkt)
                            .await?;
                    }
                }
                return Ok(());
            }
            self.enhanced_inbound
                .inbound(&network_addr, msg_type, src, net_packet)
                .await?;
            return Ok(());
        }

        // 解密
        if let Err(e) = self.packet_crypto.decrypt_in_place(&mut net_packet) {
            log::error!("{},mst_type={msg_type:?},src={src},dst={dest}", e);
            return Ok(());
        }

        // FEC 解码（始终尝试解码，如果有 FEC 标志）
        if net_packet.is_fec() {
            let packets = self.fec_decoder.receive(net_packet)?;
            if let Some(packets) = packets {
                for pkt in packets {
                    let pkt = self.packet_compression.decompress(pkt)?;
                    self.process_decompressed_packet(
                        network_addr,
                        transport_client,
                        pkt,
                        msg_type,
                        src,
                        dest,
                    )
                    .await?;
                }
            }
            return Ok(());
        }

        // 解压缩
        let net_packet = self.packet_compression.decompress(net_packet)?;
        self.process_decompressed_packet(
            network_addr,
            transport_client,
            net_packet,
            msg_type,
            src,
            dest,
        )
        .await
    }

    async fn process_decompressed_packet(
        &self,
        network_addr: NetworkAddr,
        transport_client: &mut TransportClient,
        net_packet: NetPacket<TransmissionBytes>,
        msg_type: MsgType,
        src: Ipv4Addr,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        match msg_type {
            MsgType::Turn | MsgType::Broadcast => {
                self.enhanced_inbound
                    .inbound(&network_addr, msg_type, src, net_packet)
                    .await?;
            }
            MsgType::PunchStart1 => {
                // 对方发起打洞
                let peer_punch_info = PunchInfo::from_slice(net_packet.payload())?;
                let Some(self_punch_info) = self.get_punch_info() else {
                    return Ok(());
                };
                log::info!(
                    "对方主动发起打洞 对方nat信息={peer_punch_info:?}，自己nat信息={self_punch_info:?} {src}->{dest}"
                );
                self.update_peer_nat_info(src, peer_punch_info.nat_info.clone());
                let rs = self.puncher.punch(src, peer_punch_info)?;
                if rs {
                    let bytes_mut = self_punch_info.encode();
                    let mut net_packet = NetPacket::new(TransmissionBytes::zeroed_size(
                        HEAD_LENGTH + bytes_mut.len(),
                        self.packet_crypto.encrypt_reserve(),
                    ))?;
                    net_packet.set_msg_type(MsgType::PunchStart2);
                    net_packet.set_ttl(2);
                    net_packet.set_src_id(dest.into());
                    net_packet.set_dest_id(src.into());
                    net_packet.set_payload(&bytes_mut)?;
                    self.packet_crypto.encrypt_in_place(&mut net_packet)?;
                    transport_client.send_turn(net_packet).await?;
                } else {
                    log::info!("限制打洞频率")
                }
            }
            MsgType::PunchStart2 => {
                self.punch_backoff.record(src);
                // 对方回复开始打洞
                let peer_punch_info = PunchInfo::from_slice(net_packet.payload())?;
                self.update_peer_nat_info(src, peer_punch_info.nat_info.clone());
                log::info!("对方回复开始打洞 {:?} {src}->{dest}", peer_punch_info);
                self.puncher.punch_uncheck(src, peer_punch_info)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn handle(
        &self,
        transport_client: &mut TransportClient,
        data: TransmissionBytes,
        rpc_notifier: &RpcNotifier,
        now: i64,
    ) -> anyhow::Result<()> {
        let net_packet = NetPacket::new(&data)?;
        let Some(network_addr) = self.network_addr else {
            bail!("未找到自身IP")
        };

        if net_packet.is_gateway() {
            // 服务端数据
            return self
                .handle_server_data(transport_client, network_addr, data, rpc_notifier, now)
                .await;
        }
        let dest = Ipv4Addr::from(net_packet.dest_id());
        if !dest.is_broadcast() && !dest.is_unspecified() && network_addr.ip != dest {
            return Ok(());
        }
        self.handle_client_data(network_addr, transport_client, data)
            .await
    }
    pub async fn handle_ping(
        &self,
        transport_client: &mut TransportClient,
        now: i64,
    ) -> anyhow::Result<()> {
        let mut ping_packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + 8 + 8))?;
        ping_packet.set_ttl(1);
        ping_packet.set_msg_type(MsgType::PingTurn);
        ping_packet.set_gateway_flag(true);
        ping_packet.set_payload(&now.to_be_bytes())?;
        ping_packet.payload_mut()[0..8].copy_from_slice(&now.to_be_bytes());
        ping_packet.payload_mut()[8..]
            .copy_from_slice(&self.server_info.data_version(self.server_id).to_be_bytes());
        transport_client
            .send(ping_packet.into_buffer().into_bytes().freeze())
            .await?;
        Ok(())
    }
    pub fn handle_connected(&self) {
        self.server_info.set_server_connected(self.server_id, true);
        self.server_info
            .set_last_connected_time(self.server_id, Some(crate::utils::time::now_ts_ms()));
        self.server_info.set_disconnected_time(self.server_id, None);
    }
    pub fn set_server_version(&self, version: String) {
        self.server_info.set_server_version(self.server_id, version);
    }
    pub fn handle_disconnected(&self) {
        if self.server_info.set_server_connected(self.server_id, false) {
            self.server_info
                .set_disconnected_time(self.server_id, Some(crate::utils::time::now_ts_ms()));
        }
    }
}
