use crate::context::config::DeviceMode;
use crate::context::{NetworkAddr, TrafficStats};
use crate::enhanced_tunnel::quic_over::quic_inbound::EnhancedQuicInbound;
use crate::ethernet::{MacTable, build_arp_reply, parse_arp_ipv4, parse_frame};
use crate::nat::SubnetMappingTable;
use crate::nat::internal_nat::InternalNatInbound;
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tunnel_core::outbound::HybridOutbound;
use anyhow::{Context, bail};
use pnet_packet::arp::ArpOperations;
use pnet_packet::ethernet::EtherTypes;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub(crate) struct EnhancedInbound {
    tun_data_inbound: EnhancedTunInbound,
    quic_inbound: EnhancedQuicInbound,
    internal_nat_inbound: Option<InternalNatInbound>,
    traffic_stats: TrafficStats,
    device_mode: DeviceMode,
    hybrid_outbound: HybridOutbound,
    subnet_mapping: SubnetMappingTable,
    subnet_packet_mapper: SubnetPacketMapper,
    mac_table: MacTable,
}

impl EnhancedInbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tun_data_inbound: EnhancedTunInbound,
        quic_inbound: EnhancedQuicInbound,
        internal_nat_inbound: Option<InternalNatInbound>,
        traffic_stats: TrafficStats,
        device_mode: DeviceMode,
        hybrid_outbound: HybridOutbound,
        subnet_mapping: SubnetMappingTable,
        subnet_packet_mapper: SubnetPacketMapper,
        mac_table: MacTable,
    ) -> Self {
        Self {
            tun_data_inbound,
            quic_inbound,
            internal_nat_inbound,
            traffic_stats,
            device_mode,
            hybrid_outbound,
            subnet_mapping,
            subnet_packet_mapper,
            mac_table,
        }
    }
    pub async fn inbound(
        &self,
        network_addr: &NetworkAddr,
        msg_type: MsgType,
        src: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let ethernet = packet.is_ethernet();
        let mut buf = packet.into_buffer();
        self.traffic_stats.record_rx(src, buf.len() as u64);
        buf.advance_head(HEAD_LENGTH)?;

        let ethernet_frame = if ethernet {
            let Some(frame) = parse_frame(buf.as_ref()) else {
                return Ok(());
            };
            self.mac_table.learn_remote(frame.source, src);
            Some(frame)
        } else {
            None
        };
        if ethernet && self.device_mode != DeviceMode::Tap {
            if let Some(arp) = parse_arp_ipv4(buf.as_ref())
                && arp.operation == ArpOperations::Request
                && arp.target_ip == network_addr.ip
            {
                if let Some(reply) = build_arp_reply(buf.as_ref(), network_addr.ip) {
                    self.hybrid_outbound
                        .ethernet_unicast_outbound(*network_addr, src, reply)
                        .await?;
                }
                return Ok(());
            }
            if ethernet_frame.is_none_or(|frame| frame.ethertype != EtherTypes::Ipv4) {
                return Ok(());
            }
        }

        match msg_type {
            MsgType::Turn => {
                let ip_offset = if ethernet {
                    let Some(frame) = ethernet_frame else {
                        return Ok(());
                    };
                    if frame.ethertype != EtherTypes::Ipv4 {
                        self.inbound_turn(buf, network_addr, src, true).await?;
                        return Ok(());
                    }
                    frame.payload_offset
                } else {
                    0
                };
                let Some(ipv4) = Ipv4Packet::new(&buf[ip_offset..]) else {
                    bail!("EnhancedInbound not ipv4")
                };
                let mapped = ipv4.get_destination();
                let buffers = if let Some(actual) = self.subnet_mapping.forward(mapped) {
                    match self
                        .subnet_packet_mapper
                        .map_destination(src, buf, ip_offset, mapped, actual)
                    {
                        Ok(buffers) => buffers,
                        Err(error) => {
                            log::debug!("drop invalid inbound mapped IPv4 packet: {error:#}");
                            return Ok(());
                        }
                    }
                } else {
                    vec![buf]
                };
                for buf in buffers {
                    self.inbound_turn(buf, network_addr, src, ethernet).await?;
                }
            }
            MsgType::Broadcast | MsgType::ExcludeBroadcast => {
                self.tun_data_inbound
                    .inbound(buf, network_addr, src, ethernet)
                    .await?;
            }
            MsgType::Quic => {
                let payload = buf.into_bytes().freeze();
                self.quic_inbound
                    .inbound(payload, src)
                    .await
                    .context("inbound quic")?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn inbound_turn(
        &self,
        buf: TransmissionBytes,
        network_addr: &NetworkAddr,
        src: Ipv4Addr,
        ethernet: bool,
    ) -> anyhow::Result<()> {
        if let Some(internal_nat_inbound) = self.internal_nat_inbound.as_ref() {
            let ip_data = if ethernet {
                let Some(frame) = parse_frame(buf.as_ref()) else {
                    return Ok(());
                };
                if frame.ethertype != EtherTypes::Ipv4 {
                    self.tun_data_inbound
                        .inbound(buf, network_addr, src, true)
                        .await?;
                    return Ok(());
                }
                &buf[frame.payload_offset..]
            } else {
                buf.as_ref()
            };
            let Some(ipv4) = Ipv4Packet::new(ip_data) else {
                bail!("EnhancedInbound not ipv4")
            };
            let dest = ipv4.get_destination();
            if dest != network_addr.ip && !network_addr.network().contains(&dest) {
                internal_nat_inbound.send(ip_data, network_addr).await?;
                return Ok(());
            }
        }
        self.tun_data_inbound
            .inbound(buf, network_addr, src, ethernet)
            .await?;
        Ok(())
    }
}
