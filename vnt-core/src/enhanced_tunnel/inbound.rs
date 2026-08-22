use crate::context::config::DeviceMode;
use crate::context::{NetworkAddr, TrafficStats};
use crate::enhanced_tunnel::quic_over::quic_inbound::EnhancedQuicInbound;
use crate::ethernet::{ETHERTYPE_IPV4, build_arp_reply, parse_arp_ipv4, parse_frame};
use crate::nat::internal_nat::InternalNatInbound;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use crate::tunnel_core::outbound::HybridOutbound;
use anyhow::{Context, bail};
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
}

impl EnhancedInbound {
    pub fn new(
        tun_data_inbound: EnhancedTunInbound,
        quic_inbound: EnhancedQuicInbound,
        internal_nat_inbound: Option<InternalNatInbound>,
        traffic_stats: TrafficStats,
        device_mode: DeviceMode,
        hybrid_outbound: HybridOutbound,
    ) -> Self {
        Self {
            tun_data_inbound,
            quic_inbound,
            internal_nat_inbound,
            traffic_stats,
            device_mode,
            hybrid_outbound,
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

        if ethernet && parse_frame(buf.as_ref()).is_none() {
            return Ok(());
        }
        if ethernet && self.device_mode != DeviceMode::Tap {
            if let Some(arp) = parse_arp_ipv4(buf.as_ref())
                && arp.operation == 1
                && arp.target_ip == network_addr.ip
            {
                if let Some(reply) = build_arp_reply(buf.as_ref(), network_addr.ip) {
                    self.hybrid_outbound
                        .ethernet_unicast_outbound(*network_addr, src, reply)
                        .await?;
                }
                return Ok(());
            }
            if parse_frame(buf.as_ref()).is_none_or(|frame| frame.ethertype != ETHERTYPE_IPV4) {
                return Ok(());
            }
        }

        match msg_type {
            MsgType::Turn => {
                if let Some(internal_nat_inbound) = self.internal_nat_inbound.as_ref() {
                    let ip_data = if ethernet {
                        let Some(frame) = parse_frame(buf.as_ref()) else {
                            return Ok(());
                        };
                        if frame.ethertype != ETHERTYPE_IPV4 {
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
}
