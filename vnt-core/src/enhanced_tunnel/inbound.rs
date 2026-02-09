use crate::context::{NetworkAddr, TrafficStats};
use crate::enhanced_tunnel::quic_over::quic_inbound::EnhancedQuicInbound;
use crate::nat::internal_nat::InternalNatInbound;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::enhanced_tun::EnhancedTunInbound;
use anyhow::{Context, bail};
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub(crate) struct EnhancedInbound {
    tun_data_inbound: EnhancedTunInbound,
    quic_inbound: EnhancedQuicInbound,
    internal_nat_inbound: Option<InternalNatInbound>,
    traffic_stats: TrafficStats,
}

impl EnhancedInbound {
    pub fn new(
        tun_data_inbound: EnhancedTunInbound,
        quic_inbound: EnhancedQuicInbound,
        internal_nat_inbound: Option<InternalNatInbound>,
        traffic_stats: TrafficStats,
    ) -> Self {
        Self {
            tun_data_inbound,
            quic_inbound,
            internal_nat_inbound,
            traffic_stats,
        }
    }
    pub async fn inbound(
        &self,
        network_addr: &NetworkAddr,
        msg_type: MsgType,
        src: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let mut buf = packet.into_buffer();
        self.traffic_stats.record_rx(src, buf.len() as u64);
        buf.advance_head(HEAD_LENGTH)?;

        match msg_type {
            MsgType::Turn => {
                if let Some(internal_nat_inbound) = self.internal_nat_inbound.as_ref() {
                    let Some(ipv4) = Ipv4Packet::new(&buf) else {
                        bail!("EnhancedInbound not ipv4")
                    };
                    let dest = ipv4.get_destination();
                    if dest != network_addr.ip && !network_addr.network().contains(&dest) {
                        internal_nat_inbound.send(&buf, network_addr).await?;
                        return Ok(());
                    }
                }
                self.tun_data_inbound.inbound(buf, network_addr).await?;
            }
            MsgType::Broadcast | MsgType::ExcludeBroadcast => {
                self.tun_data_inbound.inbound(buf, network_addr).await?;
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
