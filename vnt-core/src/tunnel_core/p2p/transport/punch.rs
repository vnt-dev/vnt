use crate::context::nat::PunchBackoff;
use crate::context::{ServerInfoCollection, SharedNetworkAddr};
use crate::crypto::PacketCrypto;
use crate::protocol::client_message::PunchInfo;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::route_table::RouteTable;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use log::error;
use rand::seq::SliceRandom;
use rust_p2p_core::punch::{PunchModel, Puncher};
use std::net::Ipv4Addr;
use std::time::Duration;

pub struct PunchTaskContext {
    pub network: SharedNetworkAddr,
    pub server_info: ServerInfoCollection,
    pub punch_backoff: PunchBackoff,
    pub punch_info_getter: PunchInfoGetter,
}

pub type PunchInfoGetter = std::sync::Arc<dyn Fn() -> Option<PunchInfo> + Send + Sync>;

pub async fn punch_task(
    tunnel_to_server: ServerOutbound,
    route_table: RouteTable,
    ctx: PunchTaskContext,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Some(src_ip) = ctx.network.ip() else {
            continue;
        };
        let Some(punch_info) = (ctx.punch_info_getter)() else {
            continue;
        };
        let mut list = ctx.server_info.client_online_ips();
        list.shuffle(&mut rand::rng());
        list.truncate(5);
        for dest_ip in list {
            if dest_ip <= src_ip {
                continue;
            }
            if ctx.server_info.is_any_server_connected(None) && route_table.need_punch(&dest_ip) {
                if !ctx.punch_backoff.should_punch(dest_ip) {
                    continue;
                }
                log::info!("punching {dest_ip}");

                let data = punch_info.encode();
                let mut net_packet = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH + data.len(),
                    tunnel_to_server.encrypt_reserve(),
                ))?;
                net_packet.set_msg_type(MsgType::PunchStart1);
                net_packet.set_ttl(2);
                net_packet.set_src_id(src_ip.into());
                net_packet.set_dest_id(dest_ip.into());
                net_packet.set_payload(data.as_ref())?;
                if let Err(e) = tunnel_to_server.send(dest_ip, net_packet).await {
                    error!("punch send error {:?}", e);
                }
            }
        }
    }
}
#[derive(Clone)]
pub struct NatPuncher {
    network: SharedNetworkAddr,
    punch_backoff: PunchBackoff,
    puncher: Option<Puncher>,
    packet_crypto: PacketCrypto,
}

impl NatPuncher {
    pub fn new(
        network: SharedNetworkAddr,
        punch_backoff: PunchBackoff,
        puncher: Option<Puncher>,
        packet_crypto: PacketCrypto,
    ) -> Self {
        Self {
            network,
            punch_backoff,
            puncher,
            packet_crypto,
        }
    }
    pub fn punch(&self, dest_ip: Ipv4Addr, punch_info: PunchInfo) -> anyhow::Result<bool> {
        if self.puncher.is_none() {
            return Ok(false);
        }
        if !self.punch_backoff.should_punch(dest_ip) {
            return Ok(false);
        }
        self.punch_uncheck_delay(dest_ip, punch_info, Some(Duration::from_millis(50)))?;
        Ok(true)
    }
    pub fn punch_uncheck(&self, dest_ip: Ipv4Addr, punch_info: PunchInfo) -> anyhow::Result<()> {
        self.punch_uncheck_delay(dest_ip, punch_info, None)
    }
    pub fn punch_uncheck_delay(
        &self,
        dest_ip: Ipv4Addr,
        punch_info: PunchInfo,
        time: Option<Duration>,
    ) -> anyhow::Result<()> {
        let Some(puncher) = self.puncher.clone() else {
            return Ok(());
        };
        let Some(src_ip) = self.network.ip() else {
            bail!("not ip");
        };
        let packet_crypto = self.packet_crypto.clone();
        tokio::spawn(async move {
            if let Some(time) = time {
                tokio::time::sleep(time).await;
            }
            if let Err(e) = punch_now(puncher, src_ip, dest_ip, punch_info, packet_crypto).await {
                log::warn!("punch send error {:?}", e);
            }
        });
        Ok(())
    }
}
async fn punch_now(
    puncher: Puncher,
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    nat_info: PunchInfo,
    packet_crypto: PacketCrypto,
) -> anyhow::Result<()> {
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + 8,
        packet_crypto.encrypt_reserve(),
    ))?;
    packet.set_msg_type(MsgType::PunchReq);
    packet.set_ttl(1);
    packet.set_src_id(src_ip.into());
    packet.set_dest_id(dest_ip.into());
    packet.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())?;
    packet_crypto.encrypt_in_place(&mut packet)?;
    let buf = packet.buffer();
    let punch_info = rust_p2p_core::punch::PunchInfo::new(PunchModel::all(), nat_info.nat_info);
    puncher.punch_now(Some(buf), buf, punch_info).await?;
    Ok(())
}
