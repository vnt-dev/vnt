use crate::context::config::{PunchRule, TurnRule, allow_punch, punch_model_for};
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
use rustp2p_core::punch::{PunchModel, PunchPolicy, PunchPolicySet, Puncher};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_CONCURRENT_PUNCHES: usize = 4;

#[derive(Clone)]
struct PunchLimiter {
    semaphore: Arc<Semaphore>,
}

impl Default for PunchLimiter {
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_PUNCHES)),
        }
    }
}

impl PunchLimiter {
    fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }
}

pub struct PunchTaskContext {
    pub network: SharedNetworkAddr,
    pub server_info: ServerInfoCollection,
    pub punch_backoff: PunchBackoff,
    pub punch_info_getter: PunchInfoGetter,
    pub turn: Arc<Vec<TurnRule>>,
}

pub type PunchInfoGetter = std::sync::Arc<dyn Fn(Ipv4Addr) -> Option<PunchInfo> + Send + Sync>;

fn is_other_peer(src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> bool {
    dest_ip != src_ip
}

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
        if !ctx.server_info.is_any_server_connected(None) {
            continue;
        }
        let mut list = ctx.server_info.client_online_ips();
        list.retain(|dest_ip| {
            is_other_peer(src_ip, *dest_ip)
                && allow_punch(&ctx.turn, dest_ip)
                && route_table.need_punch(dest_ip)
                && ctx.punch_backoff.should_punch(*dest_ip)
        });
        list.shuffle(&mut rand::rng());
        list.truncate(5);
        for dest_ip in list {
            let Some(punch_info) = (ctx.punch_info_getter)(dest_ip) else {
                continue;
            };
            // should_punch() 只用于候选过滤；最终必须原子占用，
            // 防止并发调度或重复报文同时启动同一目标。
            if !ctx.punch_backoff.try_begin(dest_ip) {
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
#[derive(Clone)]
pub struct NatPuncher {
    network: SharedNetworkAddr,
    punch_backoff: PunchBackoff,
    puncher: Option<Puncher>,
    packet_crypto: PacketCrypto,
    limiter: PunchLimiter,
    punch_rules: Arc<Vec<PunchRule>>,
}

impl NatPuncher {
    pub fn new(
        network: SharedNetworkAddr,
        punch_backoff: PunchBackoff,
        puncher: Option<Puncher>,
        packet_crypto: PacketCrypto,
        punch_rules: Arc<Vec<PunchRule>>,
    ) -> Self {
        Self {
            network,
            punch_backoff,
            puncher,
            packet_crypto,
            limiter: PunchLimiter::default(),
            punch_rules,
        }
    }
    pub fn punch(&self, dest_ip: Ipv4Addr, punch_info: PunchInfo) -> anyhow::Result<bool> {
        let Some(puncher) = self.puncher.clone() else {
            return Ok(false);
        };
        let Some(punch_model) = self.effective_punch_model(dest_ip, &punch_info) else {
            log::debug!("skip punch to {dest_ip}: punch model intersection is empty");
            return Ok(false);
        };
        let Some(permit) = self.limiter.try_acquire() else {
            log::debug!("skip punch to {dest_ip}: concurrent punch limit reached");
            return Ok(false);
        };
        if !self.punch_backoff.try_begin_punch(dest_ip) {
            log::debug!("skip punch to {dest_ip}: punched within the last 5 seconds");
            return Ok(false);
        }
        self.spawn_punch(
            puncher,
            dest_ip,
            punch_info,
            punch_model,
            Some(Duration::from_millis(50)),
            permit,
        )?;
        Ok(true)
    }
    pub fn punch_uncheck(&self, dest_ip: Ipv4Addr, punch_info: PunchInfo) -> anyhow::Result<()> {
        self.punch_uncheck_delay(dest_ip, punch_info, None)
    }
    fn punch_uncheck_delay(
        &self,
        dest_ip: Ipv4Addr,
        punch_info: PunchInfo,
        time: Option<Duration>,
    ) -> anyhow::Result<()> {
        let Some(puncher) = self.puncher.clone() else {
            return Ok(());
        };
        let Some(punch_model) = self.effective_punch_model(dest_ip, &punch_info) else {
            log::debug!("skip punch to {dest_ip}: punch model intersection is empty");
            return Ok(());
        };
        let Some(permit) = self.limiter.try_acquire() else {
            log::debug!("skip punch to {dest_ip}: concurrent punch limit reached");
            return Ok(());
        };
        if !self.punch_backoff.try_begin_punch(dest_ip) {
            log::debug!("skip punch to {dest_ip}: punched within the last 5 seconds");
            return Ok(());
        }
        self.spawn_punch(puncher, dest_ip, punch_info, punch_model, time, permit)
    }
    fn effective_punch_model(
        &self,
        dest_ip: Ipv4Addr,
        punch_info: &PunchInfo,
    ) -> Option<PunchModel> {
        effective_punch_model(&self.punch_rules, dest_ip, punch_info.punch_model.clone())
    }
    fn spawn_punch(
        &self,
        puncher: Puncher,
        dest_ip: Ipv4Addr,
        punch_info: PunchInfo,
        punch_model: PunchModel,
        time: Option<Duration>,
        permit: OwnedSemaphorePermit,
    ) -> anyhow::Result<()> {
        let Some(src_ip) = self.network.ip() else {
            bail!("not ip");
        };
        let packet_crypto = self.packet_crypto.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(time) = time {
                tokio::time::sleep(time).await;
            }
            if let Err(e) = punch_now(
                puncher,
                src_ip,
                dest_ip,
                punch_info,
                punch_model,
                packet_crypto,
            )
            .await
            {
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
    punch_model: PunchModel,
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
    let buf = packet.into_buffer().into_bytes().freeze();
    let punch_info = rustp2p_core::punch::PunchInfo::new(punch_model, nat_info.nat_info);
    puncher
        .punch_now(Some(buf.clone()), buf, punch_info)
        .await?;
    Ok(())
}

fn effective_punch_model(
    rules: &[PunchRule],
    dest_ip: Ipv4Addr,
    peer_model: PunchPolicySet,
) -> Option<PunchModel> {
    let model = punch_model_for(rules, &dest_ip) & peer_model;
    [
        PunchPolicy::IPv4Tcp,
        PunchPolicy::IPv4Udp,
        PunchPolicy::IPv6Tcp,
        PunchPolicy::IPv6Udp,
    ]
    .into_iter()
    .any(|policy| model.is_match(policy))
    .then_some(model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ip_directions_are_candidates_but_self_is_not() {
        let src = Ipv4Addr::new(10, 26, 0, 2);

        assert!(is_other_peer(src, Ipv4Addr::new(10, 26, 0, 1)));
        assert!(is_other_peer(src, Ipv4Addr::new(10, 26, 0, 3)));
        assert!(!is_other_peer(src, src));
    }

    #[test]
    fn punch_limiter_is_shared_and_releases_capacity() {
        let limiter = PunchLimiter::default();
        let clone = limiter.clone();
        let mut permits = Vec::new();

        for _ in 0..MAX_CONCURRENT_PUNCHES {
            permits.push(limiter.try_acquire().expect("前四个任务应获得许可"));
        }
        assert!(
            clone.try_acquire().is_none(),
            "克隆必须共享同一个全局并发上限"
        );

        permits.pop();

        assert!(
            clone.try_acquire().is_some(),
            "任务结束释放许可后应能立即开始下一轮"
        );
    }

    #[test]
    fn punch_model_uses_local_and_peer_intersection() {
        let rules = vec!["10.26.0.2,IPv4Tcp,IPv6Udp".parse::<PunchRule>().unwrap()];
        let mut peer = PunchPolicySet::empty();
        peer.or(PunchPolicy::IPv4Tcp);
        peer.or(PunchPolicy::IPv4Udp);

        let effective = effective_punch_model(&rules, Ipv4Addr::new(10, 26, 0, 2), peer)
            .expect("IPv4Tcp is allowed by both peers");
        assert!(effective.is_match(PunchPolicy::IPv4Tcp));
        assert!(!effective.is_match(PunchPolicy::IPv4Udp));
        assert!(!effective.is_match(PunchPolicy::IPv6Udp));

        let mut incompatible = PunchPolicySet::empty();
        incompatible.or(PunchPolicy::IPv6Tcp);
        assert!(effective_punch_model(&rules, Ipv4Addr::new(10, 26, 0, 2), incompatible).is_none());
    }
}
