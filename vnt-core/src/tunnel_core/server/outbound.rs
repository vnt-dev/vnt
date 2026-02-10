use crate::context::ServerInfoCollection;
use crate::crypto::PacketCrypto;
use crate::protocol::ProtoToBytesMut;
use crate::protocol::control_message::SelectiveBroadcast;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use anyhow::{Context, bail};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub(crate) struct ServerOutbound {
    server_id_list: Arc<Vec<u32>>,
    sender: Arc<HashMap<u32, Sender<(Bytes, Instant)>>>,
    server_info_collection: ServerInfoCollection,
    packet_crypto: PacketCrypto,
}
impl ServerOutbound {
    pub fn new(
        sender: Arc<HashMap<u32, Sender<(Bytes, Instant)>>>,
        server_info_collection: ServerInfoCollection,
        packet_crypto: PacketCrypto,
    ) -> Self {
        let server_id_list = Arc::new(sender.keys().copied().collect());
        Self {
            server_id_list,
            sender,
            server_info_collection,
            packet_crypto,
        }
    }
    pub fn exists_route(&self, dest: &Ipv4Addr) -> bool {
        self.server_info_collection.exists_online_client_ip(dest)
    }
    pub fn server_id_list(&self) -> &Vec<u32> {
        &self.server_id_list
    }
    pub fn encrypt_reserve(&self) -> usize {
        self.packet_crypto.encrypt_reserve()
    }

    pub async fn send_to_gateway_expired(
        &self,
        server_id: u32,
        mut buf: NetPacket<TransmissionBytes>,
        expired: Duration,
    ) -> anyhow::Result<()> {
        if !self.server_info_collection.is_server_connected(server_id) {
            bail!("未连接服务器")
        }
        buf.set_gateway_flag(true);
        self.send_expired_impl(server_id, buf, expired).await
    }

    pub async fn send(
        &self,
        dest_ip: Ipv4Addr,
        buf: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.send_expired(dest_ip, buf, Duration::from_secs(5))
            .await
    }
    pub async fn send_expired(
        &self,
        dest_ip: Ipv4Addr,
        buf: NetPacket<TransmissionBytes>,
        expired: Duration,
    ) -> anyhow::Result<()> {
        let Some(server_id) = self
            .server_info_collection
            .find_ip_to_server(&self.server_id_list, &dest_ip)
        else {
            bail!("not found ip route: {dest_ip}")
        };
        self.send_expired_impl(server_id, buf, expired).await
    }
    async fn send_expired_impl(
        &self,
        server_id: u32,
        mut buf: NetPacket<TransmissionBytes>,
        expired: Duration,
    ) -> anyhow::Result<()> {
        if !buf.is_gateway() {
            self.packet_crypto.encrypt_in_place(&mut buf)?;
        }
        let Some(sender) = self.sender.get(&server_id) else {
            bail!("not found server")
        };
        sender
            .send_timeout(
                (
                    buf.into_buffer().into_bytes().freeze(),
                    Instant::now() + expired,
                ),
                expired,
            )
            .await
            .context("connect server task failed")
    }

    pub async fn send_raw(&self, dest_ip: Ipv4Addr, buf: NetPacket<Bytes>) -> anyhow::Result<()> {
        let Some(server_id) = self
            .server_info_collection
            .find_ip_to_server(&self.server_id_list, &dest_ip)
        else {
            bail!("not found ip route: {dest_ip}")
        };
        let expired = Duration::from_secs(5);
        let Some(sender) = self.sender.get(&server_id) else {
            bail!("not found server")
        };
        sender
            .send_timeout((buf.into_buffer(), Instant::now() + expired), expired)
            .await
            .context("connect server task failed")
    }
    pub async fn send_default_raw(&self, buf: NetPacket<Bytes>) -> anyhow::Result<()> {
        let Some(server_id) = self
            .server_info_collection
            .find_connected_server(&self.server_id_list)
        else {
            bail!("not found default route")
        };
        let expired = Duration::from_secs(5);
        let Some(sender) = self.sender.get(&server_id) else {
            bail!("not found server")
        };
        sender
            .send_timeout((buf.into_buffer(), Instant::now() + expired), expired)
            .await
            .context("connect server task failed")
    }

    pub async fn send_raw_broadcast(
        &self,
        exclude_ips: Option<Vec<Ipv4Addr>>,
        buf: NetPacket<Bytes>,
    ) -> anyhow::Result<()> {
        let buf = buf.into_buffer();
        let expired = Duration::from_secs(5);

        let map: HashMap<u32, (Vec<Ipv4Addr>, u32)> =
            self.server_info_collection.server_client_ip_map();
        if map.is_empty() {
            bail!("no connected servers with clients");
        }

        // 只有一个服务器，直接发送
        if map.len() == 1 {
            let (server_id, (ips, _)) = map.iter().next().expect("map has exactly one element");
            if ips.is_empty() {
                return Ok(());
            }
            let sender = self
                .sender
                .get(server_id)
                .context("server sender not found")?;

            return if let Some(exclude_ips) = exclude_ips {
                send_exclude_broadcast(sender.clone(), buf, exclude_ips, expired).await
            } else {
                send_direct(sender.clone(), buf, expired).await
            };
        }

        // 找到最优服务器
        let (max_server_id, (max_ips, _)) = map
            .iter()
            .max_by(|(_, (ips_a, rtt_a)), (_, (ips_b, rtt_b))| {
                let score_a = ips_a.len() as f64 / (*rtt_a as f64 + 1.0);
                let score_b = ips_b.len() as f64 / (*rtt_b as f64 + 1.0);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .context("failed to find server with most IPs")?;
        if max_ips.is_empty() {
            return Ok(());
        }
        let max_ip_set: std::collections::HashSet<_> = max_ips.iter().collect();
        let exclude_set: std::collections::HashSet<_> = exclude_ips
            .as_ref()
            .map(|ips| ips.iter().collect())
            .unwrap_or_default();

        let mut handles = Vec::new();

        // 任务1: 向主服务器发送
        let sender = self
            .sender
            .get(max_server_id)
            .cloned()
            .context("max server sender not found")?;

        if let Some(exclude_ips) = exclude_ips.clone() {
            let buf_clone = buf.clone();
            let handle = tokio::spawn(async move {
                send_exclude_broadcast(sender, buf_clone, exclude_ips, expired).await
            });
            handles.push(handle);
        } else {
            let buf_clone = buf.clone();
            let handle = tokio::spawn(async move { send_direct(sender, buf_clone, expired).await });
            handles.push(handle);
        }

        // 任务2-N: 向其他服务器发送目标广播
        for (server_id, (ips, _rtt)) in map.iter() {
            if *server_id == *max_server_id {
                continue;
            }

            // 筛选目标IP：不在最大服务器中，也不在排除列表中
            let target_ips: Vec<Ipv4Addr> = ips
                .iter()
                .filter(|ip| !max_ip_set.contains(ip) && !exclude_set.contains(ip))
                .copied()
                .collect();

            if target_ips.is_empty() {
                continue;
            }

            let sender = match self.sender.get(server_id).cloned() {
                Some(s) => s,
                None => continue,
            };
            let buf_clone = buf.clone();

            let handle = tokio::spawn(async move {
                send_target_broadcast(sender, target_ips, buf_clone, expired).await
            });
            handles.push(handle);
        }

        // 等待所有任务完成
        let mut errors = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => errors.push(e),
                Err(e) => errors.push(anyhow::anyhow!("task join error: {}", e)),
            }
        }

        if !errors.is_empty() {
            bail!(
                "broadcast failed with {} errors: {:?}",
                errors.len(),
                errors
            );
        }

        Ok(())
    }
}
async fn send_exclude_broadcast(
    sender: Sender<(Bytes, Instant)>,
    buf: Bytes,
    exclude_ips: Vec<Ipv4Addr>,
    expired: Duration,
) -> anyhow::Result<()> {
    let broadcast = SelectiveBroadcast::new(&exclude_ips, buf.to_vec());
    let bytes = broadcast.encode_bytes_mut();

    let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + bytes.len()))?;
    packet.set_msg_type(MsgType::ExcludeBroadcast);
    packet.set_ttl(5);
    packet.payload_mut().copy_from_slice(&bytes);

    sender
        .send_timeout(
            (
                packet.into_buffer().into_bytes().freeze(),
                Instant::now() + expired,
            ),
            expired,
        )
        .await
        .context("failed to send exclude broadcast")?;

    Ok(())
}

// 直接发送原始数据
async fn send_direct(
    sender: Sender<(Bytes, Instant)>,
    buf: Bytes,
    expired: Duration,
) -> anyhow::Result<()> {
    sender
        .send_timeout((buf, Instant::now() + expired), expired)
        .await
        .context("failed to send direct broadcast")?;

    Ok(())
}

async fn send_target_broadcast(
    sender: Sender<(Bytes, Instant)>,
    target_ips: Vec<Ipv4Addr>,
    buf: Bytes,
    expired: Duration,
) -> anyhow::Result<()> {
    let target_broadcast = SelectiveBroadcast::new(&target_ips, buf.to_vec());
    let target_bytes = target_broadcast.encode_bytes_mut();

    let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + target_bytes.len()))?;
    packet.set_msg_type(MsgType::TargetBroadcast);
    packet.set_ttl(5);
    packet.payload_mut().copy_from_slice(&target_bytes);

    sender
        .send_timeout(
            (
                packet.into_buffer().into_bytes().freeze(),
                Instant::now() + expired,
            ),
            expired,
        )
        .await
        .context("failed to send target broadcast")?;

    Ok(())
}
