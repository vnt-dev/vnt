use crate::context::ServerInfoCollection;
use crate::crypto::PacketCrypto;
use crate::protocol::ProtoToBytesMut;
use crate::protocol::control_message::SelectiveBroadcast;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use anyhow::{Context, bail};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
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
        self.server_info_collection
            .find_ip_to_server(&self.server_id_list, dest)
            .is_some()
    }
    pub fn server_id_list(&self) -> &Vec<u32> {
        &self.server_id_list
    }
    pub fn is_server_connected(&self, server_id: u32) -> bool {
        self.server_info_collection.is_server_connected(server_id)
    }
    pub fn is_any_server_connected(&self) -> bool {
        self.server_info_collection
            .is_any_server_connected(Some(&self.server_id_list))
    }

    pub fn broadcast_coverage(&self) -> HashMap<u32, (Vec<Ipv4Addr>, u32)> {
        self.server_info_collection.server_client_ip_map()
    }
    pub fn encrypt_reserve(&self) -> usize {
        self.packet_crypto.encrypt_reserve()
    }

    /// 向所有当前已连接的控制服务端发送同一个网关控制包。
    /// 单个服务端发送失败不会阻止其他服务端接收。
    pub async fn send_gateway_to_all(
        &self,
        buf: Bytes,
        expired: Duration,
    ) -> anyhow::Result<usize> {
        let mut sent = 0usize;
        let mut connected = 0usize;
        for server_id in self.server_id_list.iter().copied() {
            if !self.server_info_collection.is_server_connected(server_id) {
                continue;
            }
            connected += 1;
            let Some(sender) = self.sender.get(&server_id) else {
                log::warn!("快速注册发送失败：未找到服务端 {server_id} 的发送通道");
                continue;
            };
            match sender
                .send_timeout((buf.clone(), Instant::now() + expired), expired)
                .await
            {
                Ok(()) => sent += 1,
                Err(error) => {
                    log::warn!("向服务端 {server_id} 发送快速注册失败: {error}");
                }
            }
        }
        if connected == 0 {
            bail!("没有已连接的服务端");
        }
        if sent == 0 {
            bail!("快速注册未能发送到任何服务端");
        }
        Ok(sent)
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

    /// Sends an already encrypted graph packet to every connected server except
    /// the ingress server. Unlike client broadcast distribution, this is a
    /// server-to-server bridge primitive and therefore does not depend on the
    /// current client snapshots of those servers.
    pub async fn flood_connected_raw(
        &self,
        buf: NetPacket<Bytes>,
        exclude_server: Option<u32>,
    ) -> usize {
        let buf = buf.into_buffer();
        let expired = Duration::from_secs(5);
        let mut sent = 0usize;
        for server_id in self.server_id_list.iter().copied() {
            if exclude_server == Some(server_id)
                || !self.server_info_collection.is_server_connected(server_id)
            {
                continue;
            }
            let Some(sender) = self.sender.get(&server_id) else {
                continue;
            };
            match sender
                .send_timeout((buf.clone(), Instant::now() + expired), expired)
                .await
            {
                Ok(()) => sent += 1,
                Err(error) => {
                    log::debug!("failed to bridge graph packet to server {server_id}: {error}");
                }
            }
        }
        sent
    }

    pub async fn send_raw_broadcast(
        &self,
        exclude_ips: Option<Vec<Ipv4Addr>>,
        buf: NetPacket<Bytes>,
    ) -> Vec<Ipv4Addr> {
        let source = Ipv4Addr::from(buf.src_id());
        let buf = buf.into_buffer();
        let expired = Duration::from_secs(5);
        let map = self.broadcast_coverage();
        let exclude_set = exclude_ips
            .as_deref()
            .unwrap_or_default()
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let mut targets = map
            .values()
            .flat_map(|(ips, _)| ips.iter().copied())
            .filter(|ip| *ip != source && !exclude_set.contains(ip))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        targets.sort_unstable();
        let assignments = greedy_server_assignments(&map, &targets);
        let mut primary_excludes = exclude_ips.unwrap_or_default();
        let mut unique_excludes = HashSet::new();
        primary_excludes.retain(|ip| unique_excludes.insert(*ip));
        primary_excludes.truncate(255);
        let mut failed = Vec::new();
        let mut handles = Vec::new();
        for (index, (server_id, mut target_ips)) in assignments.into_iter().enumerate() {
            let failed_if_unsent = if index == 0 {
                target_ips.clone()
            } else {
                target_ips.truncate(255);
                target_ips.clone()
            };
            let Some(sender) = self.sender.get(&server_id).cloned() else {
                failed.extend(failed_if_unsent);
                continue;
            };
            let data = buf.clone();
            let excludes = primary_excludes.clone();
            let wire_targets = target_ips.clone();
            let handle = if index == 0 {
                tokio::spawn(async move {
                    send_exclude_broadcast(sender, data, excludes, source, expired).await
                })
            } else {
                tokio::spawn(async move {
                    send_target_broadcast(sender, wire_targets, data, source, expired).await
                })
            };
            handles.push((failed_if_unsent, handle));
        }
        for (targets, handle) in handles {
            if !matches!(handle.await, Ok(Ok(()))) {
                failed.extend(targets);
            }
        }
        failed.sort_unstable();
        failed.dedup();
        failed
    }

    /// Sends one exact target task to each selected server. Targets are
    /// assigned once using deterministic greedy set cover; a server task is
    /// never split when the 255-address protocol limit is reached.
    pub async fn send_targeted_broadcast(
        &self,
        targets: &[Ipv4Addr],
        buf: NetPacket<Bytes>,
    ) -> Vec<Ipv4Addr> {
        let source = Ipv4Addr::from(buf.src_id());
        let buf = buf.into_buffer();
        let map = self.broadcast_coverage();
        let mut target_order = targets.to_vec();
        let mut unique = HashSet::new();
        target_order.retain(|target| unique.insert(*target));
        let target_set = target_order.iter().copied().collect::<HashSet<_>>();
        let assignments = greedy_server_assignments(&map, &target_order);
        let expired = Duration::from_secs(5);
        let mut assigned = HashSet::new();
        let mut failed = Vec::new();
        let mut handles = Vec::new();
        for (server_id, mut ips) in assignments {
            assigned.extend(ips.iter().copied());
            ips.truncate(255);
            let Some(sender) = self.sender.get(&server_id).cloned() else {
                failed.extend(ips);
                continue;
            };
            let data = buf.clone();
            let wire_ips = ips.clone();
            handles.push((
                ips,
                tokio::spawn(async move {
                    send_target_broadcast(sender, wire_ips, data, source, expired).await
                }),
            ));
        }
        for (targets, handle) in handles {
            if !matches!(handle.await, Ok(Ok(()))) {
                failed.extend(targets);
            }
        }
        failed.extend(target_set.difference(&assigned).copied());
        failed.sort_unstable();
        failed.dedup();
        failed
    }
}

fn greedy_server_assignments(
    coverage: &HashMap<u32, (Vec<Ipv4Addr>, u32)>,
    targets: &[Ipv4Addr],
) -> Vec<(u32, Vec<Ipv4Addr>)> {
    let rank = targets
        .iter()
        .enumerate()
        .map(|(index, ip)| (*ip, index))
        .collect::<HashMap<_, _>>();
    let mut remaining = targets.iter().copied().collect::<HashSet<_>>();
    let mut assignments = Vec::new();
    while !remaining.is_empty() {
        let selected = coverage
            .iter()
            .filter_map(|(server_id, (ips, rtt))| {
                let count = ips
                    .iter()
                    .copied()
                    .collect::<HashSet<_>>()
                    .intersection(&remaining)
                    .count();
                (count > 0).then_some((*server_id, *rtt, count))
            })
            .max_by(|left, right| {
                left.2
                    .cmp(&right.2)
                    .then_with(|| right.1.cmp(&left.1))
                    .then_with(|| right.0.cmp(&left.0))
            });
        let Some((server_id, _, _)) = selected else {
            break;
        };
        let coverage_set = coverage[&server_id]
            .0
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let mut assigned = remaining
            .iter()
            .filter(|ip| coverage_set.contains(ip))
            .copied()
            .collect::<Vec<_>>();
        assigned.sort_by_key(|ip| (rank.get(ip).copied().unwrap_or(usize::MAX), *ip));
        for ip in &assigned {
            remaining.remove(ip);
        }
        assignments.push((server_id, assigned));
    }
    assignments
}

async fn send_exclude_broadcast(
    sender: Sender<(Bytes, Instant)>,
    buf: Bytes,
    exclude_ips: Vec<Ipv4Addr>,
    source: Ipv4Addr,
    expired: Duration,
) -> anyhow::Result<()> {
    let broadcast = SelectiveBroadcast::new(&exclude_ips, buf.to_vec());
    let bytes = broadcast.encode_bytes_mut();

    let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + bytes.len()))?;
    packet.set_msg_type(MsgType::ExcludeBroadcast);
    packet.set_ttl(5);
    packet.set_src_id(source.into());
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

async fn send_target_broadcast(
    sender: Sender<(Bytes, Instant)>,
    target_ips: Vec<Ipv4Addr>,
    buf: Bytes,
    source: Ipv4Addr,
    expired: Duration,
) -> anyhow::Result<()> {
    let target_broadcast = SelectiveBroadcast::new(&target_ips, buf.to_vec());
    let target_bytes = target_broadcast.encode_bytes_mut();

    let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + target_bytes.len()))?;
    packet.set_msg_type(MsgType::TargetBroadcast);
    packet.set_ttl(5);
    packet.set_src_id(source.into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_cover_is_greedy_deterministic_and_assigns_each_target_once() {
        let a = Ipv4Addr::new(10, 0, 0, 2);
        let b = Ipv4Addr::new(10, 0, 0, 3);
        let c = Ipv4Addr::new(10, 0, 0, 4);
        let coverage = HashMap::from([
            (9, (vec![a, b], 40)),
            (3, (vec![a, b], 10)),
            (2, (vec![b, c], 10)),
        ]);
        let targets = vec![a, b, c];
        let assignments = greedy_server_assignments(&coverage, &targets);
        assert_eq!(assignments[0], (2, vec![b, c]));
        assert_eq!(assignments[1], (3, vec![a]));
        let assigned = assignments
            .iter()
            .flat_map(|(_, ips)| ips.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(assigned.len(), 3);
        assert_eq!(
            assigned.iter().copied().collect::<HashSet<_>>(),
            targets.iter().copied().collect()
        );
    }

    #[tokio::test]
    async fn selective_server_wrappers_preserve_inner_broadcast_source() {
        let source = Ipv4Addr::new(10, 0, 0, 9);
        let target = Ipv4Addr::new(10, 0, 0, 10);
        let inner = Bytes::from_static(&[0u8; HEAD_LENGTH]);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        send_target_broadcast(
            sender.clone(),
            vec![target],
            inner.clone(),
            source,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        send_exclude_broadcast(sender, inner, vec![target], source, Duration::from_secs(1))
            .await
            .unwrap();

        for expected in [MsgType::TargetBroadcast, MsgType::ExcludeBroadcast] {
            let (bytes, _) = receiver.recv().await.unwrap();
            let packet = NetPacket::new(bytes).unwrap();
            assert_eq!(packet.msg_type().unwrap(), expected);
            assert_eq!(Ipv4Addr::from(packet.src_id()), source);
        }
    }
}
