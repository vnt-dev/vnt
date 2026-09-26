use crate::context::ServerInfoCollection;
use crate::crypto::PacketCrypto;
use crate::protocol::control_message::SelectiveBroadcast;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;

#[derive(Clone)]
pub(crate) struct ServerOutbound {
    inner: Arc<ArcSwap<ServerOutboundInner>>,
}

struct ServerOutboundInner {
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
            inner: Arc::new(ArcSwap::from_pointee(ServerOutboundInner {
                server_id_list,
                sender,
                server_info_collection,
                packet_crypto,
            })),
        }
    }

    pub fn exists_route(&self, dest: &Ipv4Addr) -> bool {
        let inner = self.inner.load();
        inner
            .server_info_collection
            .find_ip_to_server(&inner.server_id_list, dest)
            .is_some()
    }

    /// 用新的发送通道表整体替换当前表（运行期服务端增删后发布）。
    pub(crate) fn update_senders(&self, sender: Arc<HashMap<u32, Sender<(Bytes, Instant)>>>) {
        let inner = self.inner.load();
        self.inner.store(Arc::new(ServerOutboundInner {
            server_id_list: Arc::new(sender.keys().copied().collect()),
            sender,
            server_info_collection: inner.server_info_collection.clone(),
            packet_crypto: inner.packet_crypto.clone(),
        }));
    }
    pub fn server_id_list(&self) -> Arc<Vec<u32>> {
        self.inner.load().server_id_list.clone()
    }
    pub fn is_server_connected(&self, server_id: u32) -> bool {
        self.inner
            .load()
            .server_info_collection
            .is_server_connected(server_id)
    }
    pub fn server_instance_id(&self, server_id: u32) -> Option<Vec<u8>> {
        self.inner
            .load()
            .server_info_collection
            .server_instance_id(server_id)
    }
    pub fn is_any_server_connected(&self) -> bool {
        let inner = self.inner.load();
        inner
            .server_info_collection
            .is_any_server_connected(Some(&inner.server_id_list))
    }

    pub fn broadcast_coverage(&self) -> HashMap<u32, (Vec<Ipv4Addr>, u32)> {
        self.inner
            .load()
            .server_info_collection
            .server_client_ip_map()
    }
    pub fn encrypt_reserve(&self) -> usize {
        self.inner.load().packet_crypto.encrypt_reserve()
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
        let inner = self.inner.load();
        for server_id in inner.server_id_list.iter().copied() {
            if !inner.server_info_collection.is_server_connected(server_id) {
                continue;
            }
            connected += 1;
            let Some(sender) = inner.sender.get(&server_id) else {
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

    /// Sends a gateway control packet to one connected server. Callers use
    /// this for connection-scoped protocols such as verified subscription ACKs.
    pub async fn send_gateway_to_server(
        &self,
        server_id: u32,
        buf: Bytes,
        expired: Duration,
    ) -> anyhow::Result<bool> {
        let inner = self.inner.load();
        if !inner.server_info_collection.is_server_connected(server_id) {
            return Ok(false);
        }
        let sender = inner
            .sender
            .get(&server_id)
            .with_context(|| format!("未找到服务端 {server_id} 的发送通道"))?;
        match sender
            .send_timeout((buf, Instant::now() + expired), expired)
            .await
        {
            Ok(()) => Ok(true),
            Err(error) => {
                log::warn!("向服务端 {server_id} 发送控制消息失败: {error}");
                Ok(false)
            }
        }
    }

    pub async fn send_to_gateway_expired(
        &self,
        server_id: u32,
        mut buf: NetPacket<TransmissionBytes>,
        expired: Duration,
    ) -> anyhow::Result<()> {
        let inner = self.inner.load();
        if !inner.server_info_collection.is_server_connected(server_id) {
            bail!("未连接服务器")
        }
        buf.set_gateway_flag(true);
        let sender = inner
            .sender
            .get(&server_id)
            .with_context(|| format!("未找到服务端 {server_id} 的发送通道"))?;
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
        let inner = self.inner.load();
        let server_ids = inner
            .server_info_collection
            .servers_for_ip_by_latency(&inner.server_id_list, &dest_ip);
        if server_ids.is_empty() {
            bail!("not found ip route: {dest_ip}")
        }
        Self::send_expired_impl(&inner, &server_ids, buf, expired)
    }
    fn send_expired_impl(
        inner: &ServerOutboundInner,
        server_ids: &[u32],
        mut buf: NetPacket<TransmissionBytes>,
        expired: Duration,
    ) -> anyhow::Result<()> {
        if !buf.is_gateway() {
            inner.packet_crypto.encrypt_in_place(&mut buf)?;
        }
        let bytes = buf.into_buffer().into_bytes().freeze();
        if try_send_server_candidates(&inner.sender, server_ids, bytes, expired) {
            return Ok(());
        }
        bail!("connect server task failed")
    }

    pub async fn send_raw(&self, dest_ip: Ipv4Addr, buf: NetPacket<Bytes>) -> anyhow::Result<()> {
        let inner = self.inner.load();
        let server_ids = inner
            .server_info_collection
            .servers_for_ip_by_latency(&inner.server_id_list, &dest_ip);
        if server_ids.is_empty() {
            bail!("not found ip route: {dest_ip}")
        }
        let expired = Duration::from_secs(5);
        let bytes = buf.into_buffer();
        if try_send_server_candidates(&inner.sender, &server_ids, bytes, expired) {
            return Ok(());
        }
        bail!("connect server task failed")
    }
    pub async fn send_default_raw(&self, buf: NetPacket<Bytes>) -> anyhow::Result<()> {
        let inner = self.inner.load();
        let server_ids = inner
            .server_info_collection
            .connected_servers_by_latency(&inner.server_id_list);
        if server_ids.is_empty() {
            bail!("not found default route")
        }
        let expired = Duration::from_secs(5);
        let bytes = buf.into_buffer();
        if try_send_server_candidates(&inner.sender, &server_ids, bytes, expired) {
            return Ok(());
        }
        bail!("connect server task failed")
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
        let mut primary_excludes = Some(primary_excludes);
        let mut failed = Vec::new();
        let handles = FuturesUnordered::new();
        let inner = self.inner.load();
        for (index, (server_id, mut target_ips)) in assignments.into_iter().enumerate() {
            if index != 0 {
                target_ips.truncate(255);
            }
            let Some(sender) = inner.sender.get(&server_id).cloned() else {
                failed.extend(target_ips);
                continue;
            };
            let data = buf.clone();
            let excludes = if index == 0 {
                Some(primary_excludes.take().unwrap_or_default())
            } else {
                None
            };
            handles.push(send_broadcast_assignment(
                sender, data, target_ips, excludes, source, expired,
            ));
        }
        let mut handles = handles;
        while let Some((targets, result)) = handles.next().await {
            if result.is_err() {
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
        let handles = FuturesUnordered::new();
        let inner = self.inner.load();
        for (server_id, mut ips) in assignments {
            assigned.extend(ips.iter().copied());
            ips.truncate(255);
            let Some(sender) = inner.sender.get(&server_id).cloned() else {
                failed.extend(ips);
                continue;
            };
            let data = buf.clone();
            handles.push(send_broadcast_assignment(
                sender, data, ips, None, source, expired,
            ));
        }
        let mut handles = handles;
        while let Some((targets, result)) = handles.next().await {
            if result.is_err() {
                failed.extend(targets);
            }
        }
        failed.extend(target_set.difference(&assigned).copied());
        failed.sort_unstable();
        failed.dedup();
        failed
    }
}

fn try_send_server_candidates(
    senders: &HashMap<u32, Sender<(Bytes, Instant)>>,
    server_ids: &[u32],
    bytes: Bytes,
    expired: Duration,
) -> bool {
    server_ids.iter().any(|server_id| {
        senders.get(server_id).is_some_and(|sender| {
            sender
                .try_send((bytes.clone(), Instant::now() + expired))
                .is_ok()
        })
    })
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
    let coverage_sets = coverage
        .iter()
        .map(|(server_id, (ips, _))| (*server_id, ips.iter().copied().collect::<HashSet<_>>()))
        .collect::<HashMap<_, _>>();
    let mut remaining = targets.iter().copied().collect::<HashSet<_>>();
    let mut assignments = Vec::new();
    while !remaining.is_empty() {
        let selected = coverage
            .iter()
            .filter_map(|(server_id, (_, rtt))| {
                let count = coverage_sets[server_id].intersection(&remaining).count();
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
        let mut assigned = remaining
            .iter()
            .filter(|ip| coverage_sets[&server_id].contains(ip))
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

async fn send_broadcast_assignment(
    sender: Sender<(Bytes, Instant)>,
    buf: Bytes,
    targets: Vec<Ipv4Addr>,
    excludes: Option<Vec<Ipv4Addr>>,
    source: Ipv4Addr,
    expired: Duration,
) -> (Vec<Ipv4Addr>, anyhow::Result<()>) {
    let result = if let Some(excludes) = excludes {
        send_exclude_broadcast(sender, buf, &excludes, source, expired).await
    } else {
        send_target_broadcast(sender, &targets, buf, source, expired).await
    };
    (targets, result)
}

async fn send_exclude_broadcast(
    sender: Sender<(Bytes, Instant)>,
    buf: Bytes,
    exclude_ips: &[Ipv4Addr],
    source: Ipv4Addr,
    expired: Duration,
) -> anyhow::Result<()> {
    let broadcast = SelectiveBroadcast::new(exclude_ips, buf);
    let mut packet = NetPacket::new(TransmissionBytes::zeroed(
        HEAD_LENGTH + broadcast.encoded_len(),
    ))?;
    packet.set_msg_type(MsgType::ExcludeBroadcast);
    packet.set_ttl(5);
    packet.set_src_id(source.into());
    let mut payload = packet.payload_mut();
    broadcast.encode(&mut payload)?;

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
    target_ips: &[Ipv4Addr],
    buf: Bytes,
    source: Ipv4Addr,
    expired: Duration,
) -> anyhow::Result<()> {
    let target_broadcast = SelectiveBroadcast::new(target_ips, buf);
    let mut packet = NetPacket::new(TransmissionBytes::zeroed(
        HEAD_LENGTH + target_broadcast.encoded_len(),
    ))?;
    packet.set_msg_type(MsgType::TargetBroadcast);
    packet.set_ttl(5);
    packet.set_src_id(source.into());
    let mut payload = packet.payload_mut();
    target_broadcast.encode(&mut payload)?;

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

    #[tokio::test]
    async fn packet_send_falls_back_without_duplicate_delivery() {
        let (closed_sender, closed_receiver) = tokio::sync::mpsc::channel(1);
        let (healthy_sender, mut healthy_receiver) = tokio::sync::mpsc::channel(1);
        drop(closed_receiver);
        let senders = HashMap::from([(1, closed_sender), (2, healthy_sender)]);

        assert!(try_send_server_candidates(
            &senders,
            &[1, 2],
            Bytes::from_static(b"one-packet"),
            Duration::from_secs(1),
        ));
        assert_eq!(
            healthy_receiver.recv().await.map(|(bytes, _)| bytes),
            Some(Bytes::from_static(b"one-packet"))
        );
        assert!(healthy_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn packet_send_falls_back_when_the_preferred_queue_is_full() {
        let (busy_sender, mut busy_receiver) = tokio::sync::mpsc::channel(1);
        let (healthy_sender, mut healthy_receiver) = tokio::sync::mpsc::channel(1);
        busy_sender
            .try_send((Bytes::from_static(b"occupied"), Instant::now()))
            .unwrap();
        let senders = HashMap::from([(1, busy_sender), (2, healthy_sender)]);

        assert!(try_send_server_candidates(
            &senders,
            &[1, 2],
            Bytes::from_static(b"fallback"),
            Duration::from_secs(1),
        ));
        assert_eq!(
            busy_receiver.recv().await.map(|(bytes, _)| bytes),
            Some(Bytes::from_static(b"occupied"))
        );
        assert_eq!(
            healthy_receiver.recv().await.map(|(bytes, _)| bytes),
            Some(Bytes::from_static(b"fallback"))
        );
    }

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
            &[target],
            inner.clone(),
            source,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        send_exclude_broadcast(sender, inner, &[target], source, Duration::from_secs(1))
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
