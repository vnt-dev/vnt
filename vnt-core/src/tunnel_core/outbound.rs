use crate::compression::PacketCompression;
use crate::context::config::{TurnRule, is_turn_ip, turn_ip_for};
use crate::context::{NetworkAddr, ServerInfoCollection, SharedNetworkAddr, TrafficStats};
use crate::crypto::PacketCrypto;
use crate::fec::FecEncoder;
use crate::nat::subnet_packet::SubnetPacketMapper;
use crate::nat::{AllowSubnetExternalRoute, SubnetExternalRoute, SubnetMappingTable};
use crate::protocol::ProtoToBytesMut;
use crate::protocol::control_message::ClientType;
use crate::protocol::control_message::SelectiveBroadcast;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::p2p::route_table::Route;
use crate::tunnel_core::server::outbound::ServerOutbound;
use anyhow::bail;
use bytes::Bytes;
use parking_lot::Mutex;
use pnet_packet::ipv4::Ipv4Packet;
use rustp2p_core::route_table::RouteKey;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const GRAPH_DEDUP_TTL: Duration = Duration::from_secs(60);
const GRAPH_DEDUP_CAPACITY: usize = 8192;
type GraphMessageKey = (u8, Ipv4Addr, u32);
type GraphSeen = Arc<Mutex<HashMap<GraphMessageKey, Instant>>>;
type BroadcastMessageKey = (Ipv4Addr, u32);

const BROADCAST_DEDUP_TTL: Duration = Duration::from_secs(60);
const BROADCAST_DEDUP_CAPACITY: usize = 8192;
const BROADCAST_TARGET_CAPACITY: usize = 8192;
const MAX_SELECTIVE_BROADCAST_IPS: usize = 255;

#[derive(Default)]
struct BroadcastSeenEntry {
    updated: Option<Instant>,
    delivered: bool,
    targets: HashSet<Ipv4Addr>,
}

type BroadcastSeen = Arc<Mutex<HashMap<BroadcastMessageKey, BroadcastSeenEntry>>>;

#[derive(Copy, Clone, Debug)]
struct BroadcastPath {
    owner: Ipv4Addr,
    route: Route,
}

#[derive(Debug)]
struct BroadcastP2pTask {
    owner: Ipv4Addr,
    route: Route,
    targets: Vec<Ipv4Addr>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PreferredTurn {
    Server,
    Peer(Ipv4Addr),
}

fn preferred_turn(net: NetworkAddr, rules: &[TurnRule], dest: &Ipv4Addr) -> Option<PreferredTurn> {
    if is_turn_ip(rules, dest) {
        return None;
    }
    let turn_ip = turn_ip_for(rules, dest)?;
    if net.gateway == Some(turn_ip) {
        Some(PreferredTurn::Server)
    } else {
        Some(PreferredTurn::Peer(turn_ip))
    }
}

fn relay_msg_type_for(
    client_type: Option<ClientType>,
    allow_ikev2: bool,
    allow_wireguard: bool,
) -> Option<MsgType> {
    match client_type {
        Some(ClientType::Ikev2) if allow_ikev2 => Some(MsgType::Ikev2Relay),
        Some(ClientType::Wireguard) if allow_wireguard => Some(MsgType::WireGuardRelay),
        _ => None,
    }
}

#[derive(Clone)]
pub(crate) struct BasicOutbound {
    server_outbound: ServerOutbound,
    p2p_outbound: Option<P2pOutbound>,
    packet_crypto: PacketCrypto,
    turn: Arc<Vec<TurnRule>>,
    graph_seen: GraphSeen,
    broadcast_seen: BroadcastSeen,
}

impl BasicOutbound {
    pub fn new(
        server_outbound: ServerOutbound,
        p2p_outbound: Option<P2pOutbound>,
        packet_crypto: PacketCrypto,
        turn: Arc<Vec<TurnRule>>,
    ) -> Self {
        Self {
            server_outbound,
            p2p_outbound,
            packet_crypto,
            turn,
            graph_seen: Arc::new(Mutex::new(HashMap::new())),
            broadcast_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 获取加密保留空间大小
    pub fn encrypt_reserve(&self) -> usize {
        self.packet_crypto.encrypt_reserve()
    }

    pub fn fec_auth_reserve(&self) -> usize {
        self.packet_crypto.fec_auth_reserve()
    }

    /// 加密数据包
    pub fn encrypt_in_place(
        &self,
        packet: &mut NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        Ok(self.packet_crypto.encrypt_in_place(packet)?)
    }

    /// 发送原始数据包到指定目标（通过P2P或服务器）
    pub async fn send_raw(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        if !self.try_send_raw(net, dest, packet, None).await? {
            bail!("no route to {dest}")
        }
        Ok(())
    }

    /// Sends one packet using a normal P2P route, a server which currently
    /// advertises the destination, or one deterministic direct peer as an
    /// opportunity-forwarding fallback. `exclude` is the physical ingress
    /// route of a relayed packet; all RouteKeys owned by that peer are skipped.
    pub async fn try_send_raw(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
        exclude: Option<&RouteKey>,
    ) -> anyhow::Result<bool> {
        let preferred = preferred_turn(net, &self.turn, &dest);
        let selected_p2p = self.p2p_outbound.as_ref().and_then(|p2p| match preferred {
            Some(PreferredTurn::Peer(turn_ip)) => {
                p2p.get_direct_route_to_peer(dest, turn_ip, exclude)
            }
            Some(PreferredTurn::Server) => None,
            None => p2p.get_route_by_id_excluding(&dest, exclude),
        });

        let packet = packet.into_bytes();
        if let Some(p2p) = self.p2p_outbound.as_ref() {
            if preferred == Some(PreferredTurn::Server) {
                if self.server_outbound.exists_route(&dest) {
                    self.server_outbound.send_raw(dest, packet).await?;
                    return Ok(true);
                }
                return Ok(false);
            }
            if let Some(route) = selected_p2p {
                p2p.send_raw_to(packet, &route.route_key()).await?;
                return Ok(true);
            }
        }
        if self.server_outbound.exists_route(&dest) {
            self.server_outbound.send_raw(dest, packet).await?;
            return Ok(true);
        }
        if let Some(p2p) = self.p2p_outbound.as_ref()
            && let Some((_peer, route)) = p2p.direct_candidate(dest, exclude)
        {
            p2p.send_raw_to(packet, &route.route_key()).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// 发送到默认服务器
    pub async fn send_default_raw(
        &self,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let bytes = packet.into_buffer().into_bytes().freeze();
        self.server_outbound
            .send_default_raw(NetPacket::new(bytes)?)
            .await
    }

    pub async fn send_server_raw(
        &self,
        dest: Ipv4Addr,
        packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.server_outbound
            .send_raw(dest, packet.into_bytes())
            .await
    }

    /// 检查是否存在到目标的路由
    pub fn exists_route(&self, dest: &Ipv4Addr) -> bool {
        if let Some(p2p) = self.p2p_outbound.as_ref()
            && (p2p.exists_route_by_id(dest) || p2p.direct_candidate(*dest, None).is_some())
        {
            return true;
        }
        self.server_outbound.exists_route(dest)
    }

    /// Floods an already encrypted graph-control packet over all direct
    /// tunnels. The ingress tunnel is excluded to prevent immediate
    /// reflection; sequence based deduplication handles graph cycles.
    pub fn flood_direct_p2p(&self, packet: &NetPacket<Bytes>, exclude: Option<&RouteKey>) -> usize {
        self.p2p_outbound
            .as_ref()
            .map(|p2p| p2p.flood_direct(packet, exclude))
            .unwrap_or(0)
    }

    pub async fn flood_connected_servers(
        &self,
        packet: NetPacket<Bytes>,
        exclude_server: Option<u32>,
    ) -> usize {
        self.server_outbound
            .flood_connected_raw(packet, exclude_server)
            .await
    }

    pub fn is_any_server_connected(&self) -> bool {
        self.server_outbound.is_any_server_connected()
    }

    pub fn graph_first_seen(&self, msg_type: MsgType, source: Ipv4Addr, seq: u32) -> bool {
        let now = Instant::now();
        let mut seen = self.graph_seen.lock();
        seen.retain(|_, time| now.duration_since(*time) < GRAPH_DEDUP_TTL);
        let key = (msg_type as u8, source, seq);
        if seen.contains_key(&key) {
            return false;
        }
        if seen.len() >= GRAPH_DEDUP_CAPACITY
            && let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, time)| **time)
                .map(|(key, _)| *key)
        {
            seen.remove(&oldest);
        }
        seen.insert(key, now);
        true
    }

    /// Marks local delivery independently from target processing. A terminal
    /// Broadcast may arrive through a direct tunnel and a server at the same
    /// time, while disjoint TargetBroadcast shards must still be accepted.
    pub fn broadcast_first_delivery(&self, source: Ipv4Addr, seq: u32) -> bool {
        let now = Instant::now();
        let mut seen = self.broadcast_seen.lock();
        prune_broadcast_seen(&mut seen, now);
        let entry = broadcast_seen_entry(&mut seen, (source, seq), now);
        if entry.delivered {
            return false;
        }
        entry.delivered = true;
        entry.updated = Some(now);
        true
    }

    /// Returns only targets not processed by an earlier shard of this inner
    /// broadcast. Targets are reserved before forwarding, which closes loops
    /// even when overlapping tasks arrive concurrently.
    pub fn take_broadcast_targets(
        &self,
        source: Ipv4Addr,
        seq: u32,
        targets: Vec<Ipv4Addr>,
    ) -> Vec<Ipv4Addr> {
        let now = Instant::now();
        let mut seen = self.broadcast_seen.lock();
        prune_broadcast_seen(&mut seen, now);
        let entry = broadcast_seen_entry(&mut seen, (source, seq), now);
        entry.updated = Some(now);
        let mut fresh = Vec::new();
        for target in targets {
            if entry.targets.len() >= BROADCAST_TARGET_CAPACITY {
                break;
            }
            if entry.targets.insert(target) {
                fresh.push(target);
            }
        }
        fresh
    }

    /// Distributes one encrypted inner Broadcast. `scope` is exact when this
    /// node is relaying a TargetBroadcast; otherwise the current route and
    /// server snapshots define the known target universe.
    pub async fn distribute_broadcast(
        &self,
        net: NetworkAddr,
        packet: NetPacket<Bytes>,
        scope: Option<Vec<Ipv4Addr>>,
        ingress_peer: Option<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let source = Ipv4Addr::from(packet.src_id());
        if !valid_broadcast_ip(&net, source) {
            return Ok(());
        }

        let server_coverage = self.server_outbound.broadcast_coverage();
        let server_union = server_coverage
            .values()
            .flat_map(|(ips, _)| ips.iter().copied())
            .collect::<HashSet<_>>();
        let route_snapshot = self
            .p2p_outbound
            .as_ref()
            .map(P2pOutbound::broadcast_routes)
            .unwrap_or_default();
        let mut paths = HashMap::<Ipv4Addr, Vec<BroadcastPath>>::new();
        for (target, routes) in route_snapshot {
            let candidates = routes
                .into_iter()
                .filter(|(owner, _)| {
                    *owner != source && Some(*owner) != ingress_peer && *owner != net.ip
                })
                .map(|(owner, route)| BroadcastPath { owner, route })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                paths.insert(target, candidates);
            }
        }

        let exact_scope = scope.is_some();
        let mut targets = scope.unwrap_or_else(|| {
            paths
                .keys()
                .copied()
                .chain(server_union.iter().copied())
                .collect()
        });
        targets.retain(|target| *target != source && valid_broadcast_target(&net, *target));
        targets.sort_unstable();
        targets.dedup();
        if targets.is_empty() {
            return Ok(());
        }

        let mut direct = HashMap::new();
        if let Some(p2p) = &self.p2p_outbound {
            for target in &targets {
                if Some(*target) == ingress_peer || *target == source {
                    continue;
                }
                if let Some(route) = p2p.best_direct_route(*target) {
                    direct.insert(*target, route);
                }
            }
        }

        let target_set = targets.iter().copied().collect::<HashSet<_>>();
        let full_server_coverage =
            !exact_scope && !target_set.is_empty() && target_set.is_subset(&server_union);
        if full_server_coverage {
            return self
                .distribute_with_full_server_coverage(net, packet, targets, direct, ingress_peer)
                .await;
        }

        self.distribute_partial(
            net,
            packet,
            targets,
            direct,
            paths,
            server_union,
            HashSet::new(),
        )
        .await
    }

    async fn distribute_with_full_server_coverage(
        &self,
        _net: NetworkAddr,
        packet: NetPacket<Bytes>,
        targets: Vec<Ipv4Addr>,
        direct: HashMap<Ipv4Addr, Route>,
        ingress_peer: Option<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let mut sent_direct = Vec::new();
        if let Some(p2p) = &self.p2p_outbound {
            let mut direct = direct.into_iter().collect::<Vec<_>>();
            direct.sort_by(|left, right| {
                left.1
                    .loss_rate()
                    .cmp(&right.1.loss_rate())
                    .then_with(|| left.1.rtt().cmp(&right.1.rtt()))
                    .then_with(|| left.0.cmp(&right.0))
            });
            for (target, route) in direct.into_iter().take(MAX_SELECTIVE_BROADCAST_IPS) {
                if p2p
                    .send_raw_to(packet.clone(), &route.route_key())
                    .await
                    .is_ok()
                {
                    sent_direct.push(target);
                }
            }
        }
        if sent_direct.len() == targets.len() {
            return Ok(());
        }
        let failed = self
            .server_outbound
            .send_raw_broadcast(Some(sent_direct.clone()), packet.clone())
            .await;
        if !failed.is_empty() {
            let paths = self.broadcast_paths(ingress_peer, Ipv4Addr::from(packet.src_id()));
            self.send_p2p_tasks(_net.ip, packet, failed, &paths, &HashSet::new())
                .await;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn distribute_partial(
        &self,
        net: NetworkAddr,
        packet: NetPacket<Bytes>,
        targets: Vec<Ipv4Addr>,
        direct: HashMap<Ipv4Addr, Route>,
        paths: HashMap<Ipv4Addr, Vec<BroadcastPath>>,
        server_union: HashSet<Ipv4Addr>,
        banned_owners: HashSet<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let direct_targets = direct.keys().copied().collect::<HashSet<_>>();
        let mut server_targets = Vec::new();
        let mut p2p_targets = Vec::new();
        for target in targets {
            if direct_targets.contains(&target) {
                continue;
            }
            if server_union.contains(&target) {
                server_targets.push(target);
            } else {
                p2p_targets.push(target);
            }
        }
        server_targets.sort_by_key(|target| broadcast_target_rank(*target, &paths));

        let mut tasks = plan_p2p_tasks(&p2p_targets, &paths, &banned_owners);
        for task in &mut tasks {
            if direct_targets.contains(&task.owner) && !task.targets.contains(&task.owner) {
                // The relay itself is a one-hop target and therefore outranks
                // every relayed destination when the task is at capacity.
                task.targets.insert(0, task.owner);
                task.targets.truncate(MAX_SELECTIVE_BROADCAST_IPS);
            }
        }
        let relay_owners = tasks.iter().map(|task| task.owner).collect::<HashSet<_>>();
        let mut sent = 0usize;
        let mut retry_targets = Vec::new();
        let mut retry_banned_owners = banned_owners.clone();
        let mut retry_server_allowed = HashSet::new();

        if let Some(p2p) = &self.p2p_outbound {
            for (target, route) in &direct {
                if relay_owners.contains(target) {
                    continue;
                }
                match p2p.send_raw_to(packet.clone(), &route.route_key()).await {
                    Ok(()) => sent += 1,
                    Err(_) => {
                        retry_targets.push(*target);
                        retry_banned_owners.insert(*target);
                        if server_union.contains(target) {
                            retry_server_allowed.insert(*target);
                        }
                    }
                }
            }
        }

        if !server_targets.is_empty() {
            let failed = self
                .server_outbound
                .send_targeted_broadcast(&server_targets, packet.clone())
                .await;
            if failed.len() < server_targets.len() {
                sent += 1;
            }
            retry_targets.extend(failed);
        }

        if let Some(p2p) = &self.p2p_outbound {
            for task in tasks {
                match self.send_p2p_task(p2p, net.ip, packet.clone(), &task).await {
                    Ok(()) => sent += 1,
                    Err(_) => {
                        let failed_targets = task.targets;
                        let mut banned = banned_owners.clone();
                        banned.insert(task.owner);
                        let retry_sent = self
                            .send_p2p_tasks(
                                net.ip,
                                packet.clone(),
                                failed_targets.clone(),
                                &paths,
                                &banned,
                            )
                            .await;
                        sent += usize::from(!retry_sent.is_empty());
                        let server_fallback = failed_targets
                            .into_iter()
                            .filter(|target| {
                                !retry_sent.contains(target) && server_union.contains(target)
                            })
                            .collect::<Vec<_>>();
                        if !server_fallback.is_empty() {
                            let failed = self
                                .server_outbound
                                .send_targeted_broadcast(&server_fallback, packet.clone())
                                .await;
                            if failed.len() < server_fallback.len() {
                                sent += 1;
                            }
                        }
                    }
                }
            }
        }

        // One synchronous retry for direct/server failures: use an alternate
        // P2P owner first, then an exact server task for what P2P cannot cover.
        if !retry_targets.is_empty() {
            let p2p_sent = self
                .send_p2p_tasks(
                    net.ip,
                    packet.clone(),
                    retry_targets,
                    &paths,
                    &retry_banned_owners,
                )
                .await;
            if !p2p_sent.is_empty() {
                sent += 1;
            }
            let server_retry = retry_server_allowed
                .difference(&p2p_sent)
                .copied()
                .collect::<Vec<_>>();
            if !server_retry.is_empty() {
                let failed = self
                    .server_outbound
                    .send_targeted_broadcast(&server_retry, packet)
                    .await;
                if failed.len() < server_retry.len() {
                    sent += 1;
                }
            }
        }

        // Having no currently usable target is a normal broadcast outcome.
        let _ = sent;
        Ok(())
    }

    fn broadcast_paths(
        &self,
        ingress_peer: Option<Ipv4Addr>,
        source: Ipv4Addr,
    ) -> HashMap<Ipv4Addr, Vec<BroadcastPath>> {
        self.p2p_outbound
            .as_ref()
            .map(P2pOutbound::broadcast_routes)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(target, routes)| {
                let routes = routes
                    .into_iter()
                    .filter(|(owner, _)| *owner != source && Some(*owner) != ingress_peer)
                    .map(|(owner, route)| BroadcastPath { owner, route })
                    .collect::<Vec<_>>();
                (!routes.is_empty()).then_some((target, routes))
            })
            .collect()
    }

    async fn send_p2p_tasks(
        &self,
        local_ip: Ipv4Addr,
        packet: NetPacket<Bytes>,
        targets: Vec<Ipv4Addr>,
        paths: &HashMap<Ipv4Addr, Vec<BroadcastPath>>,
        banned_owners: &HashSet<Ipv4Addr>,
    ) -> HashSet<Ipv4Addr> {
        let Some(p2p) = &self.p2p_outbound else {
            return HashSet::new();
        };
        let mut sent = HashSet::new();
        for task in plan_p2p_tasks(&targets, paths, banned_owners) {
            if self
                .send_p2p_task(p2p, local_ip, packet.clone(), &task)
                .await
                .is_ok()
            {
                sent.extend(task.targets);
            }
        }
        sent
    }

    async fn send_p2p_task(
        &self,
        p2p: &P2pOutbound,
        local_ip: Ipv4Addr,
        inner: NetPacket<Bytes>,
        task: &BroadcastP2pTask,
    ) -> anyhow::Result<()> {
        let payload =
            SelectiveBroadcast::new(&task.targets, inner.source_buf().to_vec()).encode_bytes_mut();
        let mut outer = NetPacket::new(TransmissionBytes::zeroed_size(
            HEAD_LENGTH + payload.len(),
            p2p.encrypt_reserve(),
        ))?;
        outer.set_msg_type(MsgType::TargetBroadcast);
        outer.set_ttl(1);
        outer.set_src_id(local_ip.into());
        outer.set_dest_id(task.owner.into());
        outer.payload_mut().copy_from_slice(&payload);
        p2p.send_to(outer, &task.route.route_key()).await
    }

    /// 发送加密后的数据包
    pub async fn send_encrypted_packet(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.packet_crypto.encrypt_in_place(&mut packet)?;
        self.send_raw(net, dest, packet).await
    }

    /// 认证并发送 FEC 外层包。FEC 内层已经是普通 AEAD 密文或 QUIC 密文，
    /// 外层只追加认证标签，不再重复加密。
    pub async fn send_fec_packet(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        self.packet_crypto.authenticate_fec_in_place(&mut packet)?;
        self.send_raw(net, dest, packet).await
    }
}

fn prune_broadcast_seen(seen: &mut HashMap<BroadcastMessageKey, BroadcastSeenEntry>, now: Instant) {
    seen.retain(|_, entry| {
        entry
            .updated
            .is_some_and(|updated| now.duration_since(updated) < BROADCAST_DEDUP_TTL)
    });
    while seen.len() >= BROADCAST_DEDUP_CAPACITY {
        let Some(oldest) = seen
            .iter()
            .min_by_key(|(_, entry)| entry.updated)
            .map(|(key, _)| *key)
        else {
            break;
        };
        seen.remove(&oldest);
    }
}

fn broadcast_seen_entry(
    seen: &mut HashMap<BroadcastMessageKey, BroadcastSeenEntry>,
    key: BroadcastMessageKey,
    now: Instant,
) -> &mut BroadcastSeenEntry {
    seen.entry(key).or_insert_with(|| BroadcastSeenEntry {
        updated: Some(now),
        ..BroadcastSeenEntry::default()
    })
}

fn valid_broadcast_ip(net: &NetworkAddr, ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && ip != net.network().network()
        && ip != net.broadcast
        && net.network().contains(&ip)
}

fn valid_broadcast_target(net: &NetworkAddr, ip: Ipv4Addr) -> bool {
    ip != net.ip && valid_broadcast_ip(net, ip)
}

fn path_quality_cmp(left: &BroadcastPath, right: &BroadcastPath) -> std::cmp::Ordering {
    left.route
        .score()
        .cmp(&right.route.score())
        .then_with(|| right.route.loss_rate().cmp(&left.route.loss_rate()))
        .then_with(|| right.route.rtt().cmp(&left.route.rtt()))
}

fn broadcast_target_rank(
    target: Ipv4Addr,
    paths: &HashMap<Ipv4Addr, Vec<BroadcastPath>>,
) -> (u8, u16, u32, Ipv4Addr) {
    paths
        .get(&target)
        .and_then(|candidates| {
            candidates
                .iter()
                .map(|path| {
                    (
                        path.route.metric(),
                        path.route.loss_rate(),
                        path.route.rtt(),
                        target,
                    )
                })
                .min()
        })
        .unwrap_or((u8::MAX, u16::MAX, u32::MAX, target))
}

fn plan_p2p_tasks(
    targets: &[Ipv4Addr],
    paths: &HashMap<Ipv4Addr, Vec<BroadcastPath>>,
    banned_owners: &HashSet<Ipv4Addr>,
) -> Vec<BroadcastP2pTask> {
    let mut candidates = HashMap::<Ipv4Addr, Vec<BroadcastPath>>::new();
    for target in targets {
        let Some(target_paths) = paths.get(target) else {
            continue;
        };
        let Some(min_metric) = target_paths
            .iter()
            .filter(|path| !banned_owners.contains(&path.owner))
            .map(|path| path.route.metric())
            .min()
        else {
            continue;
        };
        let mut best_by_owner = HashMap::<Ipv4Addr, BroadcastPath>::new();
        for path in target_paths.iter().copied().filter(|path| {
            path.route.metric() == min_metric && !banned_owners.contains(&path.owner)
        }) {
            best_by_owner
                .entry(path.owner)
                .and_modify(|current| {
                    if path_quality_cmp(&path, current).is_gt() {
                        *current = path;
                    }
                })
                .or_insert(path);
        }
        if !best_by_owner.is_empty() {
            candidates.insert(*target, best_by_owner.into_values().collect());
        }
    }

    let mut remaining = candidates.keys().copied().collect::<HashSet<_>>();
    let mut tasks = Vec::new();
    while !remaining.is_empty() {
        let mut owner_stats = HashMap::<Ipv4Addr, (usize, u64, u64)>::new();
        for target in &remaining {
            for path in &candidates[target] {
                let stat = owner_stats.entry(path.owner).or_default();
                stat.0 += 1;
                stat.1 += u64::from(path.route.score());
                stat.2 += u64::from(path.route.metric());
            }
        }
        let Some((owner, _)) = owner_stats.into_iter().max_by(|left, right| {
            left.1
                .0
                .cmp(&right.1.0)
                .then_with(|| left.1.1.cmp(&right.1.1))
                .then_with(|| right.1.2.cmp(&left.1.2))
                .then_with(|| right.0.cmp(&left.0))
        }) else {
            break;
        };

        let mut covered = remaining
            .iter()
            .filter_map(|target| {
                candidates[target]
                    .iter()
                    .find(|path| path.owner == owner)
                    .copied()
                    .map(|path| (*target, path))
            })
            .collect::<Vec<_>>();
        covered.sort_by(|left, right| {
            left.1
                .route
                .metric()
                .cmp(&right.1.route.metric())
                .then_with(|| left.1.route.loss_rate().cmp(&right.1.route.loss_rate()))
                .then_with(|| left.1.route.rtt().cmp(&right.1.route.rtt()))
                .then_with(|| left.0.cmp(&right.0))
        });
        // A single owner gets at most one task. Targets beyond the protocol
        // limit are intentionally dropped, not split or returned to flooding.
        let route = covered
            .iter()
            .map(|(_, path)| *path)
            .max_by(path_quality_cmp)
            .expect("selected broadcast owner must cover at least one target")
            .route;
        for (target, _) in &covered {
            remaining.remove(target);
        }
        let target_list = covered
            .into_iter()
            .take(MAX_SELECTIVE_BROADCAST_IPS)
            .map(|(target, _)| target)
            .collect::<Vec<_>>();
        tasks.push(BroadcastP2pTask {
            owner,
            route,
            targets: target_list,
        });
    }
    tasks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(metric: u8, rtt: u32, loss: u16) -> Route {
        Route::from_with_loss(RouteKey::default(), metric, rtt, loss)
    }

    #[test]
    fn configured_gateway_turn_forces_server_and_peer_turn_stays_p2p() {
        let rules = vec!["10.26.1.0/24,10.26.0.1".parse().unwrap()];
        let target = Ipv4Addr::new(10, 26, 1, 9);
        let network = NetworkAddr {
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
            broadcast: Ipv4Addr::new(10, 26, 255, 255),
            ip: Ipv4Addr::new(10, 26, 0, 8),
            prefix_len: 16,
        };
        assert_eq!(
            preferred_turn(network, &rules, &target),
            Some(PreferredTurn::Server)
        );
        let peer_network = NetworkAddr {
            gateway: Some(Ipv4Addr::new(10, 26, 0, 254)),
            ..network
        };
        assert_eq!(
            preferred_turn(peer_network, &rules, &target),
            Some(PreferredTurn::Peer(Ipv4Addr::new(10, 26, 0, 1)))
        );
        assert_eq!(
            preferred_turn(network, &rules, &network.gateway.unwrap()),
            None
        );
    }

    #[test]
    fn relay_message_type_respects_independent_capabilities() {
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Ikev2), true, false),
            Some(MsgType::Ikev2Relay)
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Wireguard), false, true),
            Some(MsgType::WireGuardRelay)
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Ikev2), false, true),
            None
        );
        assert_eq!(
            relay_msg_type_for(Some(ClientType::Wireguard), true, false),
            None
        );
        assert_eq!(relay_msg_type_for(Some(ClientType::Vnt), true, true), None);
    }

    #[test]
    fn p2p_broadcast_planner_uses_only_shortest_paths_and_greedy_owner() {
        let a = Ipv4Addr::new(10, 0, 0, 2);
        let b = Ipv4Addr::new(10, 0, 0, 3);
        let x = Ipv4Addr::new(10, 0, 0, 10);
        let y = Ipv4Addr::new(10, 0, 0, 11);
        let z = Ipv4Addr::new(10, 0, 0, 12);
        let paths = HashMap::from([
            (
                x,
                vec![
                    BroadcastPath {
                        owner: a,
                        route: route(2, 20, 0),
                    },
                    BroadcastPath {
                        owner: b,
                        route: route(3, 1, 0),
                    },
                ],
            ),
            (
                y,
                vec![BroadcastPath {
                    owner: a,
                    route: route(2, 30, 0),
                }],
            ),
            (
                z,
                vec![BroadcastPath {
                    owner: b,
                    route: route(2, 10, 0),
                }],
            ),
        ]);
        let tasks = plan_p2p_tasks(&[x, y, z], &paths, &HashSet::new());
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].owner, a);
        assert_eq!(tasks[0].targets, vec![x, y]);
        assert_eq!(tasks[1].owner, b);
        assert_eq!(tasks[1].targets, vec![z]);
    }

    #[test]
    fn p2p_broadcast_task_is_not_split_beyond_255_targets() {
        let owner = Ipv4Addr::new(10, 0, 0, 2);
        let targets = (1..=300)
            .map(|value| Ipv4Addr::from(0x0a00_1000u32 + value))
            .collect::<Vec<_>>();
        let paths = targets
            .iter()
            .copied()
            .map(|target| {
                (
                    target,
                    vec![BroadcastPath {
                        owner,
                        route: route(2, 20, 0),
                    }],
                )
            })
            .collect::<HashMap<_, _>>();
        let tasks = plan_p2p_tasks(&targets, &paths, &HashSet::new());
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].targets.len(), 255);
    }

    #[test]
    fn target_aware_state_accepts_disjoint_shards_and_one_delivery() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let mut seen = HashMap::new();
        let entry = broadcast_seen_entry(&mut seen, (source, 7), now);
        assert!(entry.targets.insert(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(!entry.targets.insert(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(entry.targets.insert(Ipv4Addr::new(10, 0, 0, 3)));
        assert!(!entry.delivered);
        entry.delivered = true;
        assert!(entry.delivered);
    }
}

#[derive(Clone)]
pub(crate) struct HybridOutbound {
    network: SharedNetworkAddr,
    server_info: ServerInfoCollection,
    traffic_stats: TrafficStats,
    basic_outbound: BasicOutbound,
    packet_compression: PacketCompression,
    external_route: SubnetExternalRoute,
    subnet_mapping: SubnetMappingTable,
    subnet_packet_mapper: SubnetPacketMapper,
    relay_subnets: AllowSubnetExternalRoute,
    fec_encoder: Option<FecEncoder>,
    no_broadcast: bool,
    allow_ikev2: bool,
    allow_wireguard: bool,
}
impl HybridOutbound {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: SharedNetworkAddr,
        server_info: ServerInfoCollection,
        traffic_stats: TrafficStats,
        basic_outbound: BasicOutbound,
        packet_compression: PacketCompression,
        external_route: SubnetExternalRoute,
        subnet_mapping: SubnetMappingTable,
        subnet_packet_mapper: SubnetPacketMapper,
        relay_subnets: AllowSubnetExternalRoute,
        fec_encoder: Option<FecEncoder>,
    ) -> Self {
        Self {
            network,
            server_info,
            traffic_stats,
            basic_outbound,
            packet_compression,
            external_route,
            subnet_mapping,
            subnet_packet_mapper,
            relay_subnets,
            fec_encoder,
            no_broadcast: false,
            allow_ikev2: false,
            allow_wireguard: false,
        }
    }

    pub fn with_no_broadcast(mut self, no_broadcast: bool) -> Self {
        self.no_broadcast = no_broadcast;
        self
    }
    pub fn with_allow_ikev2(mut self, allow_ikev2: bool) -> Self {
        self.allow_ikev2 = allow_ikev2;
        self
    }

    pub fn with_allow_wireguard(mut self, allow_wireguard: bool) -> Self {
        self.allow_wireguard = allow_wireguard;
        self
    }
    pub fn is_relay_client(&self, ip: &Ipv4Addr) -> bool {
        self.relay_msg_type(ip).is_some()
    }
    fn relay_msg_type(&self, ip: &Ipv4Addr) -> Option<MsgType> {
        relay_msg_type_for(
            self.server_info.client_type(ip),
            self.allow_ikev2,
            self.allow_wireguard,
        )
    }
    pub async fn server_relay_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let Some(msg_type) = self.relay_msg_type(&dest) else {
            return Ok(());
        };
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let header_length = ipv4.get_header_length() as usize * 4;
        let total_length = ipv4.get_total_length() as usize;
        if header_length < Ipv4Packet::minimum_packet_size()
            || total_length < header_length
            || total_length > data.len()
            || (ipv4.get_source() != net.ip && !self.relay_subnets.allow(&ipv4.get_source()))
            || (ipv4.get_destination() != dest
                && self.external_route.route(&ipv4.get_destination()) != Some(dest))
        {
            return Ok(());
        }
        if total_length < data.len() {
            let trailing = data.len() - total_length;
            data.shrink_end(trailing);
        }
        let len = data.len() as u64;
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(msg_type);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(dest.into());
        packet.set_ttl(15);
        self.basic_outbound.send_server_raw(dest, packet).await?;
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }
    pub async fn outbound_raw(
        &self,
        dest: Ipv4Addr,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> anyhow::Result<()> {
        let Some(net) = self.network.get() else {
            bail!("Not src ip")
        };
        if packet.src_id() == 0 {
            packet.set_src_id(net.ip.into());
        }

        let len = packet.buffer().len() as u64;

        if let Some(fec_encoder) = &self.fec_encoder {
            packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound.send_raw(net, dest, packet).await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }
    pub async fn ipv4_outbound_common(&self, data: TransmissionBytes) -> anyhow::Result<()> {
        let Some(net) = self.network.get() else {
            bail!("Not src ip")
        };
        self.ipv4_outbound(net, data).await
    }
    pub async fn ipv4_outbound(
        &self,
        net: NetworkAddr,
        data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let source = ipv4.get_source();
        let mut dest = ipv4.get_destination();
        let len = data.len() as u64;
        let dest_is_overlay = net.network().contains(&dest);
        if !dest_is_overlay {
            if let Some(v) = self.external_route.route(&dest) {
                dest = v;
            } else {
                return Ok(());
            }
        }
        // On an output node, replies leave the physical network with their real
        // source. Restore the mapped source immediately before tunnelling them
        // back to the overlay peer. Access-side packets remain untouched.
        let packets = if dest_is_overlay {
            if let Some(mapped) = self.subnet_mapping.reverse(source) {
                self.subnet_packet_mapper
                    .map_source(dest, data, 0, source, mapped)?
            } else {
                vec![data]
            }
        } else {
            vec![data]
        };
        if self.is_relay_client(&dest) {
            for data in packets {
                self.server_relay_outbound(net, data, dest).await?;
            }
            return Ok(());
        }
        for data in packets {
            self.ipv4_outbound_to(net, data, dest).await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }

    async fn ipv4_outbound_to(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
        dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_ttl(15);
        packet.set_dest_id(dest.into());

        packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;

        if let Some(fec_encoder) = &self.fec_encoder {
            self.basic_outbound.encrypt_in_place(&mut packet)?;
            packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound
                .send_encrypted_packet(net, dest, packet)
                .await?;
        }
        Ok(())
    }

    pub async fn ethernet_ipv4_outbound(
        &self,
        net: NetworkAddr,
        data: TransmissionBytes,
        mut dest: Ipv4Addr,
    ) -> anyhow::Result<()> {
        if self.is_relay_client(&dest) {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.server_relay_outbound(net, ip, dest).await;
        }
        if net.gateway == Some(dest) {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.ipv4_gateway_outbound(net, ip).await;
        }
        if dest.is_multicast() || dest == net.broadcast || dest.is_broadcast() {
            if self.no_broadcast {
                return Ok(());
            }
            return self.ethernet_broadcast_outbound(net, data).await;
        }
        let dest_is_overlay = net.network().contains(&dest);
        if !dest_is_overlay {
            if let Some(route) = self.external_route.route(&dest) {
                dest = route;
            } else {
                return Ok(());
            }
        }
        if self.is_relay_client(&dest) {
            let Some(ip) = crate::ethernet::strip_ipv4(data) else {
                return Ok(());
            };
            return self.server_relay_outbound(net, ip, dest).await;
        }
        let packets = if dest_is_overlay {
            let Some(frame) = crate::ethernet::parse_frame(data.as_ref()) else {
                return Ok(());
            };
            let Some(ipv4) = Ipv4Packet::new(&data[frame.payload_offset..]) else {
                return Ok(());
            };
            let source = ipv4.get_source();
            if let Some(mapped) = self.subnet_mapping.reverse(source) {
                self.subnet_packet_mapper.map_source(
                    dest,
                    data,
                    frame.payload_offset,
                    source,
                    mapped,
                )?
            } else {
                vec![data]
            }
        } else {
            vec![data]
        };
        for packet in packets {
            self.ethernet_unicast_outbound(net, dest, packet).await?;
        }
        Ok(())
    }

    pub async fn ethernet_unicast_outbound(
        &self,
        net: NetworkAddr,
        dest: Ipv4Addr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        let len = data.len() as u64;
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(dest.into());
        packet.set_ttl(15);
        packet.set_ethernet_flag(true);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        if let Some(fec_encoder) = &self.fec_encoder {
            self.basic_outbound.encrypt_in_place(&mut packet)?;
            let packet = fec_encoder.encode(packet)?;
            self.basic_outbound
                .send_fec_packet(net, dest, packet)
                .await?;
        } else {
            self.basic_outbound
                .send_encrypted_packet(net, dest, packet)
                .await?;
        }
        self.traffic_stats.record_tx(dest, len);
        Ok(())
    }
    pub async fn ipv4_gateway_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Turn);
        packet.set_src_id(net.ip.into());
        let Some(gateway) = net.gateway else {
            return Ok(());
        };
        packet.set_dest_id(gateway.into());
        packet.set_ttl(15);
        packet.set_gateway_flag(true);
        self.basic_outbound.send_default_raw(packet).await?;
        Ok(())
    }
    pub async fn ipv4_broadcast_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Broadcast);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(Ipv4Addr::BROADCAST.into());
        packet.set_ttl(15);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        self.basic_outbound
            .distribute_broadcast(net, packet_bytes, None, None)
            .await
    }

    pub async fn ethernet_broadcast_outbound(
        &self,
        net: NetworkAddr,
        mut data: TransmissionBytes,
    ) -> anyhow::Result<()> {
        data.retreat_head(HEAD_LENGTH)?;
        let mut packet = NetPacket::new(data)?;
        packet.set_msg_type(MsgType::Broadcast);
        packet.set_src_id(net.ip.into());
        packet.set_dest_id(Ipv4Addr::BROADCAST.into());
        packet.set_ttl(15);
        packet.set_ethernet_flag(true);
        let mut packet = self
            .packet_compression
            .compress(packet, self.basic_outbound.encrypt_reserve())?;
        self.basic_outbound.encrypt_in_place(&mut packet)?;
        let packet_bytes = packet.into_bytes();
        self.basic_outbound
            .distribute_broadcast(net, packet_bytes, None, None)
            .await
    }
    pub fn has_route(&self, dest: &Ipv4Addr) -> bool {
        self.basic_outbound.exists_route(dest)
    }

    pub fn no_broadcast(&self) -> bool {
        self.no_broadcast
    }
}
