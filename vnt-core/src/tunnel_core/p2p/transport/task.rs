use crate::context::config::{PeerAddress, PeerProtocol, TurnRule, turn_ip_for};
use crate::context::nat::MyNatInfo;
use crate::context::{AppState, PacketLossStats, SharedNetworkAddr};
use crate::crypto::PacketCrypto;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::p2p::inbound::P2pInboundHandler;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::p2p::route_table::RouteTable;
use crate::tunnel_core::p2p::transport::nat_test::{
    my_nat_info, query_tcp_public_addr_loop, query_udp_public_addr_loop,
};
use crate::tunnel_core::p2p::transport::punch::{PunchTaskContext, punch_task};
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::utils::task_control::TaskGroup;
use rustp2p_core::endpoint::{Config as TunnelConfig, LengthPrefixedInitCodec, TunnelIncoming};
use rustp2p_core::punch::Puncher;
use rustp2p_core::route_table::Protocol;
use rustp2p_core::socket::LocalInterface;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) struct P2pInitConfig {
    pub tunnel_port: Option<u16>,
    pub automatic_punch: bool,
    pub peer_address: Vec<PeerAddress>,
    pub turn: Arc<Vec<TurnRule>>,
    pub default_interface: Option<LocalInterface>,
}

pub async fn init_tunnel(
    task_group: TaskGroup,
    app_state: AppState,
    tunnel_to_server: ServerOutbound,
    packet_crypto: PacketCrypto,
    config: P2pInitConfig,
) -> anyhow::Result<(Puncher, P2pOutbound, P2pTask)> {
    let tunnel_port = config.tunnel_port.unwrap_or(0);
    let mut tunnel_config = TunnelConfig::new()
        .udp_port(tunnel_port)
        .tcp_port(tunnel_port)
        .tcp_codec(Box::new(LengthPrefixedInitCodec))
        .max_assistant_sockets(82)
        .max_udp_datagram_size(4096);
    if let Some(interface) = config.default_interface.clone() {
        tunnel_config = tunnel_config.default_interface(interface);
    }
    let tunnel_incoming = TunnelIncoming::bind(tunnel_config).await?;
    let puncher = tunnel_incoming.puncher();
    let local_tcp_port = tunnel_incoming
        .local_tcp_addr()
        .map(|addr| addr.port())
        .unwrap_or_default();
    let route_table = app_state.route_table.clone();
    let socket_manager = P2pOutbound::new(puncher.clone(), route_table.clone(), packet_crypto);
    if config.automatic_punch {
        let nat_app_state = app_state.clone();
        let nat_puncher = puncher.clone();
        task_group.spawn(async move {
            my_nat_info(nat_app_state, nat_puncher).await;
        });
        task_group.spawn(query_udp_public_addr_loop(
            app_state.clone(),
            puncher.clone(),
        ));
        task_group.spawn(query_tcp_public_addr_loop(
            app_state.clone(),
            local_tcp_port,
            config.default_interface.clone(),
        ));
    }

    task_group.spawn(route_timeout_task(
        route_table.clone(),
        app_state.packet_loss_stats.clone(),
    ));
    if config.automatic_punch {
        let app_state_for_punch = app_state.clone();
        let punch_ctx = PunchTaskContext {
            network: app_state.network.clone(),
            server_info: app_state.server_info_collection.clone(),
            punch_backoff: app_state.punch_backoff.clone(),
            punch_info_getter: Arc::new(move || app_state_for_punch.get_punch_info()),
            turn: config.turn.clone(),
        };
        task_group.spawn(punch_task(tunnel_to_server, route_table.clone(), punch_ctx));
    }
    task_group.spawn(ping_all(
        app_state.network.clone(),
        app_state.packet_loss_stats.clone(),
        route_table.clone(),
        socket_manager.clone(),
    ));
    task_group.spawn(relay_probe_task(
        app_state.network.clone(),
        route_table.clone(),
        socket_manager.clone(),
        config.turn.clone(),
    ));
    // peer_address 支持域名；域名不在启动时解析，由 direct_peer_probe_task
    // 在每次使用时解析出地址（支持 DNS 变更），解析失败只告警跳过
    for peer in &config.peer_address {
        let protocols: &[Protocol] = match peer.protocol() {
            PeerProtocol::Both => &[Protocol::TCP, Protocol::UDP],
            PeerProtocol::Tcp => &[Protocol::TCP],
            PeerProtocol::Udp => &[Protocol::UDP],
        };
        for &protocol in protocols {
            task_group.spawn(direct_peer_probe_task(
                app_state.network.clone(),
                route_table.clone(),
                socket_manager.clone(),
                protocol,
                peer.clone(),
                config.default_interface.clone(),
            ));
        }
    }
    let p2p_task = P2pTask {
        task_group,
        nat_info: app_state.nat_info.clone(),
        tunnel_incoming,
        outbound: socket_manager.clone(),
    };
    Ok((puncher, socket_manager, p2p_task))
}

async fn direct_peer_probe_task(
    network: SharedNetworkAddr,
    route_table: RouteTable,
    socket_manager: P2pOutbound,
    protocol: Protocol,
    peer: PeerAddress,
    default_interface: Option<LocalInterface>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(src_ip) = network.ip() else {
            continue;
        };
        // peer 可能为域名，每次使用时解析出当前地址（支持 DNS 变化）
        let resolved = match peer.endpoints(&default_interface).await {
            Ok(list) => list,
            Err(error) => {
                log::warn!("failed to resolve peer {peer} for {protocol}: {error}");
                continue;
            }
        };
        let Some(address) = resolved
            .into_iter()
            .find(|(p, _)| *p == protocol)
            .map(|(_, addr)| addr)
        else {
            continue;
        };
        if route_table.has_direct_endpoint(protocol, address) {
            continue;
        }
        let packet = match build_direct_peer_probe(src_ip, socket_manager.encrypt_reserve()) {
            Ok(packet) => packet,
            Err(error) => {
                log::warn!("failed to build direct peer probe for {protocol}://{address}: {error}");
                continue;
            }
        };
        if let Err(error) = socket_manager.send_to_addr(packet, protocol, address).await {
            log::debug!("direct peer probe failed for {protocol}://{address}: {error:?}");
        }
    }
}

fn build_direct_peer_probe(
    src_ip: Ipv4Addr,
    encrypt_reserve: usize,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + 8,
        encrypt_reserve,
    ))?;
    packet.set_msg_type(MsgType::DirectConnectReq);
    packet.set_ttl(1);
    packet.set_src_id(src_ip.into());
    packet.set_dest_id(Ipv4Addr::UNSPECIFIED.into());
    packet.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())?;
    Ok(packet)
}
pub struct P2pTask {
    task_group: TaskGroup,
    nat_info: MyNatInfo,
    tunnel_incoming: TunnelIncoming,
    outbound: P2pOutbound,
}
impl P2pTask {
    pub fn start(self, p2p_inbound_handler: P2pInboundHandler) {
        self.task_group.spawn(tunnel_dispatch_task(
            self.nat_info,
            self.task_group.clone(),
            self.tunnel_incoming,
            self.outbound,
            p2p_inbound_handler,
        ));
    }
}

pub async fn ping_all(
    network: SharedNetworkAddr,
    packet_loss_stats: PacketLossStats,
    route_table: RouteTable,
    socket_manager: P2pOutbound,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let Some(src) = network.ip() else {
            continue;
        };
        let vec = route_table.route_table();

        for (id, list) in vec {
            for (index, route) in list.iter().enumerate() {
                if index > 4 {
                    break;
                }
                let ping = match build_route_ping(
                    src,
                    id,
                    route.metric(),
                    socket_manager.encrypt_reserve(),
                ) {
                    Ok(ping) => ping,
                    Err(error) => {
                        log::warn!("failed to build route probe: {error}");
                        continue;
                    }
                };
                let route_key = route.route_key();
                if socket_manager.send_to(ping, &route_key).await.is_ok() {
                    packet_loss_stats.record_sent(id, route_key);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn build_route_ping(
    src: Ipv4Addr,
    target: Ipv4Addr,
    metric: u8,
    encrypt_reserve: usize,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let mut ping = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + 8,
        encrypt_reserve,
    ))?;
    ping.set_msg_type(MsgType::Ping);
    ping.set_ttl(metric);
    ping.set_src_id(src.into());
    ping.set_dest_id(target.into());
    ping.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())?;
    Ok(ping)
}
pub async fn route_timeout_task(route_table: RouteTable, packet_loss_stats: PacketLossStats) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let expired_time = std::time::Instant::now() - Duration::from_secs(10);
        let removed_keys = route_table.remove_oldest_route(expired_time);
        if !removed_keys.is_empty() {
            packet_loss_stats.remove_batch(&removed_keys);
        }
    }
}

/// 隧道读空闲超时:超过该时长未收到对端数据则回收隧道
const TUNNEL_READ_TIMEOUT: Duration = Duration::from_secs(20);
const RELAY_ROUTE_TARGET: usize = 3;
const RELAY_TARGETS_PER_BATCH: usize = 10;
const RELAY_PROBES_PER_TARGET: usize = 3;
const RELAY_RESPONSE_WAIT: Duration = Duration::from_secs(2);
const RELAY_START_DELAY: Duration = Duration::from_secs(10);
const RELAY_RECONCILE_INTERVAL: Duration = Duration::from_secs(120);
const RELAY_BACKOFF: [Duration; 5] = [
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(300),
];
const RELAY_PROBE_RATE: f64 = 30.0;
const RELAY_PROBE_BURST: f64 = 30.0;

#[derive(Clone, Copy, Debug)]
struct RelayCandidate {
    ip: Ipv4Addr,
    route_key: rustp2p_core::route_table::RouteKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelayProbeAction {
    target_ip: Ipv4Addr,
    relay_ip: Ipv4Addr,
    route_key: rustp2p_core::route_table::RouteKey,
}

#[derive(Debug)]
struct RelayTargetState {
    relay_count: usize,
    attempted_relays: HashSet<Ipv4Addr>,
    next_attempt: Instant,
    backoff_index: usize,
}

#[derive(Debug)]
struct RelayProbeScheduler {
    states: HashMap<Ipv4Addr, RelayTargetState>,
    queue: VecDeque<Ipv4Addr>,
    known_direct_peers: HashSet<Ipv4Addr>,
    tokens: f64,
    last_refill: Instant,
}

impl RelayProbeScheduler {
    fn new(now: Instant) -> Self {
        Self {
            states: HashMap::new(),
            queue: VecDeque::new(),
            known_direct_peers: HashSet::new(),
            tokens: RELAY_PROBE_BURST,
            last_refill: now,
        }
    }

    fn plan(
        &mut self,
        now: Instant,
        src: Ipv4Addr,
        routes: &[(Ipv4Addr, Vec<crate::tunnel_core::p2p::route_table::Route>)],
        turn: &[TurnRule],
    ) -> Vec<RelayProbeAction> {
        self.refill(now);

        let mut candidates = routes
            .iter()
            .filter_map(|(ip, list)| {
                list.iter()
                    .filter(|route| route.is_direct())
                    .max_by_key(|route| route.score())
                    .map(|route| RelayCandidate {
                        ip: *ip,
                        route_key: route.route_key(),
                    })
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|candidate| candidate.ip);

        let direct_peer_ips: HashSet<_> = candidates.iter().map(|candidate| candidate.ip).collect();
        let has_new_direct_peer = direct_peer_ips
            .iter()
            .any(|ip| !self.known_direct_peers.contains(ip));
        self.known_direct_peers = direct_peer_ips.clone();

        let mut eligible = HashMap::new();
        for (ip, list) in routes {
            if *ip == src {
                continue;
            }
            if turn_ip_for(turn, ip).is_some() {
                continue;
            }
            if list.iter().any(|route| route.is_direct()) {
                continue;
            }
            let relay_count = list.iter().filter(|route| !route.is_direct()).count();
            if relay_count < RELAY_ROUTE_TARGET {
                eligible.insert(*ip, relay_count);
            }
        }

        self.states.retain(|ip, _| eligible.contains_key(ip));
        self.queue.retain(|ip| self.states.contains_key(ip));

        for (ip, relay_count) in eligible {
            if let Some(state) = self.states.get_mut(&ip) {
                state
                    .attempted_relays
                    .retain(|relay_ip| direct_peer_ips.contains(relay_ip));
                if relay_count < state.relay_count {
                    state.attempted_relays.clear();
                    state.next_attempt = now;
                    state.backoff_index = 0;
                } else if relay_count > state.relay_count {
                    state.backoff_index = 0;
                }
                if has_new_direct_peer {
                    state.next_attempt = now;
                    state.backoff_index = 0;
                }
                state.relay_count = relay_count;
            } else {
                self.states.insert(
                    ip,
                    RelayTargetState {
                        relay_count,
                        attempted_relays: HashSet::new(),
                        next_attempt: now,
                        backoff_index: 0,
                    },
                );
                self.queue.push_back(ip);
            }
        }

        let mut actions = Vec::new();
        let mut visited = 0;
        let queue_len = self.queue.len();
        let mut processed_targets = 0;
        while visited < queue_len
            && processed_targets < RELAY_TARGETS_PER_BATCH
            && self.tokens >= 1.0
        {
            let Some(target_ip) = self.queue.pop_front() else {
                break;
            };
            visited += 1;
            let Some(state) = self.states.get_mut(&target_ip) else {
                continue;
            };

            if state.next_attempt > now {
                self.queue.push_back(target_ip);
                continue;
            }

            let missing_routes = RELAY_ROUTE_TARGET.saturating_sub(state.relay_count);
            let available = rotated_candidates(&candidates, target_ip)
                .filter(|candidate| !state.attempted_relays.contains(&candidate.ip))
                .take(
                    missing_routes
                        .min(RELAY_PROBES_PER_TARGET)
                        .min(self.tokens.floor() as usize),
                )
                .copied()
                .collect::<Vec<_>>();

            if available.is_empty() {
                state.attempted_relays.clear();
                let delay = RELAY_BACKOFF[state.backoff_index.min(RELAY_BACKOFF.len() - 1)];
                state.backoff_index = (state.backoff_index + 1).min(RELAY_BACKOFF.len() - 1);
                state.next_attempt = now + delay;
                self.queue.push_back(target_ip);
                continue;
            }

            for candidate in available {
                state.attempted_relays.insert(candidate.ip);
                actions.push(RelayProbeAction {
                    target_ip,
                    relay_ip: candidate.ip,
                    route_key: candidate.route_key,
                });
                self.tokens -= 1.0;
            }
            state.next_attempt = now + RELAY_RESPONSE_WAIT;
            processed_targets += 1;
            self.queue.push_back(target_ip);
        }

        actions
    }

    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let deadline = self.states.values().map(|state| state.next_attempt).min()?;
        if deadline <= now && self.tokens < 1.0 {
            let wait = (1.0 - self.tokens) / RELAY_PROBE_RATE;
            Some(now + Duration::from_secs_f64(wait.max(0.001)))
        } else {
            Some(deadline)
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * RELAY_PROBE_RATE).min(RELAY_PROBE_BURST);
        self.last_refill = now;
    }
}

fn rotated_candidates(
    candidates: &[RelayCandidate],
    target_ip: Ipv4Addr,
) -> impl Iterator<Item = &RelayCandidate> {
    let start = if candidates.is_empty() {
        0
    } else {
        u32::from(target_ip) as usize % candidates.len()
    };
    candidates[start..].iter().chain(candidates[..start].iter())
}

fn build_relay_probe(
    src: Ipv4Addr,
    target: Ipv4Addr,
    encrypt_reserve: usize,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let mut probe = NetPacket::new(TransmissionBytes::zeroed_size(HEAD_LENGTH, encrypt_reserve))?;
    probe.set_msg_type(MsgType::RelayProbe);
    probe.set_ttl(2);
    probe.set_src_id(src.into());
    probe.set_dest_id(target.into());
    Ok(probe)
}

/// 事件驱动的客户端中继探测任务。
pub async fn relay_probe_task(
    network: SharedNetworkAddr,
    route_table: RouteTable,
    socket_manager: P2pOutbound,
    turn: Arc<Vec<TurnRule>>,
) {
    let first_direct_route = route_table.first_direct_route_notify();
    tokio::time::sleep(RELAY_START_DELAY).await;
    let mut reconcile = tokio::time::interval_at(
        tokio::time::Instant::now() + RELAY_RECONCILE_INTERVAL,
        RELAY_RECONCILE_INTERVAL,
    );
    reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut scheduler = RelayProbeScheduler::new(Instant::now());
    loop {
        let now = Instant::now();
        if let Some(src) = network.ip() {
            let routes = route_table.route_table();
            let actions = scheduler.plan(now, src, &routes, &turn);
            for action in actions {
                let probe = match build_relay_probe(
                    src,
                    action.target_ip,
                    socket_manager.encrypt_reserve(),
                ) {
                    Ok(probe) => probe,
                    Err(error) => {
                        log::warn!("failed to build relay probe: {error}");
                        continue;
                    }
                };
                if let Err(error) = socket_manager.try_send_to(probe, &action.route_key) {
                    log::debug!(
                        "failed to send relay probe through {} for {}: {error:?}",
                        action.relay_ip,
                        action.target_ip
                    );
                }
            }
        }

        let retry = async {
            if let Some(deadline) = scheduler.next_deadline(Instant::now()) {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(retry);
        tokio::select! {
            _ = first_direct_route.notified() => {}
            _ = reconcile.tick() => {}
            _ = &mut retry => {}
        }
    }
}

/// 隧道收发调度与数据分发
pub async fn tunnel_dispatch_task(
    nat_info: MyNatInfo,
    task_group: TaskGroup,
    mut tunnel_incoming: TunnelIncoming,
    outbound: P2pOutbound,
    p2p_inbound_handler: P2pInboundHandler,
) {
    while let Some(tunnel) = tunnel_incoming.next().await {
        let route_key = tunnel.route_key();
        let protocol = tunnel.protocol();
        let remote_addr = tunnel.remote_addr();
        let (mut reader, writer) = tunnel.split();
        outbound.register_tunnel(route_key, writer.clone());
        log::info!("tunnel {protocol:?}-{remote_addr:?}");
        let p2p_inbound_handler = p2p_inbound_handler.clone();
        let nat_info = nat_info.clone();
        let outbound = outbound.clone();
        task_group.spawn(async move {
            loop {
                // 超过空闲超时仍未收到数据时回收隧道，避免任务与连接长期驻留
                let buf = match tokio::time::timeout(TUNNEL_READ_TIMEOUT, reader.recv()).await {
                    Ok(Some(buf)) => buf,
                    Ok(None) => break,
                    Err(_) => {
                        log::debug!("tunnel {protocol:?}-{remote_addr:?} read idle timeout");
                        break;
                    }
                };
                if protocol.is_udp()
                    && rustp2p_core::stun::is_stun_response(&buf)
                    && let Some(pub_addr) = rustp2p_core::stun::recv_stun_response(&buf)
                {
                    nat_info.update_public_addr(pub_addr);
                    continue;
                }
                p2p_inbound_handler
                    .next_handle(buf.into(), route_key, &writer)
                    .await;
            }
            outbound.remove_tunnel(&route_key);
            p2p_inbound_handler.tunnel_disconnect(route_key);
            log::info!("drop tunnel {protocol:?}-{remote_addr:?}");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_peer(ip: Ipv4Addr) -> (Ipv4Addr, Vec<crate::tunnel_core::p2p::route_table::Route>) {
        (
            ip,
            vec![crate::tunnel_core::p2p::route_table::Route::from(
                rustp2p_core::route_table::RouteKey::default(),
                1,
                10,
            )],
        )
    }

    fn relay_route() -> crate::tunnel_core::p2p::route_table::Route {
        crate::tunnel_core::p2p::route_table::Route::from(
            rustp2p_core::route_table::RouteKey::default(),
            2,
            20,
        )
    }

    fn relay_target(
        ip: Ipv4Addr,
        route_count: usize,
    ) -> (Ipv4Addr, Vec<crate::tunnel_core::p2p::route_table::Route>) {
        (ip, vec![relay_route(); route_count])
    }

    #[test]
    fn direct_peer_probe_uses_unspecified_destination() {
        let source = Ipv4Addr::new(10, 26, 0, 2);
        let packet = build_direct_peer_probe(source, 0).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::DirectConnectReq);
        assert_eq!(Ipv4Addr::from(packet.src_id()), source);
        assert_eq!(Ipv4Addr::from(packet.dest_id()), Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.max_ttl(), 1);
        assert_eq!(packet.ttl(), 1);
        assert_eq!(packet.payload().len(), 8);
    }

    #[test]
    fn relay_probe_packet_uses_two_hop_route() {
        let source = Ipv4Addr::new(10, 26, 0, 2);
        let target = Ipv4Addr::new(10, 26, 0, 9);
        let packet = build_relay_probe(source, target, 0).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::RelayProbe);
        assert_eq!(Ipv4Addr::from(packet.src_id()), source);
        assert_eq!(Ipv4Addr::from(packet.dest_id()), target);
        assert_eq!(packet.max_ttl(), 2);
        assert_eq!(packet.ttl(), 2);
    }

    #[test]
    fn relay_route_ping_uses_route_metric_as_ttl() {
        let source = Ipv4Addr::new(10, 26, 0, 2);
        let target = Ipv4Addr::new(10, 26, 0, 9);
        let packet = build_route_ping(source, target, 2, 0).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::Ping);
        assert_eq!(packet.max_ttl(), 2);
        assert_eq!(packet.ttl(), 2);
    }

    #[test]
    fn relay_scheduler_fairly_covers_more_than_twenty_targets() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let relay = Ipv4Addr::new(10, 0, 0, 2);
        let mut routes = vec![direct_peer(relay)];
        routes.extend((10..40).map(|last| relay_target(Ipv4Addr::new(10, 0, 0, last), 1)));
        let mut scheduler = RelayProbeScheduler::new(now);
        let mut probed = HashSet::new();

        for _ in 0..3 {
            for action in scheduler.plan(now, source, &routes, &[]) {
                probed.insert(action.target_ip);
            }
        }

        assert_eq!(probed.len(), 30);
    }

    #[test]
    fn relay_scheduler_uses_direct_route_even_when_it_is_not_first() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let relay = Ipv4Addr::new(10, 0, 0, 2);
        let target = Ipv4Addr::new(10, 0, 0, 9);
        let routes = vec![
            (
                relay,
                vec![
                    relay_route(),
                    crate::tunnel_core::p2p::route_table::Route::from(
                        rustp2p_core::route_table::RouteKey::default(),
                        1,
                        10,
                    ),
                ],
            ),
            relay_target(target, 1),
        ];
        let mut scheduler = RelayProbeScheduler::new(now);

        let actions = scheduler.plan(now, source, &routes, &[]);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].relay_ip, relay);
    }

    #[test]
    fn relay_scheduler_skips_configured_targets_but_keeps_turn_candidate() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let relay = Ipv4Addr::new(10, 0, 0, 2);
        let configured_target = Ipv4Addr::new(10, 0, 0, 8);
        let normal_target = Ipv4Addr::new(10, 0, 0, 9);
        let routes = vec![
            direct_peer(relay),
            relay_target(configured_target, 1),
            relay_target(normal_target, 1),
        ];
        let turn = vec!["10.0.0.8,10.0.0.2".parse().unwrap()];
        let mut scheduler = RelayProbeScheduler::new(now);

        let actions = scheduler.plan(now, source, &routes, &turn);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].target_ip, normal_target);
        assert_eq!(actions[0].relay_ip, relay);
    }

    #[test]
    fn relay_scheduler_stops_at_three_routes_and_restarts_after_loss() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let relay = Ipv4Addr::new(10, 0, 0, 2);
        let target = Ipv4Addr::new(10, 0, 0, 9);
        let complete_routes = vec![
            direct_peer(relay),
            (target, vec![relay_route(), relay_route(), relay_route()]),
        ];
        let mut scheduler = RelayProbeScheduler::new(now);

        assert!(
            scheduler
                .plan(now, source, &complete_routes, &[])
                .is_empty()
        );

        let reduced_routes = vec![direct_peer(relay), relay_target(target, 2)];
        let actions = scheduler.plan(now, source, &reduced_routes, &[]);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].target_ip, target);
    }

    #[test]
    fn relay_scheduler_rotates_candidates_before_backoff() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let target = Ipv4Addr::new(10, 0, 0, 9);
        let mut routes = (2..6)
            .map(|last| direct_peer(Ipv4Addr::new(10, 0, 0, last)))
            .collect::<Vec<_>>();
        routes.push(relay_target(target, 1));
        let mut scheduler = RelayProbeScheduler::new(now);

        let first = scheduler.plan(now, source, &routes, &[]);
        let second = scheduler.plan(now + RELAY_RESPONSE_WAIT, source, &routes, &[]);
        let attempted: HashSet<_> = first
            .iter()
            .chain(second.iter())
            .map(|action| action.relay_ip)
            .collect();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_eq!(attempted.len(), 4);

        assert!(
            scheduler
                .plan(now + RELAY_RESPONSE_WAIT * 2, source, &routes, &[])
                .is_empty()
        );
        assert_eq!(
            scheduler.next_deadline(now + RELAY_RESPONSE_WAIT * 2),
            Some(now + RELAY_RESPONSE_WAIT * 2 + RELAY_BACKOFF[0])
        );
    }

    #[test]
    fn relay_scheduler_limits_each_batch_to_thirty_packets() {
        let now = Instant::now();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let mut routes = (2..12)
            .map(|last| direct_peer(Ipv4Addr::new(10, 0, 0, last)))
            .collect::<Vec<_>>();
        routes.extend((100..120).map(|last| relay_target(Ipv4Addr::new(10, 0, 0, last), 1)));
        let mut scheduler = RelayProbeScheduler::new(now);

        let first = scheduler.plan(now, source, &routes, &[]);
        let second = scheduler.plan(now, source, &routes, &[]);
        assert_eq!(first.len(), 20);
        assert_eq!(second.len(), 10);
        assert!(scheduler.plan(now, source, &routes, &[]).is_empty());
        assert!(
            scheduler
                .next_deadline(now)
                .is_some_and(|deadline| deadline > now)
        );
    }
}
