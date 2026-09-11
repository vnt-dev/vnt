use crate::context::config::{PeerAddress, PeerProtocol, TurnRule};
use crate::context::nat::MyNatInfo;
use crate::context::{AppState, PacketLossStats, SharedNetworkAddr};
use crate::crypto::PacketCrypto;
use crate::protocol::client_message::{
    MAX_ANNOUNCED_DIRECT_PEERS, NodeAnnouncement, NodeIdentityTemplate, PeerHandshake,
};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::BasicOutbound;
use crate::tunnel_core::p2p::inbound::P2pInboundHandler;
use crate::tunnel_core::p2p::outbound::P2pOutbound;
use crate::tunnel_core::p2p::route_table::RouteTable;
use crate::tunnel_core::p2p::transport::nat_test::{
    my_nat_info, query_tcp_public_addr_loop, query_udp_public_addr_loop,
};
use crate::tunnel_core::p2p::transport::punch::{PunchTaskContext, punch_task};
use crate::tunnel_core::server::outbound::ServerOutbound;
use crate::utils::task_control::TaskGroup;
use rand::seq::SliceRandom;
use rustp2p_core::endpoint::{Config as TunnelConfig, LengthPrefixedInitCodec, TunnelIncoming};
use rustp2p_core::punch::Puncher;
use rustp2p_core::route_table::Protocol;
use rustp2p_core::socket::LocalInterface;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct P2pInitConfig {
    pub tunnel_addr: Vec<SocketAddr>,
    pub tunnel_port: Option<u16>,
    pub automatic_punch: bool,
    pub auto_sync_subnet: bool,
    pub peer_address: Vec<PeerAddress>,
    pub turn: Arc<Vec<TurnRule>>,
    pub default_interface: Option<LocalInterface>,
    pub identity: NodeIdentityTemplate,
}

pub async fn init_tunnel(
    task_group: TaskGroup,
    app_state: AppState,
    tunnel_to_server: ServerOutbound,
    packet_crypto: PacketCrypto,
    config: P2pInitConfig,
) -> anyhow::Result<(Puncher, P2pOutbound, P2pTask)> {
    let tunnel_port = config
        .tunnel_addr
        .first()
        .map(SocketAddr::port)
        .or(config.tunnel_port)
        .unwrap_or(0);
    let mut tunnel_config = TunnelConfig::new()
        .udp_port(tunnel_port)
        .tcp_port(tunnel_port)
        .tcp_codec(Box::new(LengthPrefixedInitCodec))
        .max_assistant_sockets(82)
        .max_udp_datagram_size(4096);
    for addr in &config.tunnel_addr {
        tunnel_config = match addr {
            SocketAddr::V4(addr) => tunnel_config.bind_ipv4(*addr.ip()),
            SocketAddr::V6(addr) => tunnel_config.bind_ipv6(*addr.ip()),
        };
    }
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
        app_state.subnet_route.clone(),
        config.auto_sync_subnet,
    ));
    if config.automatic_punch {
        let app_state_for_punch = app_state.clone();
        let punch_ctx = PunchTaskContext {
            network: app_state.network.clone(),
            server_info: app_state.server_info_collection.clone(),
            punch_backoff: app_state.punch_backoff.clone(),
            punch_info_getter: Arc::new(move |target| app_state_for_punch.get_punch_info(target)),
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
                config.identity.clone(),
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

pub(crate) async fn node_announcement_task(
    network: SharedNetworkAddr,
    outbound: BasicOutbound,
    route_table: RouteTable,
    identity: NodeIdentityTemplate,
) {
    loop {
        let jitter = 25 + (rand::random::<u64>() % 11);
        tokio::time::sleep(Duration::from_secs(jitter)).await;
        let Some(ip) = network.ip() else {
            continue;
        };
        let payload = NodeAnnouncement {
            identity: identity.with_ip(ip),
            direct_peer_ips: sample_direct_peer_ips(route_table.direct_peer_ips()),
        }
        .encode();
        let packet = (|| -> anyhow::Result<_> {
            let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
                HEAD_LENGTH + payload.len(),
                outbound.encrypt_reserve(),
            ))?;
            packet.set_msg_type(MsgType::NodeAnnouncement);
            packet.set_ttl(15);
            packet.set_src_id(ip.into());
            packet.set_dest_id(Ipv4Addr::BROADCAST.into());
            packet.set_payload(&payload)?;
            Ok(packet)
        })();
        match packet {
            Ok(mut packet) => {
                if let Err(error) = outbound.encrypt_in_place(&mut packet) {
                    log::debug!("failed to encrypt node announcement: {error}");
                    continue;
                }
                let packet = packet.into_bytes();
                outbound.graph_first_seen(MsgType::NodeAnnouncement, ip, packet.seq());
                let sent = outbound.flood_direct_p2p(&packet, None);
                outbound.flood_connected_servers(packet, None).await;
                log::trace!("node announcement sent to {sent} direct peers");
            }
            Err(error) => log::debug!("failed to build node announcement: {error}"),
        }
    }
}

fn sample_direct_peer_ips(mut peers: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    peers.shuffle(&mut rand::rng());
    peers.truncate(MAX_ANNOUNCED_DIRECT_PEERS);
    peers
}

async fn direct_peer_probe_task(
    network: SharedNetworkAddr,
    route_table: RouteTable,
    socket_manager: P2pOutbound,
    protocol: Protocol,
    peer: PeerAddress,
    default_interface: Option<LocalInterface>,
    identity: NodeIdentityTemplate,
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
        let addresses = resolved_peer_addresses(resolved, protocol);
        let attempts = addresses
            .into_iter()
            .filter(|address| !route_table.has_direct_endpoint(protocol, *address))
            .map(|address| {
                let socket_manager = socket_manager.clone();
                let identity = identity.clone();
                async move {
                    let packet = match build_direct_peer_probe(
                        src_ip,
                        socket_manager.encrypt_reserve(),
                        &identity,
                    ) {
                        Ok(packet) => packet,
                        Err(error) => {
                            log::warn!(
                                "failed to build direct peer probe for {protocol}://{address}: {error}"
                            );
                            return;
                        }
                    };
                    if let Err(error) = socket_manager
                        .send_to_addr(packet, protocol, address)
                        .await
                    {
                        log::debug!(
                            "direct peer probe failed for {protocol}://{address}: {error:?}"
                        );
                    }
                }
            });
        // 同一域名的多个候选地址并行探测，避免首个不可达地址阻塞后续地址。
        futures::future::join_all(attempts).await;
    }
}

fn resolved_peer_addresses(
    resolved: Vec<(Protocol, SocketAddr)>,
    protocol: Protocol,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    resolved
        .into_iter()
        .filter_map(|(resolved_protocol, address)| {
            (resolved_protocol == protocol && seen.insert(address)).then_some(address)
        })
        .collect()
}

fn build_direct_peer_probe(
    src_ip: Ipv4Addr,
    encrypt_reserve: usize,
    identity: &NodeIdentityTemplate,
) -> anyhow::Result<NetPacket<TransmissionBytes>> {
    let payload = PeerHandshake {
        identity: identity.with_ip(src_ip),
        request_id: rand::random(),
    }
    .encode();
    let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(
        HEAD_LENGTH + payload.len(),
        encrypt_reserve,
    ))?;
    packet.set_msg_type(MsgType::DirectConnectReq);
    packet.set_ttl(1);
    packet.set_src_id(src_ip.into());
    packet.set_dest_id(Ipv4Addr::UNSPECIFIED.into());
    packet.set_payload(&payload)?;
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
                if index > 4 && !route.is_direct() {
                    continue;
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
pub async fn route_timeout_task(
    route_table: RouteTable,
    packet_loss_stats: PacketLossStats,
    subnet_route: crate::nat::SubnetExternalRoute,
    auto_sync_subnet: bool,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let expired_time = std::time::Instant::now() - Duration::from_secs(10);
        let removed_keys = route_table.remove_oldest_route(expired_time);
        if !removed_keys.is_empty() {
            packet_loss_stats.remove_batch(&removed_keys);
            if auto_sync_subnet {
                let routes = route_table
                    .node_infos()
                    .into_iter()
                    .flat_map(|node| {
                        node.advertised_subnets
                            .into_iter()
                            .map(move |net| crate::nat::NetInput {
                                net,
                                target_ip: node.ip,
                            })
                    })
                    .collect();
                subnet_route.set_gossip_routes(routes);
            }
        }
    }
}

/// 隧道读空闲超时:超过该时长未收到对端数据则回收隧道
const TUNNEL_READ_TIMEOUT: Duration = Duration::from_secs(20);

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

    #[test]
    fn direct_peer_probe_uses_unspecified_destination() {
        let source = Ipv4Addr::new(10, 26, 0, 2);
        let identity = NodeIdentityTemplate::default();
        let packet = build_direct_peer_probe(source, 0, &identity).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::DirectConnectReq);
        assert_eq!(Ipv4Addr::from(packet.src_id()), source);
        assert_eq!(Ipv4Addr::from(packet.dest_id()), Ipv4Addr::UNSPECIFIED);
        assert_eq!(packet.max_ttl(), 1);
        assert_eq!(packet.ttl(), 1);
        let handshake = PeerHandshake::from_slice(packet.payload()).unwrap();
        assert_eq!(handshake.identity.ip, source);
        assert_ne!(handshake.request_id, 0);
    }

    #[test]
    fn direct_peer_probe_keeps_all_resolved_addresses_for_protocol() {
        let first: SocketAddr = "192.0.2.1:29872".parse().unwrap();
        let second: SocketAddr = "[2001:db8::1]:29872".parse().unwrap();
        let endpoints = vec![
            (Protocol::TCP, first),
            (Protocol::UDP, first),
            (Protocol::TCP, second),
            (Protocol::TCP, first),
        ];

        assert_eq!(
            resolved_peer_addresses(endpoints, Protocol::TCP),
            vec![first, second]
        );
    }

    #[test]
    fn announcement_samples_at_most_three_unique_direct_peers() {
        let peers = (2..=8)
            .map(|last| Ipv4Addr::new(10, 26, 0, last))
            .collect::<Vec<_>>();
        let sampled = sample_direct_peer_ips(peers.clone());

        assert_eq!(sampled.len(), 3);
        assert!(sampled.iter().all(|peer| peers.contains(peer)));
        assert_eq!(sampled.iter().copied().collect::<HashSet<_>>().len(), 3);
        assert_eq!(
            sample_direct_peer_ips(peers[..2].to_vec())
                .into_iter()
                .collect::<HashSet<_>>(),
            peers[..2].iter().copied().collect()
        );
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
}
