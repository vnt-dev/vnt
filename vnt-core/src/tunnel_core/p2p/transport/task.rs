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
use rust_p2p_core::punch::Puncher;
use rust_p2p_core::tunnel::{Tunnel, TunnelDispatcher, new_tunnel_component};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

pub async fn init_tunnel(
    task_group: TaskGroup,
    app_state: AppState,
    tunnel_to_server: ServerOutbound,
    packet_crypto: PacketCrypto,
    tunnel_port: Option<u16>,
) -> anyhow::Result<(Puncher, P2pOutbound, P2pTask)> {
    let tunnel_port = tunnel_port.unwrap_or(0);
    let udp_config = rust_p2p_core::tunnel::config::UdpTunnelConfig::default()
        .set_main_udp_count(2)
        .set_sub_udp_count(82)
        .set_simple_udp_port(tunnel_port);
    let tcp_config = rust_p2p_core::tunnel::config::TcpTunnelConfig::new(Box::new(
        rust_p2p_core::tunnel::tcp::LengthPrefixedInitCodec,
    ))
    .set_tcp_multiplexing_limit(2)
    .set_tcp_port(tunnel_port);
    let config = rust_p2p_core::tunnel::config::TunnelConfig::empty()
        .set_udp_tunnel_config(udp_config)
        .set_tcp_tunnel_config(tcp_config);
    let (tunnel_dispatcher, puncher) = new_tunnel_component(config)?;
    let route_table = app_state.route_table.clone();
    let socket_manager = P2pOutbound::new(
        tunnel_dispatcher.socket_manager(),
        route_table.clone(),
        packet_crypto,
    );
    task_group.spawn(my_nat_info(
        app_state.clone(),
        tunnel_dispatcher.socket_manager(),
    ));
    let manager = tunnel_dispatcher.socket_manager();
    task_group.spawn(query_udp_public_addr_loop(
        app_state.clone(),
        manager.clone(),
    ));
    task_group.spawn(query_tcp_public_addr_loop(app_state.clone(), manager));

    task_group.spawn(route_timeout_task(
        route_table.clone(),
        app_state.packet_loss_stats.clone(),
    ));
    let app_state_for_punch = app_state.clone();
    let punch_ctx = PunchTaskContext {
        network: app_state.network.clone(),
        server_info: app_state.server_info_collection.clone(),
        punch_backoff: app_state.punch_backoff.clone(),
        punch_info_getter: Arc::new(move || app_state_for_punch.get_punch_info()),
    };
    task_group.spawn(punch_task(tunnel_to_server, route_table.clone(), punch_ctx));
    task_group.spawn(ping_all(
        app_state.network.clone(),
        app_state.packet_loss_stats.clone(),
        route_table.clone(),
        socket_manager.clone(),
    ));
    task_group.spawn(relay_probe_task(
        app_state.network.clone(),
        app_state.server_info_collection.clone(),
        route_table.clone(),
        socket_manager.clone(),
    ));
    let p2p_task = P2pTask {
        task_group,
        nat_info: app_state.nat_info.clone(),
        socket_manager: socket_manager.clone(),
        tunnel_dispatcher,
    };
    Ok((puncher, socket_manager, p2p_task))
}
pub struct P2pTask {
    task_group: TaskGroup,
    nat_info: MyNatInfo,
    socket_manager: P2pOutbound,
    tunnel_dispatcher: TunnelDispatcher,
}
impl P2pTask {
    pub fn start(self, p2p_inbound_handler: P2pInboundHandler) {
        self.task_group.spawn(tunnel_dispatch_task(
            self.nat_info,
            self.task_group.clone(),
            self.tunnel_dispatcher,
            p2p_inbound_handler,
            self.socket_manager,
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
                if index > 2 {
                    break;
                }
                let Ok(mut ping) = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH + 8,
                    socket_manager.encrypt_reserve(),
                )) else {
                    continue;
                };
                ping.set_msg_type(MsgType::Ping);
                ping.set_ttl(1);
                ping.set_src_id(src.into());
                ping.set_dest_id(id.into());
                ping.set_payload(&crate::utils::time::now_ts_ms().to_be_bytes())
                    .unwrap();
                let route_key = route.route_key();
                if socket_manager.send_to(ping, &route_key).await.is_ok() {
                    packet_loss_stats.record_sent(id, route_key);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
pub async fn route_timeout_task(
    route_table: RouteTable,
    packet_loss_stats: PacketLossStats,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let expired_time = std::time::Instant::now() - Duration::from_secs(10);
        let removed_keys = route_table.remove_oldest_route(expired_time);
        if !removed_keys.is_empty() {
            packet_loss_stats.remove_batch(&removed_keys);
        }
    }
}

/// 客户端中继探测任务
/// 每5分钟执行一次，找到所有未直连的目标IP，通过Ping消息发送给已打洞的客户端
pub async fn relay_probe_task(
    network: SharedNetworkAddr,
    server_info: crate::context::ServerInfoCollection,
    route_table: RouteTable,
    socket_manager: P2pOutbound,
) {
    use rand::prelude::*;

    loop {
        tokio::time::sleep(Duration::from_secs(300)).await; // 5分钟

        let Some(src) = network.ip() else {
            continue;
        };

        let online_ips = server_info.client_online_ips();
        if online_ips.is_empty() {
            continue;
        }

        let mut non_direct_targets = Vec::new();
        for ip in online_ips {
            if ip == src {
                continue;
            }

            let is_direct = route_table
                .get_route_by_id(&ip)
                .ok()
                .map(|route| route.is_direct())
                .unwrap_or(false);

            if !is_direct {
                non_direct_targets.push(ip);
                if non_direct_targets.len() >= 20 {
                    break;
                }
            }
        }

        if non_direct_targets.is_empty() {
            continue;
        }

        let non_direct_count = non_direct_targets.len();

        let targets_to_probe: Vec<Ipv4Addr> = {
            let mut rng = rand::rng();
            if non_direct_targets.len() <= 10 {
                non_direct_targets
            } else {
                non_direct_targets
                    .choose_multiple(&mut rng, 10)
                    .copied()
                    .collect()
            }
        };

        let all_routes = route_table.route_table();
        let mut direct_peers = Vec::new();
        for (ip, routes) in &all_routes {
            if let Some(best_route) = routes.first() {
                if best_route.is_direct() {
                    direct_peers.push((*ip, best_route.route_key()));
                }
            }
        }

        if direct_peers.is_empty() {
            log::debug!("No direct peers available for relay probe");
            continue;
        }

        let max_probes_per_target = 3.min(direct_peers.len());

        for target_ip in &targets_to_probe {
            let selected_peers: Vec<_> = {
                let mut rng = rand::rng();
                direct_peers
                    .iter()
                    .filter(|(ip, _)| ip != target_ip)
                    .choose_multiple(&mut rng, max_probes_per_target)
                    .into_iter()
                    .cloned()
                    .collect()
            };

            for (relay_ip, route_key) in selected_peers {
                // 构造RelayProbe消息，目标是target_ip，但发送给relay_ip
                let Ok(mut probe) = NetPacket::new(TransmissionBytes::zeroed_size(
                    HEAD_LENGTH,
                    socket_manager.encrypt_reserve(),
                )) else {
                    continue;
                };

                probe.set_msg_type(MsgType::RelayProbe);
                probe.set_ttl(2); // TTL设为2，允许中继一次
                probe.set_src_id(src.into());
                probe.set_dest_id((*target_ip).into());

                // 发送给已打洞的客户端，让它中继到目标
                if let Err(e) = socket_manager.send_to(probe, &route_key).await {
                    log::debug!(
                        "Failed to send relay probe to {} for target {}: {:?}",
                        relay_ip,
                        target_ip,
                        e
                    );
                }
            }

            // 控制发送速率，避免网络拥塞
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        log::info!(
            "Relay probe task completed: {} targets probed (from {} non-direct), {} direct peers",
            targets_to_probe.len(),
            non_direct_count,
            direct_peers.len()
        );
    }
}

/// 隧道收发调度与数据分发
pub async fn tunnel_dispatch_task(
    nat_info: MyNatInfo,
    task_group: TaskGroup,
    mut tunnel_factory: TunnelDispatcher,
    p2p_inbound_handler: P2pInboundHandler,
    p2p_socket_manager: P2pOutbound,
) {
    loop {
        let mut tunnel = match tunnel_factory.dispatch().await {
            Ok(rs) => rs,
            Err(e) => {
                log::error!("tunnel disptach :{e:?}");
                return;
            }
        };
        log::info!("tunnel {:?}-{:?}", tunnel.protocol(), tunnel.remote_addr());
        let p2p_inbound_handler = p2p_inbound_handler.clone();
        let nat_info = nat_info.clone();
        let p2p_socket_manager = p2p_socket_manager.clone();
        task_group.spawn(async move {
            let mut buf = vec![0; 65536];
            while let Some(rs) = tunnel.recv_from(&mut buf).await {
                let (len, route_key) = match rs {
                    Ok(rs) => rs,
                    Err(e) => {
                        log::warn!("recv_from {e:?}");
                        if tunnel.protocol().is_udp() {
                            continue;
                        }
                        break;
                    }
                };
                if tunnel.protocol().is_udp()
                    && rust_p2p_core::stun::is_stun_response(&buf[..len])
                    && let Some(pub_addr) = rust_p2p_core::stun::recv_stun_response(&buf[..len])
                {
                    nat_info.update_public_addr(route_key.index(), pub_addr);
                    continue;
                }
                let mut bytes = TransmissionBytes::zeroed(len);
                bytes.copy_from_slice(&buf[..len]);
                p2p_inbound_handler
                    .next_handle(bytes, route_key, &p2p_socket_manager, &mut tunnel)
                    .await;
            }
            log::info!(
                "drop tunnel {:?}-{:?}",
                tunnel.protocol(),
                tunnel.remote_addr()
            );
            if let Tunnel::Tcp(tcp) = tunnel {
                p2p_inbound_handler.tcp_disconnect(tcp.route_key()).await;
            }
        });
    }
}
