use crate::context::AppState;
use rust_p2p_core::nat::{NatInfo, NatType};
use rust_p2p_core::socket::LocalInterface;
use rust_p2p_core::tunnel::SocketManager;
use rust_p2p_core::tunnel::udp::Model;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn my_nat_info(
    app_context: AppState,
    socket_manager: SocketManager,
    default_interface: Option<LocalInterface>,
    outbound_interface_name: Option<String>,
) {
    loop {
        my_nat_info_impl(
            &app_context,
            &socket_manager,
            default_interface.as_ref(),
            outbound_interface_name.as_deref(),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(60 * 30)).await;
    }
}
async fn my_nat_info_impl(
    app_context: &AppState,
    socket_manager: &SocketManager,
    default_interface: Option<&LocalInterface>,
    outbound_interface_name: Option<&str>,
) {
    let network = app_context.network.network();
    let mut local_ipv4s = Vec::new();
    let mut local_ipv6 = Vec::new();
    match getifaddrs::getifaddrs() {
        Ok(addrs) => {
            for x in addrs {
                if outbound_interface_name.is_some_and(|name| x.name != name) {
                    continue;
                }
                let Some(ip) = x.address.ip_addr() else {
                    continue;
                };
                if ip.is_loopback() {
                    continue;
                }
                if ip.is_unspecified() {
                    continue;
                }
                if ip.is_multicast() {
                    continue;
                }

                match ip {
                    IpAddr::V4(addr) => {
                        if addr.is_documentation() {
                            continue;
                        }
                        if addr.is_broadcast() {
                            continue;
                        }
                        if let Some(network) = &network
                            && network.contains(&addr)
                        {
                            continue;
                        }
                        local_ipv4s.push(addr);
                    }
                    IpAddr::V6(addr) => {
                        if addr.is_unique_local() {
                            continue;
                        }
                        if addr.is_unicast_link_local() {
                            continue;
                        }
                        local_ipv6.push(addr);
                    }
                }
            }
        }
        Err(e) => {
            log::error!("getifaddrs error: {e}");
        }
    }
    log::info!("local_ipv4s: {:?}", local_ipv4s);
    let detected = if outbound_interface_name.is_none() {
        rust_p2p_core::extend::addr::local_ipv4()
            .await
            .map_err(|e| {
                log::warn!("local ipv4 failed {e:?}");
                e
            })
            .ok()
    } else {
        None
    };
    let Some((local_ipv4, merged)) = select_local_ipv4(detected, &local_ipv4s) else {
        log::warn!("未发现可用本机 IPv4 地址，跳过本次 NAT 信息更新");
        return;
    };
    // 保留网卡扫描结果，主地址排在首位
    local_ipv4s = merged;
    let mut ipv6 = if outbound_interface_name.is_none() {
        rust_p2p_core::extend::addr::local_ipv6().await.ok()
    } else {
        local_ipv6.first().cloned()
    };
    if let Some(addr) = ipv6 {
        if addr.is_loopback()
            || addr.is_unique_local()
            || addr.is_unicast_link_local()
            || addr.is_unspecified()
            || addr.is_multicast()
        {
            ipv6 = local_ipv6.first().cloned();
        }
    } else {
        ipv6 = local_ipv6.first().cloned();
    }
    let Some(udp_mgr) = socket_manager.udp_socket_manager_as_ref() else {
        log::warn!("udp socket manager 未就绪，跳过本次 NAT 信息更新");
        return;
    };
    let local_udp_ports = match udp_mgr.local_ports() {
        Ok(ports) => ports,
        Err(e) => {
            log::warn!("获取本地 UDP 端口失败: {e:?}，跳过本次 NAT 信息更新");
            return;
        }
    };
    let local_tcp_port = socket_manager
        .tcp_socket_manager_as_ref()
        .map(|m| m.local_addr().port())
        .unwrap_or_else(|| {
            log::warn!("tcp socket manager 未就绪，local_tcp_port 置 0");
            0
        });
    log::info!(
        "local_ipv4={local_ipv4},ipv6={ipv6:?},local_udp_ports:{local_udp_ports:?},local_tcp_port:{local_tcp_port:?}"
    );
    let mut public_ports = local_udp_ports.clone();
    public_ports.fill(0);
    let mut nat_info = NatInfo {
        nat_type: NatType::Cone,
        public_ips: vec![],
        public_udp_ports: public_ports,
        mapping_tcp_addr: vec![],
        mapping_udp_addr: vec![],
        public_port_range: 0,
        local_ipv4s,
        local_ipv4,
        ipv6,
        local_udp_ports,
        local_tcp_port,
        public_tcp_port: 0,
    };
    let mut stun_server = app_context.udp_stun();
    if stun_server.is_empty() {
        stun_server = default_udp_stun();
    }
    let (nat_type, public_ips, port_range) =
        rust_p2p_core::stun::stun_test_nat(stun_server, default_interface)
            .await
            .unwrap_or_else(|e| {
                log::warn!("stun_test_nat {e:?}");
                (NatType::Cone, vec![], 0)
            });
    log::info!("nat_type:{nat_type:?},public_ips:{public_ips:?},port_range={port_range}");
    nat_info.nat_type = nat_type;
    nat_info.public_ips = public_ips;
    nat_info.public_port_range = port_range;
    app_context.nat_info.replace_nat_info(nat_info);
    let model = match nat_type {
        NatType::Cone => Model::Low,
        NatType::Symmetric => Model::High,
    };
    if let Err(e) = udp_mgr.switch_model(model) {
        log::error!("switch_model error: {e:?}");
    }
}

/// 确定本机主 IPv4 并把它合并到地址列表首位。
/// detected 为路由探测得到的主地址（可能不可用），scanned 为网卡扫描结果。
/// 返回 None 表示没有任何可用地址，调用方应跳过本次发布，避免上报 0.0.0.0。
fn select_local_ipv4(
    detected: Option<Ipv4Addr>,
    scanned: &[Ipv4Addr],
) -> Option<(Ipv4Addr, Vec<Ipv4Addr>)> {
    let primary = detected
        .filter(|ip| !ip.is_unspecified())
        .or_else(|| scanned.first().copied())?;
    let mut list: Vec<Ipv4Addr> = scanned.iter().copied().filter(|a| *a != primary).collect();
    list.insert(0, primary);
    Some((primary, list))
}

pub async fn query_udp_public_addr_loop(app_context: AppState, socket_manager: SocketManager) {
    let mut udp_stun_servers = app_context.udp_stun();
    if udp_stun_servers.is_empty() {
        udp_stun_servers = default_udp_stun();
    }
    let udp_len = udp_stun_servers.len();
    let mut udp_count = 0;
    let stun_request = rust_p2p_core::stun::send_stun_request();
    loop {
        let stun = &udp_stun_servers[udp_count % udp_len];
        udp_count += 1;
        match tokio::net::lookup_host(stun.as_str()).await {
            Ok(mut addr) => {
                if let Some(addr) = addr.next()
                    && let Some(w) = socket_manager.udp_socket_manager_as_ref()
                    && let Err(e) = w.detect_pub_addrs(&stun_request, addr).await
                {
                    log::info!("detect_pub_addrs {e:?} {addr:?}");
                }
            }
            Err(e) => {
                log::info!("query_public_addr lookup_host {e:?} {stun:?}",);
            }
        }
        let not_port = app_context
            .get_nat_info()
            .map(|v| v.public_udp_ports.contains(&0))
            .unwrap_or(true);
        if not_port {
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

pub(crate) async fn query_tcp_public_addr_loop(
    app_context: AppState,
    socket_manager: SocketManager,
) {
    use rand::RngExt;
    use rand::seq::SliceRandom;

    let tcp_stun_servers = {
        let servers = app_context.tcp_stun();
        if servers.is_empty() {
            default_tcp_stun()
        } else {
            servers
        }
    };

    if tcp_stun_servers.is_empty() {
        return;
    }
    log::debug!("tcp_stun_servers = {tcp_stun_servers:?}");

    let stun_request = rust_p2p_core::stun::send_stun_request();
    let target_conn_count = tcp_stun_servers.len().min(2);
    let mut active_connections: HashMap<SocketAddr, (TcpStream, SocketAddr)> = HashMap::new();

    'outer: loop {
        while active_connections.len() < target_conn_count {
            let mut candidates: Vec<&String> = tcp_stun_servers.iter().collect();
            candidates.shuffle(&mut rand::rng());

            let mut connected = false;
            for stun in candidates {
                let addr = match tokio::net::lookup_host(stun.as_str()).await {
                    Ok(mut addrs) => addrs.next(),
                    Err(e) => {
                        log::debug!("lookup_host failed {stun} {e}");
                        continue;
                    }
                };

                let Some(addr) = addr else {
                    continue;
                };

                if active_connections.contains_key(&addr) {
                    continue;
                }

                let Some(w) = socket_manager.tcp_socket_manager_as_ref() else {
                    continue;
                };

                match tokio::time::timeout(Duration::from_secs(5), w.connect_reuse_port_raw(addr))
                    .await
                {
                    Ok(Ok(mut tcp_stream)) => {
                        let write_result = tokio::time::timeout(
                            Duration::from_secs(5),
                            tcp_stream.write_all(&stun_request),
                        )
                        .await;

                        if let Ok(Ok(_)) = write_result {
                            match stun_tcp_read(&mut tcp_stream).await {
                                Ok(pub_addr) => {
                                    log::debug!(
                                        "update_tcp_public_addr {stun} {addr} -> {pub_addr}"
                                    );

                                    let existing_pub_addr =
                                        active_connections.values().next().map(|(_, p)| *p);

                                    if let Some(existing) = existing_pub_addr
                                        && existing != pub_addr
                                    {
                                        log::debug!(
                                            "pub_addr mismatch: {existing} != {pub_addr}, wait 60s"
                                        );
                                        active_connections.clear();
                                        app_context.nat_info.update_tcp_public_addr(
                                            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
                                        );
                                        tokio::time::sleep(Duration::from_secs(5 * 60)).await;
                                        continue 'outer;
                                    }

                                    active_connections.insert(addr, (tcp_stream, pub_addr));
                                    connected = true;
                                    break;
                                }
                                Err(e) => {
                                    log::debug!("stun_tcp_read failed {stun} {addr} {e}");
                                }
                            }
                        } else {
                            log::debug!("write stun request failed {stun} {addr}");
                        }
                    }
                    Ok(Err(e)) => {
                        log::debug!("connect_reuse_port_raw failed {stun} {addr} {e}");
                    }
                    Err(_) => {
                        log::debug!("connect_reuse_port_raw timeout {stun} {addr}");
                    }
                }
            }

            if !connected {
                break;
            }
        }
        let existing_pub_addr = active_connections.values().next().map(|(_, p)| *p);
        if let Some(existing) = existing_pub_addr {
            app_context.nat_info.update_tcp_public_addr(existing);
        }

        let sleep_secs = rand::rng().random_range(10u64..=15);
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

        let mut to_remove = Vec::new();
        let addrs: Vec<SocketAddr> = active_connections.keys().cloned().collect();

        for addr in addrs {
            let (tcp_stream, _) = active_connections.get_mut(&addr).unwrap();
            let mut buf = [0u8; 1024];

            match tcp_stream.try_read(&mut buf) {
                Ok(0) => {
                    log::warn!("stun tcp close {addr} EOF");
                    to_remove.push(addr);
                    continue;
                }
                Err(e) if e.kind() != std::io::ErrorKind::WouldBlock => {
                    log::warn!("stun tcp read error {addr} {e}");
                    to_remove.push(addr);
                    continue;
                }
                _ => {}
            }

            match tokio::time::timeout(Duration::from_secs(3), tcp_stream.write_all(&stun_request))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    log::warn!("stun tcp write error {addr} {e}");
                    to_remove.push(addr);
                }
                Err(_) => {
                    log::warn!("stun tcp write timeout {addr}");
                    to_remove.push(addr);
                }
            }
        }

        for addr in to_remove {
            active_connections.remove(&addr);
        }
    }
}

async fn stun_tcp_read(tcp_stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut head = [0; 20];
    match tokio::time::timeout(Duration::from_secs(5), tcp_stream.read_exact(&mut head)).await {
        Ok(rs) => rs?,
        Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut))?,
    };
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    let mut buf = vec![0; len + 20];
    buf[..20].copy_from_slice(&head);
    match tokio::time::timeout(
        Duration::from_secs(5),
        tcp_stream.read_exact(&mut buf[20..]),
    )
    .await
    {
        Ok(rs) => rs?,
        Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut))?,
    };
    if let Some(addr) = rust_p2p_core::stun::recv_stun_response(&buf) {
        Ok(addr)
    } else {
        log::debug!("stun_tcp_read {buf:?}");
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }
}

fn default_udp_stun() -> Vec<String> {
    vec![
        "stun.miwifi.com:3478".to_string(),
        "stun.chat.bilibili.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
    ]
}

fn default_tcp_stun() -> Vec<String> {
    vec![
        "stun.flashdance.cx:3478".to_string(),
        "stun.sipnet.net:3478".to_string(),
        "stun.nextcloud.com:443".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// 探测地址有效时：主地址在首位，扫描结果保留
    #[test]
    fn test_select_local_ipv4_detected_valid() {
        let scanned = vec![ip("192.168.1.2"), ip("10.0.0.3")];
        let (primary, list) = select_local_ipv4(Some(ip("172.16.0.2")), &scanned).unwrap();
        assert_eq!(primary, ip("172.16.0.2"));
        assert_eq!(
            list,
            vec![ip("172.16.0.2"), ip("192.168.1.2"), ip("10.0.0.3")]
        );
    }

    /// 探测失败/0.0.0.0 时：回退到扫描结果首个地址
    #[test]
    fn test_select_local_ipv4_fallback_to_scanned() {
        let scanned = vec![ip("192.168.1.2"), ip("10.0.0.3")];
        let (primary, list) = select_local_ipv4(None, &scanned).unwrap();
        assert_eq!(primary, ip("192.168.1.2"));
        assert_eq!(list, scanned);

        let (primary, _) = select_local_ipv4(Some(Ipv4Addr::UNSPECIFIED), &scanned).unwrap();
        assert_eq!(primary, ip("192.168.1.2"));
    }

    /// 探测地址已在扫描结果中时不重复
    #[test]
    fn test_select_local_ipv4_no_duplicate() {
        let scanned = vec![ip("192.168.1.2"), ip("10.0.0.3")];
        let (_, list) = select_local_ipv4(Some(ip("10.0.0.3")), &scanned).unwrap();
        assert_eq!(list, vec![ip("10.0.0.3"), ip("192.168.1.2")]);
    }

    /// 两者皆空：返回 None，调用方跳过发布，不会上报 0.0.0.0
    #[test]
    fn test_select_local_ipv4_none_when_empty() {
        assert!(select_local_ipv4(None, &[]).is_none());
        assert!(select_local_ipv4(Some(Ipv4Addr::UNSPECIFIED), &[]).is_none());
    }
}
