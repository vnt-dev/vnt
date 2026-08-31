use crate::context::AppState;
use rustp2p_core::nat::NatType;
use rustp2p_core::punch::Puncher;
use rustp2p_core::socket::LocalInterface;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn my_nat_info(app_context: AppState, puncher: Puncher) {
    loop {
        my_nat_info_impl(&app_context, &puncher).await;
        tokio::time::sleep(Duration::from_secs(60 * 30)).await;
    }
}
async fn my_nat_info_impl(app_context: &AppState, puncher: &Puncher) {
    let mut stun_server = app_context.udp_stun();
    if stun_server.is_empty() {
        stun_server = default_udp_stun();
    }
    match puncher.nat_info_with_servers(&stun_server).await {
        Ok(mut nat_info) => {
            // STUN NAT classification uses temporary sockets. The public
            // mapping of the P2P socket is learned separately by sending a
            // request through Puncher::send_to.
            // VNT tracks one public mapping for the Puncher-owned main UDP
            // endpoint and does not expose the core's IPv4/IPv6 socket layout.
            nat_info.public_udp_ports = vec![0];
            nat_info.stun_mapped_ports.clear();
            let nat_type = nat_info.nat_type;
            log::info!(
                "nat_type:{nat_type:?},public_ips:{:?},port_range={}",
                nat_info.public_ips,
                nat_info.public_port_range
            );
            app_context.nat_info.replace_nat_info(nat_info);
            if let Err(error) = puncher.apply_nat_model(nat_type) {
                log::error!("apply_nat_model error: {error:?}");
            }
        }
        Err(error) => log::warn!("nat_info_with_servers {error:?}"),
    }
}

pub async fn query_udp_public_addr_loop(app_context: AppState, puncher: Puncher) {
    let mut udp_stun_servers = app_context.udp_stun();
    if udp_stun_servers.is_empty() {
        udp_stun_servers = default_udp_stun();
    }
    let udp_len = udp_stun_servers.len();
    let mut udp_count = 0;
    let stun_request = rustp2p_core::stun::send_stun_request();
    loop {
        if app_context
            .get_nat_info()
            .is_some_and(|info| info.nat_type == NatType::Symmetric)
        {
            // NAT type can change while the task is alive. Keep polling so
            // UDP public-port discovery resumes after returning to Cone NAT.
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        let stun = &udp_stun_servers[udp_count % udp_len];
        udp_count += 1;
        match tokio::net::lookup_host(stun.as_str()).await {
            Ok(mut addr) => {
                if let Some(addr) = addr.next()
                    && let Err(e) = puncher.send_to(&stun_request, addr)
                {
                    log::info!("send STUN request {e:?} {addr:?}");
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
    local_tcp_port: u16,
    default_interface: Option<LocalInterface>,
) {
    use rand::RngExt;

    if local_tcp_port == 0 {
        log::warn!("P2P TCP listener is disabled; skip TCP public address detection");
        return;
    }

    let stun_request = rustp2p_core::stun::send_stun_request();
    loop {
        let tcp_stun_servers = {
            let servers = app_context.tcp_stun();
            if servers.is_empty() {
                default_tcp_stun()
            } else {
                servers
            }
        };
        let target_count = tcp_stun_servers.len().min(2);
        if target_count == 0 {
            log::warn!("TCP STUN server list is empty");
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        let Some(local_ipv4) = app_context
            .get_nat_info()
            .map(|info| info.local_ipv4)
            .filter(|ip| !ip.is_unspecified())
        else {
            log::debug!("local IPv4 is not available for TCP STUN port reuse");
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };
        let candidates = resolve_tcp_stun_candidates(&tcp_stun_servers, target_count).await;
        if candidates.len() < target_count {
            log::warn!(
                "TCP public address detection requires {target_count} reachable STUN server(s)"
            );
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }

        let attempts = candidates.into_iter().map(|(stun, addr)| {
            connect_tcp_stun(
                stun,
                addr,
                local_tcp_port,
                local_ipv4,
                default_interface.as_ref(),
                &stun_request,
            )
        });
        let results = futures::future::join_all(attempts).await;
        let mut connections = Vec::with_capacity(target_count);
        for result in results {
            match result {
                Ok(connection) => connections.push(connection),
                Err(error) => log::debug!("TCP STUN connection failed: {error}"),
            }
        }
        if connections.len() != target_count {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }

        let Some(public_addr) =
            matching_tcp_public_addr(connections.iter().map(|connection| connection.public_addr))
        else {
            let public_addrs = connections
                .iter()
                .map(|connection| connection.public_addr)
                .collect::<Vec<_>>();
            log::warn!(
                "TCP STUN public address mismatch: {public_addrs:?}; disable TCP punching and retry later"
            );
            app_context
                .nat_info
                .update_tcp_public_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into());
            tokio::time::sleep(Duration::from_secs(5 * 60)).await;
            continue;
        };
        app_context.nat_info.update_tcp_public_addr(public_addr);

        loop {
            let sleep_secs = rand::rng().random_range(10u64..=15);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            if !keep_tcp_stun_connections_alive(&mut connections, &stun_request).await {
                break;
            }
            // NAT classification periodically replaces NatInfo and initializes
            // its TCP mapping to zero. Reapply the address while the validated
            // STUN connection set is still healthy.
            app_context.nat_info.update_tcp_public_addr(public_addr);
        }
    }
}

struct TcpStunConnection {
    stun: String,
    remote_addr: SocketAddr,
    stream: TcpStream,
    public_addr: SocketAddr,
}

async fn resolve_tcp_stun_candidates(
    servers: &[String],
    target_count: usize,
) -> Vec<(String, SocketAddr)> {
    use rand::seq::SliceRandom;

    let mut servers = servers.to_vec();
    servers.shuffle(&mut rand::rng());
    let mut remote_addrs = HashSet::new();
    let mut candidates = Vec::with_capacity(2);
    for stun in servers {
        match tokio::net::lookup_host(stun.as_str()).await {
            Ok(addrs) => {
                if let Some(addr) = addrs
                    .filter(SocketAddr::is_ipv4)
                    .find(|addr| remote_addrs.insert(*addr))
                {
                    candidates.push((stun.clone(), addr));
                    if candidates.len() == target_count {
                        break;
                    }
                }
            }
            Err(error) => log::debug!("lookup_host failed {stun} {error}"),
        }
    }
    candidates
}

fn matching_tcp_public_addr(
    public_addrs: impl IntoIterator<Item = SocketAddr>,
) -> Option<SocketAddr> {
    let mut public_addrs = public_addrs.into_iter();
    let first = public_addrs.next()?;
    public_addrs
        .all(|public_addr| public_addr == first)
        .then_some(first)
}

async fn connect_tcp_stun(
    stun: String,
    remote_addr: SocketAddr,
    local_tcp_port: u16,
    local_ipv4: Ipv4Addr,
    default_interface: Option<&LocalInterface>,
    stun_request: &[u8],
) -> io::Result<TcpStunConnection> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        crate::utils::socket::connect_tcp_reuse_port(
            remote_addr,
            local_tcp_port,
            local_ipv4,
            default_interface,
        ),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(stun_request))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let public_addr = stun_tcp_read(&mut stream).await?;
    log::debug!("TCP STUN {stun} {remote_addr} -> {public_addr}");
    Ok(TcpStunConnection {
        stun,
        remote_addr,
        stream,
        public_addr,
    })
}

async fn keep_tcp_stun_connections_alive(
    connections: &mut [TcpStunConnection],
    stun_request: &[u8],
) -> bool {
    for connection in connections {
        let mut buf = [0u8; 1024];
        match connection.stream.try_read(&mut buf) {
            Ok(0) => {
                log::warn!(
                    "TCP STUN connection closed: {} {}",
                    connection.stun,
                    connection.remote_addr
                );
                return false;
            }
            Err(error) if error.kind() != io::ErrorKind::WouldBlock => {
                log::warn!(
                    "TCP STUN read failed: {} {} {error}",
                    connection.stun,
                    connection.remote_addr
                );
                return false;
            }
            _ => {}
        }
        match tokio::time::timeout(
            Duration::from_secs(3),
            connection.stream.write_all(stun_request),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::warn!(
                    "TCP STUN write failed: {} {} {error}",
                    connection.stun,
                    connection.remote_addr
                );
                return false;
            }
            Err(_) => {
                log::warn!(
                    "TCP STUN write timeout: {} {}",
                    connection.stun,
                    connection.remote_addr
                );
                return false;
            }
        }
    }
    true
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
    if let Some(addr) = rustp2p_core::stun::recv_stun_response(&buf) {
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
    use super::matching_tcp_public_addr;
    use std::net::SocketAddr;

    #[test]
    fn one_tcp_stun_result_is_usable() {
        let public_addrs = ["1.1.1.1:10000".parse::<SocketAddr>().unwrap()];
        assert_eq!(
            matching_tcp_public_addr(public_addrs),
            Some("1.1.1.1:10000".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn two_matching_tcp_stun_results_are_usable() {
        let public_addrs = [
            "1.1.1.1:10000".parse::<SocketAddr>().unwrap(),
            "1.1.1.1:10000".parse::<SocketAddr>().unwrap(),
        ];
        assert_eq!(
            matching_tcp_public_addr(public_addrs),
            Some("1.1.1.1:10000".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn tcp_stun_ip_or_port_mismatch_is_unusable() {
        let ip_mismatch = [
            "1.1.1.1:10000".parse::<SocketAddr>().unwrap(),
            "2.2.2.2:10000".parse::<SocketAddr>().unwrap(),
        ];
        assert_eq!(matching_tcp_public_addr(ip_mismatch), None);

        let port_mismatch = [
            "1.1.1.1:10000".parse::<SocketAddr>().unwrap(),
            "1.1.1.1:20000".parse::<SocketAddr>().unwrap(),
        ];
        assert_eq!(matching_tcp_public_addr(port_mismatch), None);
    }
}
