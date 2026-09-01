use crate::context::SharedNetworkAddr;
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use pnet_packet::Packet;
use pnet_packet::icmp::echo_reply::{Identifier, SequenceNumber};
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ipv4::Ipv4Packet;
use rustp2p_core::socket::LocalInterface;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tcp_ip::IpStack;
use tcp_ip::icmp::IcmpSocket;
use tokio::net::UdpSocket;

/// ICMP echo 映射超时：正常 ping 应答在秒级返回，超时条目视为无应答残留
const ICMP_NAT_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_NAT_GC_INTERVAL: Duration = Duration::from_secs(60);

/// (对端地址, identifier, sequence) -> (内网客户端地址, 创建时间)
type IcmpNatMap = HashMap<(Ipv4Addr, Identifier, SequenceNumber), (Ipv4Addr, Instant)>;

pub async fn start_icmp_nat(
    task_group: &TaskGroup,
    ip_stack: &IpStack,
    no_tun: bool,
    network: SharedNetworkAddr,
    default_interface: Option<LocalInterface>,
) -> anyhow::Result<()> {
    let net_icmp_socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .context("new Socket RAW ICMPV4 failed")?;
    crate::utils::socket::bind_socket_to_interface(
        &net_icmp_socket,
        default_interface.as_ref(),
        false,
    )
    .context("bind ICMP socket to outbound interface failed")?;
    let addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    net_icmp_socket
        .bind(&socket2::SockAddr::from(addr))
        .context("bind Socket ICMPV4 failed")?;
    net_icmp_socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = net_icmp_socket.into();

    let tokio_icmp_socket = UdpSocket::from_std(std_socket)?;

    let inner_icmp_socket = IcmpSocket::bind_all(ip_stack.clone()).await?;
    task_group.spawn(async move {
        if let Err(e) = task(tokio_icmp_socket, inner_icmp_socket, no_tun, network).await {
            log::error!("icmp task failed: {:?}", e);
        }
    });
    Ok(())
}
async fn task(
    tokio_icmp_socket: UdpSocket,
    inner_icmp_socket: IcmpSocket,
    no_tun: bool,
    network: SharedNetworkAddr,
) -> anyhow::Result<()> {
    let mut buf1 = vec![0u8; 65536];
    let mut buf2 = vec![0u8; 65536];
    let mut map: IcmpNatMap = HashMap::new();
    let mut gc_interval = tokio::time::interval(ICMP_NAT_GC_INTERVAL);
    loop {
        // 单次收发/处理失败不能拖垮整个任务：记录日志后继续，
        // 短暂休眠避免持续性错误造成空转
        tokio::select! {
            rs = tokio_icmp_socket.recv(&mut buf1) => {
                match rs {
                    Ok(len) => {
                        if let Err(e) = tokio_icmp_socket_recv(&buf1[..len],&inner_icmp_socket,&mut map,no_tun,&network).await {
                            log::warn!("icmp nat outbound error: {e:?}");
                        }
                    }
                    Err(e) => {
                        log::warn!("icmp nat recv error: {e:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            rs = inner_icmp_socket.recv_from_to(&mut buf2) => {
                match rs {
                    Ok((len,src,dst)) => {
                        if let Err(e) = inner_icmp_socket_recv(&buf2[..len],src,dst,&tokio_icmp_socket,&mut map,no_tun,&network).await {
                            log::warn!("icmp nat inbound error: {e:?}");
                        }
                    }
                    Err(e) => {
                        log::warn!("icmp nat inner recv error: {e:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = gc_interval.tick() => {
                evict_expired(&mut map, Instant::now(), ICMP_NAT_TIMEOUT);
            }
        }
    }
}

/// 清理超时未收到应答的映射条目，防止 map 无界增长
fn evict_expired(map: &mut IcmpNatMap, now: Instant, timeout: Duration) {
    let before = map.len();
    map.retain(|_, (_, created)| now.duration_since(*created) < timeout);
    let evicted = before - map.len();
    if evicted > 0 {
        log::debug!("icmp nat evicted {} expired entries", evicted);
    }
}
async fn tokio_icmp_socket_recv(
    buf: &[u8],
    inner_icmp_socket: &IcmpSocket,
    map: &mut IcmpNatMap,
    no_tun: bool,
    network: &SharedNetworkAddr,
) -> anyhow::Result<()> {
    let Some(ipv4) = Ipv4Packet::new(buf) else {
        return Ok(());
    };
    let Some(icmp) = IcmpPacket::new(ipv4.payload()) else {
        return Ok(());
    };
    if icmp.get_icmp_type() != IcmpTypes::EchoReply
        && icmp.get_icmp_type() != IcmpTypes::EchoRequest
    {
        return Ok(());
    }
    let payload = icmp.payload();
    if payload.len() < 4 {
        return Ok(());
    }
    let mut src = ipv4.get_source();
    let identifier = Identifier::new(u16::from_be_bytes([payload[0], payload[1]]));
    let sequence_number = SequenceNumber::new(u16::from_be_bytes([payload[2], payload[3]]));
    // 收到应答即完成一次 echo 交换，移除映射，避免条目残留
    let Some((dst, _)) = map.remove(&(src, identifier, sequence_number)) else {
        return Ok(());
    };
    if no_tun && src == Ipv4Addr::LOCALHOST {
        // 虚拟地址未就绪时丢弃该应答包，而不是让错误传播杀掉整个任务
        let Some(ip) = network.ip() else {
            return Ok(());
        };
        src = ip;
    }

    inner_icmp_socket
        .send_from_to(ipv4.payload(), src.into(), dst.into())
        .await
        .context("sending ICMPv4 failed")?;
    Ok(())
}
async fn inner_icmp_socket_recv(
    buf: &[u8],
    src: IpAddr,
    dst: IpAddr,
    tokio_icmp_socket: &UdpSocket,
    map: &mut IcmpNatMap,
    no_tun: bool,
    network: &SharedNetworkAddr,
) -> anyhow::Result<()> {
    let (IpAddr::V4(src), IpAddr::V4(mut dst)) = (src, dst) else {
        return Ok(());
    };
    let Some(icmp) = IcmpPacket::new(buf) else {
        return Ok(());
    };
    if icmp.get_icmp_type() != IcmpTypes::EchoReply
        && icmp.get_icmp_type() != IcmpTypes::EchoRequest
    {
        return Ok(());
    }
    let payload = icmp.payload();
    if payload.len() < 4 {
        return Ok(());
    }
    // 虚拟地址未就绪（None）时跳过重写，而不是让错误传播杀掉整个任务
    if no_tun && Some(dst) == network.ip() {
        dst = Ipv4Addr::LOCALHOST;
    }

    let identifier = Identifier::new(u16::from_be_bytes([payload[0], payload[1]]));
    let sequence_number = SequenceNumber::new(u16::from_be_bytes([payload[2], payload[3]]));
    map.insert((dst, identifier, sequence_number), (src, Instant::now()));
    tokio_icmp_socket
        .send_to(buf, SocketAddr::new(dst.into(), 0))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        ip: &str,
        id: u16,
        seq: u16,
        created: Instant,
    ) -> ((Ipv4Addr, Identifier, SequenceNumber), (Ipv4Addr, Instant)) {
        (
            (
                ip.parse().unwrap(),
                Identifier::new(id),
                SequenceNumber::new(seq),
            ),
            (Ipv4Addr::new(10, 0, 0, 1), created),
        )
    }

    /// 超时未应答的条目必须被清理，未超时的保留，map 不会无界增长
    #[test]
    fn test_evict_expired() {
        let now = Instant::now();
        let mut map: IcmpNatMap = HashMap::new();
        let (k_fresh, v_fresh) = entry("8.8.8.8", 1, 1, now);
        let (k_stale, v_stale) = entry(
            "1.1.1.1",
            2,
            2,
            now - ICMP_NAT_TIMEOUT - Duration::from_secs(1),
        );
        map.insert(k_fresh, v_fresh);
        map.insert(k_stale, v_stale);

        evict_expired(&mut map, now, ICMP_NAT_TIMEOUT);

        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&k_fresh));
        assert!(!map.contains_key(&k_stale));
    }
}
