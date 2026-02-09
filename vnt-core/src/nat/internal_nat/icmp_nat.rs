use crate::context::SharedNetworkAddr;
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use pnet_packet::Packet;
use pnet_packet::icmp::echo_reply::{Identifier, SequenceNumber};
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::ipv4::Ipv4Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use tcp_ip::IpStack;
use tcp_ip::icmp::IcmpSocket;
use tokio::net::UdpSocket;

pub async fn start_icmp_nat(
    task_group: &TaskGroup,
    ip_stack: &IpStack,
    no_tun: bool,
    network: SharedNetworkAddr,
) -> anyhow::Result<()> {
    let net_icmp_socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .context("new Socket RAW ICMPV4 failed")?;
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
    let mut map = HashMap::new();
    loop {
        tokio::select! {
            rs = tokio_icmp_socket.recv(&mut buf1) => {
                let len = rs?;
                tokio_icmp_socket_recv(&buf1[..len],&inner_icmp_socket,&map,no_tun,&network).await?;
            }
            rs = inner_icmp_socket.recv_from_to(&mut buf2) => {
                let (len,src,dst) = rs?;
                inner_icmp_socket_recv(&buf2[..len],src,dst,&tokio_icmp_socket,&mut map,no_tun,&network).await?;
            }
        }
    }
}
async fn tokio_icmp_socket_recv(
    buf: &[u8],
    inner_icmp_socket: &IcmpSocket,
    map: &HashMap<(Ipv4Addr, Identifier, SequenceNumber), Ipv4Addr>,
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
    let Some(dst) = map.get(&(src, identifier, sequence_number)) else {
        return Ok(());
    };
    if no_tun && src == Ipv4Addr::LOCALHOST {
        src = network.ip().context("not ip")?;
    }

    inner_icmp_socket
        .send_from_to(ipv4.payload(), src.into(), (*dst).into())
        .await
        .context("sending ICMPv4 failed")?;
    Ok(())
}
async fn inner_icmp_socket_recv(
    buf: &[u8],
    src: IpAddr,
    dst: IpAddr,
    tokio_icmp_socket: &UdpSocket,
    map: &mut HashMap<(Ipv4Addr, Identifier, SequenceNumber), Ipv4Addr>,
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
    if no_tun && dst == network.ip().context("not ip")? {
        dst = Ipv4Addr::LOCALHOST;
    }

    let identifier = Identifier::new(u16::from_be_bytes([payload[0], payload[1]]));
    let sequence_number = SequenceNumber::new(u16::from_be_bytes([payload[2], payload[3]]));
    map.insert((dst, identifier, sequence_number), src);
    tokio_icmp_socket
        .send_to(buf, SocketAddr::new(dst.into(), 0))
        .await?;
    Ok(())
}
