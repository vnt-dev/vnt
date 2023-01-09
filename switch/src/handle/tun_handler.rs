/// 接收tun数据，并且转发到udp上
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;

use chrono::Local;
use tokio::sync::watch;

use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::ApplicationStatus;
use crate::error::*;
use crate::handle::{CurrentDeviceInfo, DIRECT_ROUTE_TABLE};
use crate::protocol::{NetPacket, Protocol, Version};
use crate::protocol::turn_packet::TurnPacket;
use crate::tun_device::TunReader;

/// 是否在一个网段
fn check_dest(dest: Ipv4Addr, cur_info: &CurrentDeviceInfo) -> bool {
    u32::from_be_bytes(dest.octets()) & u32::from_be_bytes(cur_info.virtual_netmask.octets())
        == u32::from_be_bytes(cur_info.virtual_network.octets())
}

fn icmp(udp: &UdpSocket, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> Result<()> {
    if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            let mut addr = udp.local_addr()?;
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            udp.send_to(ipv4_packet.buffer, addr)?;
        }
    }
    Ok(())
}

#[inline]
fn handle(
    udp: &UdpSocket,
    data: &mut [u8],
    cur_info: &CurrentDeviceInfo,
    net_packet: &mut NetPacket<Vec<u8>>,
) -> Result<()> {
    let data_len = data.len();
    let ipv4_packet = match IpV4Packet::new(data) {
        Ok(ipv4_packet) => ipv4_packet,
        Err(packet::error::Error::Unimplemented) => {
            return Ok(());
        }
        Err(e) => Err(e)?,
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    // if dest_ip == cur_info.broadcast_address {
    //     // 启动服务后会收到对137端口的广播
    //     // 137端口是在局域网中提供计算机的名字或IP地址查询服务
    //     return Ok(());
    // }
    if src_ip != cur_info.virtual_ip || !check_dest(dest_ip, &cur_info) {
        return Ok(());
    }
    if src_ip == dest_ip {
        return icmp(&udp, ipv4_packet);
    }
    let mut ipv4_turn_packet = TurnPacket::new(net_packet.payload_mut())?;
    ipv4_turn_packet.set_source(src_ip);
    ipv4_turn_packet.set_destination(dest_ip);
    ipv4_turn_packet.set_payload(ipv4_packet.buffer);
    //优先发到直连到地址
    if let Some(route) = DIRECT_ROUTE_TABLE.get(&dest_ip) {
        let current_time = Local::now().timestamp_millis();
        if current_time - route.recv_time < 3_000 {
            if udp.send_to(&net_packet.buffer()[..(4 + 8 + data_len)], route.address).is_ok() {
                return Ok(());
            }
        }
    }
    udp.send_to(&net_packet.buffer()[..(4 + 8 + data_len)], cur_info.connect_server)?;
    return Ok(());
}

#[cfg(target_os = "windows")]
pub async fn handler_start<F>(mut status_watch: watch::Receiver<ApplicationStatus>,
                              udp: UdpSocket,
                              tun_reader: TunReader,
                              cur_info: CurrentDeviceInfo, stop_fn: F)
    where F: FnOnce() + Send + 'static {
    let session = tun_reader.0.clone();
    tokio::spawn(async move {
        let _ = status_watch.changed().await;
        session.shutdown();
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        let _ = udp.send_to(&[0],SocketAddr::new(IpAddr::V4(cur_info.virtual_gateway),10));
    });
    thread::spawn(move || {
        if let Err(e) = handle_loop(udp, tun_reader, cur_info) {
            log::error!("tun数据处理线程停止 {:?}",e);
        }
        stop_fn();
    });
}

#[cfg(target_os = "windows")]
fn handle_loop(
    udp: UdpSocket,
    tun_reader: TunReader,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let mut net_packet = NetPacket::new(vec![0u8; 4 + 8 + 1500])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Ipv4Turn);
    net_packet.set_transport_protocol(ipv4::protocol::Protocol::Ipv4.into());
    net_packet.set_ttl(255);
    loop {
        let mut data = tun_reader.next()?;
        match handle(&udp, data.bytes_mut(), &cur_info, &mut net_packet) {
            Ok(_) => {}
            Err(e) => {
                println!("{:?}", e)
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
pub async fn handler_start<F>(mut status_watch: watch::Receiver<ApplicationStatus>,
                              udp: UdpSocket,
                              tun_reader: TunReader,
                              cur_info: CurrentDeviceInfo, stop_fn: F)
    where F: FnOnce() + Send + 'static {
    let raw_fd = tun_reader.0.as_raw_fd();
    tokio::spawn(async move {
        let _ = status_watch.changed().await;
        // 让tun接收线程关闭，问题：如果改变tun配置，可能导致tun接收线程无法关闭
        unsafe {
            libc::close(raw_fd);
        }
        let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
        let _ = udp.send_to(&[0],SocketAddr::new(IpAddr::V4(cur_info.virtual_gateway),10));
    });
    thread::spawn(move || {
        if let Err(e) = handle_loop(udp, tun_reader, cur_info) {
            log::error!(" tun数据处理线程停止 {:?}",e);
        }
        stop_fn();
    });
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
pub fn handle_loop(
    udp: UdpSocket,
    mut tun_reader: TunReader,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let mut net_packet = NetPacket::new(vec![0u8; 4 + 8 + 1500])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Ipv4Turn);
    net_packet.set_transport_protocol(0);
    net_packet.set_ttl(255);
    let mut buf = [0u8; 1500];
    loop {
        let data = tun_reader.read(&mut buf)?;
        match handle(&udp, data, &cur_info, &mut net_packet) {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}",e)
            }
        }
    }
}
