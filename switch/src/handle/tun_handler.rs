use std::{io, thread};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use crossbeam::atomic::AtomicCell;

use p2p_channel::channel::sender::Sender;
use packet::icmp:: Kind;
use packet::icmp::icmp:: IcmpPacket;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::error::*;
use crate::external_route::ExternalRoute;
use crate::handle::{check_dest, CurrentDeviceInfo};
use crate::ip_proxy::IpProxyMap;
use crate::protocol::{MAX_TTL, NetPacket, Protocol, Version};
use crate::tun_device::{TunReader, TunWriter};

fn icmp(tun_writer: &TunWriter, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> Result<()> {
    if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            tun_writer.write(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

/// 接收tun数据，并且转发到udp上
#[inline]
fn handle(sender: &Sender<Ipv4Addr>, data: &mut [u8], tun_writer: &TunWriter, current_device: CurrentDeviceInfo, net_packet: &mut NetPacket<[u8; 1512]>, ip_route: &ExternalRoute, proxy_map: &IpProxyMap) -> Result<()> {
    let data_len = data.len();
    let mut ipv4_packet = match IpV4Packet::new(data) {
        Ok(ipv4_packet) => ipv4_packet,
        Err(packet::error::Error::Unimplemented) => {
            return Ok(());
        }
        Err(e) => Err(e)?,
    };
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    // if dest_ip == cur_info.broadcast_address {
    //     // 启动服务后会收到对137端口的广播
    //     // 137端口是在局域网中提供计算机的名字或IP地址查询服务
    //     return Ok(());
    // }
    if src_ip != current_device.virtual_ip() {
        return Ok(());
    }
    if src_ip == dest_ip {
        return icmp(&tun_writer, ipv4_packet);
    }
    if !check_dest(dest_ip, current_device.virtual_netmask, current_device.virtual_network) && !dest_ip.is_broadcast() {
        // println!("非目标 {:?}",ipv4_packet);
        if let Some(r_dest_ip) = ip_route.route(&dest_ip) {
            //路由的目标不能是自己
            if r_dest_ip == src_ip {
                return Ok(());
            }
            dest_ip = r_dest_ip;
        } else {
            return Ok(());
        }
    } else {
        match ipv4_packet.protocol() {
            ipv4::protocol::Protocol::Tcp => {
                let dest_addr = {
                    let tcp_packet = packet::tcp::tcp::TcpPacket::new(src_ip, dest_ip, ipv4_packet.payload())?;
                    SocketAddrV4::new(dest_ip, tcp_packet.destination_port())
                };
                if let Some(entry) = proxy_map.tcp_proxy_map.get(&dest_addr) {
                    let source_addr = entry.value().1;
                    let source_ip = *source_addr.ip();
                    let mut tcp_packet = packet::tcp::tcp::TcpPacket::new(source_ip, dest_ip, ipv4_packet.payload_mut())?;
                    tcp_packet.set_source_port(source_addr.port());
                    tcp_packet.update_checksum();
                    ipv4_packet.set_source_ip(source_ip);
                    ipv4_packet.update_checksum();
                }
            }
            ipv4::protocol::Protocol::Udp => {
                let dest_addr = {
                    let udp_packet = packet::udp::udp::UdpPacket::new(src_ip, dest_ip, ipv4_packet.payload())?;
                    SocketAddrV4::new(dest_ip, udp_packet.destination_port())
                };
                if let Some(entry) = proxy_map.udp_proxy_map.get(&dest_addr) {
                    let source_addr = entry.value().1;
                    let source_ip = *source_addr.ip();
                    let mut udp_packet = packet::udp::udp::UdpPacket::new(source_ip, dest_ip, ipv4_packet.payload_mut())?;
                    udp_packet.set_source_port(source_addr.port());
                    udp_packet.update_checksum();
                    ipv4_packet.set_source_ip(source_ip);
                    ipv4_packet.update_checksum();
                }
            }
            _ => {}
        }
    }

    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    net_packet.set_payload(ipv4_packet.buffer);
    //优先发到直连到地址
    if sender.send_to_id(&net_packet.buffer()[..(12 + data_len)], &dest_ip).is_err() {
        sender.send_to_addr(&net_packet.buffer()[..(12 + data_len)], current_device.connect_server)?;
    }
    return Ok(());
}

pub fn start(sender: Sender<Ipv4Addr>,
             tun_reader: TunReader,
             tun_writer: TunWriter,
             current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
             ip_route: ExternalRoute,
             ip_proxy_map: IpProxyMap) {
    thread::Builder::new().name("tun-handler".into()).spawn(move || {
        if let Err(e) = start_(sender, tun_reader, tun_writer, current_device, ip_route, ip_proxy_map) {
            log::warn!("{:?}",e);
        }
    }).unwrap();
}

#[cfg(target_os = "windows")]
fn start_(sender: Sender<Ipv4Addr>,
          tun_reader: TunReader,
          tun_writer: TunWriter,
          current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
          ip_route: ExternalRoute,
          ip_proxy_map: IpProxyMap) -> io::Result<()> {
    let mut net_packet = NetPacket::new([0u8; 4 + 8 + 1500])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Ipv4Turn);
    net_packet.set_transport_protocol(ipv4::protocol::Protocol::Ipv4.into());
    net_packet.set_ttl(MAX_TTL);
    loop {
        let mut data = tun_reader.next()?;
        match handle(&sender, data.bytes_mut(), &tun_writer, current_device.load(), &mut net_packet, &ip_route, &ip_proxy_map) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn start_(sender: Sender<Ipv4Addr>,
          tun_reader: TunReader,
          tun_writer: TunWriter,
          current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
          ip_route: ExternalRoute,
          ip_proxy_map: IpProxyMap) -> io::Result<()> {
    let mut net_packet = NetPacket::new([0u8; 4 + 8 + 1500])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Ipv4Turn);
    net_packet.set_transport_protocol(ipv4::protocol::Protocol::Ipv4.into());
    net_packet.set_ttl(MAX_TTL);
    let mut buf = [0; 4096];
    loop {
        let len = tun_reader.read(&mut buf)?;
        match handle(&sender, &mut buf[..len], &tun_writer, current_device.load(), &mut net_packet, &ip_route, &ip_proxy_map) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
    }
}