use std::net::{Ipv4Addr, SocketAddrV4};
use packet::ip::ipv4::packet::IpV4Packet;
use packet::ip::ipv4::protocol::Protocol;
use packet::tcp::tcp::TcpPacket;
use packet::udp::udp::UdpPacket;
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::external_route::ExternalRoute;
use crate::handle::{check_dest, CurrentDeviceInfo};
use crate::ip_proxy::IpProxyMap;
use crate::protocol::{ip_turn_packet, NetPacket, Version};
use crate::error::*;
use crate::igmp_server::IgmpServer;
use crate::protocol;
use crate::protocol::ip_turn_packet::BroadcastPacketEnd;

pub mod tun_handler;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod tap_handler;

async fn broadcast(sender: &ChannelSender, net_packet: &mut NetPacket<&mut [u8]>, data_len: usize, current_device: &CurrentDeviceInfo) -> Result<()> {
    let mut peer_ips = Vec::with_capacity(8);
    let vec = sender.route_table_one();
    let mut relay_count = 0;
    const MAX_COUNT: usize = u8::MAX as usize;
    for (peer_ip, route) in vec {
        if peer_ip == current_device.virtual_gateway {
            continue;
        }
        if peer_ips.len() == MAX_COUNT {
            break;
        }
        if route.is_p2p()
            && sender.send_by_key(&net_packet.buffer()[..data_len], &route.route_key()).await.is_ok() {
            peer_ips.push(peer_ip);
        } else {
            relay_count += 1;
        }
    }
    if relay_count == 0 && !peer_ips.is_empty() && peer_ips.len() != MAX_COUNT {
        //不需要转发
        return Ok(());
    }

    if peer_ips.is_empty() {
        sender.send_main(&net_packet.buffer()[..data_len], current_device.connect_server).await?;
    } else {
        let end_len = 1 + peer_ips.len() * 4;
        //剩余的发送到服务端，需要告知哪些已发送过
        //放在末尾可以减少复制次数
        let mut broadcast = BroadcastPacketEnd::unchecked(&mut net_packet.buffer_mut()[data_len..data_len + end_len]);
        broadcast.set_address(&peer_ips)?;
        net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4Broadcast.into());
        sender.send_main(&net_packet.buffer()[..(data_len + end_len)], current_device.connect_server).await?;
    }
    Ok(())
}

async fn multicast(igmp_server: &IgmpServer, multicast_addr: Ipv4Addr, sender: &ChannelSender, net_packet: &mut NetPacket<&mut [u8]>, data_len: usize, current_device: &CurrentDeviceInfo) -> Result<()> {
    let mut peer_ips = Vec::with_capacity(8);
    let vec = sender.route_table_one();
    let mut relay_count = 0;
    const MAX_COUNT: usize = u8::MAX as usize;
    if let Some(members) = igmp_server.load(&multicast_addr) {
        for (peer_ip, route) in vec {
            if peer_ip == current_device.virtual_gateway {
                continue;
            }
            let is_send = { members.read().is_send(&peer_ip) };
            if is_send {
                if peer_ips.len() == MAX_COUNT {
                    break;
                }
                if route.is_p2p()
                    && sender.send_by_key(&net_packet.buffer()[..data_len], &route.route_key()).await.is_ok() {
                    peer_ips.push(peer_ip);
                } else {
                    relay_count += 1;
                }
            }
        }
    }
    if relay_count == 0 && !peer_ips.is_empty() && peer_ips.len() != MAX_COUNT {
        //不需要转发
        return Ok(());
    }
    if peer_ips.is_empty() {
        sender.send_main(&net_packet.buffer()[..data_len], current_device.connect_server).await?;
    } else {
        let end_len = 1 + peer_ips.len() * 4;
        //剩余的发送到服务端，需要告知哪些已发送过
        //放在末尾可以减少复制次数
        let mut broadcast = BroadcastPacketEnd::unchecked(&mut net_packet.buffer_mut()[data_len..data_len + end_len]);
        broadcast.set_address(&peer_ips)?;
        net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4Broadcast.into());
        sender.send_main(&net_packet.buffer()[..(data_len + end_len)], current_device.connect_server).await?;
    }
    Ok(())
}

/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节+12字节结尾|
///
#[inline]
pub async fn base_handle(sender: &ChannelSender, buf: &mut [u8],
                         mut data_len: usize,//数据总长度=ip长度+12
                         igmp_server: &Option<IgmpServer>,
                         current_device: CurrentDeviceInfo,
                         ip_route: &Option<ExternalRoute>, proxy_map: &Option<IpProxyMap>, cipher: &Cipher) -> Result<()> {
    let ipv4_packet = IpV4Packet::new(&buf[12..data_len])?;
    let protocol = ipv4_packet.protocol();
    let ip_head_len = ipv4_packet.header_len() as usize * 4;
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
    net_packet.first_set_ttl(3);
    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        if protocol == Protocol::Icmp {
            net_packet.set_transport_protocol(ip_turn_packet::Protocol::Icmp.into());
            //发送到服务端的不加密
            sender.send_main(&net_packet.buffer()[..data_len], current_device.connect_server).await?;
        }
        return Ok(());
    }
    if dest_ip.is_multicast() {
        match protocol {
            Protocol::Igmp => {
                if igmp_server.is_some() {
                    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Igmp.into());
                    //发送到服务端
                    net_packet.set_destination(current_device.virtual_gateway);
                    sender.send_main(&net_packet.buffer()[..data_len], current_device.connect_server).await?;
                }
                return Ok(());
            }
            Protocol::Udp => {
                if let Some(igmp_server) = igmp_server {
                    if let Some(len) = cipher.encrypt_ipv4(data_len - 12, &mut net_packet)? {
                        data_len = 12 + len;
                    }
                    multicast(igmp_server, dest_ip, sender, &mut net_packet, data_len, &current_device).await?;
                    return Ok(());
                } else {
                    //当广播
                    dest_ip = Ipv4Addr::BROADCAST;
                    net_packet.set_destination(dest_ip);
                }
            }
            _ => {
                return Ok(());
            }
        }
    }
    if dest_ip.is_broadcast() || current_device.broadcast_address == dest_ip {
        // 广播 发送到直连目标
        if Protocol::Udp == protocol {
            if let Some(len) = cipher.encrypt_ipv4(data_len - 12, &mut net_packet)? {
                data_len = 12 + len;
            }
            broadcast(sender, &mut net_packet, data_len, &current_device).await?;
        }
        return Ok(());
    }
    if !check_dest(dest_ip, current_device.virtual_netmask, current_device.virtual_network) {
        if let Some(ip_route) = ip_route {
            if let Some(r_dest_ip) = ip_route.route(&dest_ip) {
                //路由的目标不能是自己
                if r_dest_ip == src_ip {
                    return Ok(());
                }
                //需要修改目的地址
                dest_ip = r_dest_ip;
                net_packet.set_destination(r_dest_ip);
            } else {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    } else if let Some(proxy_map) = proxy_map {
        match protocol {
            Protocol::Tcp => {
                let dest_addr = {
                    let tcp_packet = TcpPacket::new(src_ip, dest_ip, &mut net_packet.buffer_mut()[12 + ip_head_len..data_len])?;
                    SocketAddrV4::new(dest_ip, tcp_packet.destination_port())
                };
                if let Some(entry) = proxy_map.tcp_proxy_map.get(&dest_addr) {
                    let source_addr = entry.value().1;
                    let source_ip = *source_addr.ip();
                    let mut tcp_packet = TcpPacket::new(source_ip, dest_ip, &mut net_packet.buffer_mut()[12 + ip_head_len..data_len])?;
                    tcp_packet.set_source_port(source_addr.port());
                    tcp_packet.update_checksum();
                    let mut ipv4_packet = IpV4Packet::new(&mut net_packet.buffer_mut()[12..data_len])?;
                    ipv4_packet.set_source_ip(source_ip);
                    ipv4_packet.update_checksum();
                }
            }
            Protocol::Udp => {
                let dest_addr = {
                    let udp_packet = UdpPacket::new(src_ip, dest_ip, &mut net_packet.buffer_mut()[12 + ip_head_len..data_len])?;
                    SocketAddrV4::new(dest_ip, udp_packet.destination_port())
                };
                if let Some(entry) = proxy_map.udp_proxy_map.get(&dest_addr) {
                    let source_addr = entry.value().1;
                    let source_ip = *source_addr.ip();
                    let mut udp_packet = UdpPacket::new(source_ip, dest_ip, &mut net_packet.buffer_mut()[12 + ip_head_len..data_len])?;
                    udp_packet.set_source_port(source_addr.port());
                    udp_packet.update_checksum();
                    let mut ipv4_packet = IpV4Packet::new(&mut net_packet.buffer_mut()[12..data_len])?;
                    ipv4_packet.set_source_ip(source_ip);
                    ipv4_packet.update_checksum();
                }
            }
            _ => {}
        }
    }
    if let Some(len) = cipher.encrypt_ipv4(data_len - 12, &mut net_packet)? {
        data_len = 12 + len;
    }

    //优先发到直连到地址
    if sender.send_by_id(&net_packet.buffer()[..data_len], &dest_ip).await.is_err() {
        sender.send_main(&net_packet.buffer()[..data_len], current_device.connect_server).await?;
    }
    return Ok(());
}
