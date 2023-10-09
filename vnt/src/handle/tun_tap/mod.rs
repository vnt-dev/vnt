use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::RwLock;

use packet::ip::ipv4::packet::IpV4Packet;
use packet::ip::ipv4::protocol::Protocol;

use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::error::*;
use crate::external_route::ExternalRoute;
use crate::handle::{check_dest, CurrentDeviceInfo};
use crate::igmp_server::{IgmpServer, Multicast};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::{IpProxyMap, ProxyHandler};
use crate::protocol;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::ip_turn_packet::BroadcastPacket;
use crate::protocol::{ip_turn_packet, NetPacket, Version, MAX_TTL};

pub mod channel_group;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod tap_handler;
pub mod tun_handler;

fn broadcast(
    server_cipher: &Cipher,
    multicast_members: Option<Arc<RwLock<Multicast>>>,
    sender: &ChannelSender,
    net_packet: &mut NetPacket<&mut [u8]>,
    current_device: &CurrentDeviceInfo,
) -> Result<()> {
    let mut peer_ips = Vec::with_capacity(8);
    let vec = sender.route_table_one();
    let mut relay_count = 0;
    const MAX_COUNT: usize = 8;
    for (peer_ip, route) in vec {
        if peer_ip == current_device.virtual_gateway {
            continue;
        }
        if peer_ips.len() == MAX_COUNT {
            break;
        }
        if let Some(members) = &multicast_members {
            if !members.read().is_send(&peer_ip) {
                continue;
            }
        }
        if route.is_p2p()
            && sender
                .try_send_by_key(net_packet.buffer(), &route.route_key())
                .is_ok()
        {
            peer_ips.push(peer_ip);
        } else {
            relay_count += 1;
        }
    }
    if relay_count == 0 && !peer_ips.is_empty() && peer_ips.len() != MAX_COUNT {
        //不需要转发
        return Ok(());
    }
    //转发到服务端的可选择广播，还要进行服务端加密
    if peer_ips.is_empty() {
        sender.send_main(net_packet.buffer(), current_device.connect_server)?;
    } else {
        let buf =
            vec![0u8; 12 + 1 + peer_ips.len() * 4 + net_packet.data_len() + ENCRYPTION_RESERVED];
        //剩余的发送到服务端，需要告知哪些已发送过
        let mut server_packet = NetPacket::new_encrypt(buf)?;
        server_packet.set_version(Version::V1);
        server_packet.set_gateway_flag(true);
        server_packet.first_set_ttl(MAX_TTL);
        server_packet.set_source(net_packet.source());
        //使用对应的目的地址
        server_packet.set_destination(net_packet.destination());
        server_packet.set_protocol(protocol::Protocol::IpTurn);
        server_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4Broadcast.into());

        let mut broadcast = BroadcastPacket::unchecked(server_packet.payload_mut());
        broadcast.set_address(&peer_ips)?;
        broadcast.set_data(net_packet.buffer())?;
        server_cipher.encrypt_ipv4(&mut server_packet)?;
        sender.send_main(server_packet.buffer(), current_device.connect_server)?;
    }
    Ok(())
}

/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节结尾|
///
#[inline]
pub fn base_handle(
    sender: &ChannelSender,
    buf: &mut [u8],
    data_len: usize, //数据总长度=12+ip包长度
    igmp_server: &Option<IgmpServer>,
    current_device: CurrentDeviceInfo,
    ip_route: &Option<ExternalRoute>,
    #[cfg(feature = "ip_proxy")] proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
) -> Result<()> {
    let ipv4_packet = IpV4Packet::new(&buf[12..data_len])?;
    let protocol = ipv4_packet.protocol();
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    let mut net_packet = NetPacket::new0(data_len, buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
    net_packet.first_set_ttl(3);
    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        if protocol == Protocol::Icmp {
            net_packet.set_gateway_flag(true);
            server_cipher.encrypt_ipv4(&mut net_packet)?;
            sender.send_main(net_packet.buffer(), current_device.connect_server)?;
        }
        return Ok(());
    }
    if dest_ip.is_multicast() {
        match protocol {
            Protocol::Igmp => {
                if igmp_server.is_some() {
                    //发送到服务端
                    net_packet.set_destination(current_device.virtual_gateway);
                    net_packet.set_gateway_flag(true);
                    server_cipher.encrypt_ipv4(&mut net_packet)?;
                    sender.send_main(net_packet.buffer(), current_device.connect_server)?;
                }
            }
            Protocol::Udp => {
                let multicast_members = if let Some(igmp_server) = igmp_server {
                    igmp_server.load(&dest_ip)
                } else {
                    //当作广播处理
                    net_packet.set_destination(Ipv4Addr::BROADCAST);
                    None
                };
                client_cipher.encrypt_ipv4(&mut net_packet)?;
                broadcast(
                    server_cipher,
                    multicast_members,
                    sender,
                    &mut net_packet,
                    &current_device,
                )?;
            }
            _ => {}
        }
        return Ok(());
    }
    if dest_ip.is_broadcast() || current_device.broadcast_address == dest_ip {
        // 广播 发送到直连目标
        client_cipher.encrypt_ipv4(&mut net_packet)?;
        broadcast(
            server_cipher,
            None,
            sender,
            &mut net_packet,
            &current_device,
        )?;
        return Ok(());
    }
    if !check_dest(
        dest_ip,
        current_device.virtual_netmask,
        current_device.virtual_network,
    ) {
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
    }
    #[cfg(feature = "ip_proxy")]
    if let Some(proxy_map) = proxy_map {
        let mut ipv4_packet = IpV4Packet::new(net_packet.payload_mut())?;
        proxy_map.send_handle(&mut ipv4_packet)?;
    }
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    //优先发到直连到地址
    if sender
        .try_send_by_id(net_packet.buffer(), &dest_ip)
        .is_err()
    {
        sender.send_main(net_packet.buffer(), current_device.connect_server)?;
    }
    return Ok(());
}
