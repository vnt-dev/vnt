use crossbeam_utils::atomic::AtomicCell;
use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::ip::ipv4::protocol::Protocol;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};
use tun_rs::SyncDevice;

use crate::channel::context::ChannelContext;
use crate::channel::sender::{send_to_wg, send_to_wg_broadcast};
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::ProxyHandler;
use crate::protocol;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::ip_turn_packet::BroadcastPacket;
use crate::protocol::{ip_turn_packet, NetPacket, MAX_TTL};
use crate::util::StopManager;
fn icmp(device_writer: &SyncDevice, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> anyhow::Result<()> {
    if ipv4_packet.protocol() == Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            device_writer.send(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

pub fn start(
    stop_manager: StopManager,
    context: ChannelContext,
    device: Arc<SyncDevice>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    compressor: Compressor,
    device_stop: DeviceStop,
    allow_wire_guard: bool,
) -> io::Result<()> {
    thread::Builder::new()
        .name("tunHandlerS".into())
        .spawn(move || {
            if let Err(e) = crate::handle::tun_tap::start_simple(
                stop_manager,
                &context,
                device,
                current_device,
                ip_route,
                #[cfg(feature = "ip_proxy")]
                ip_proxy_map,
                client_cipher,
                server_cipher,
                device_map,
                compressor,
                device_stop,
                allow_wire_guard,
            ) {
                log::warn!("stop:{}", e);
            }
        })?;

    Ok(())
}

fn broadcast(
    server_cipher: &Cipher,
    sender: &ChannelContext,
    net_packet: &mut NetPacket<&mut [u8]>,
    current_device: &CurrentDeviceInfo,
    device_map: &Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>,
) -> anyhow::Result<()> {
    let list: Vec<Ipv4Addr> = device_map
        .lock()
        .1
        .values()
        .filter(|info| !info.wireguard && info.status.is_online())
        .map(|info| info.virtual_ip)
        .collect();
    if list.is_empty() {
        return Ok(());
    }
    const MAX_COUNT: usize = 8;
    let mut p2p_ips = Vec::with_capacity(8);
    let mut relay = false;
    let mut overflow = false;
    for (index, peer_ip) in list.into_iter().enumerate() {
        if index > MAX_COUNT {
            overflow = true;
            break;
        }
        if let Some(route) = sender.route_table.route_one_p2p(&peer_ip) {
            if sender.send_by_key(&net_packet, route.route_key()).is_ok() {
                p2p_ips.push(peer_ip);
                continue;
            }
        }
        relay = true;
    }
    if !overflow && !relay {
        //全部p2p,不需要服务器中转
        return Ok(());
    }
    if current_device.status.offline() {
        //离线的不再转发
        return Ok(());
    }
    if p2p_ips.is_empty() {
        //都没有p2p则直接由服务器转发
        sender.send_default(&net_packet, current_device.connect_server)?;
        return Ok(());
    }

    let buf = vec![0u8; 12 + 1 + p2p_ips.len() * 4 + net_packet.data_len() + ENCRYPTION_RESERVED];
    //剩余的发送到服务端，需要告知哪些已发送过
    let mut server_packet = NetPacket::new_encrypt(buf)?;
    server_packet.set_default_version();
    server_packet.set_gateway_flag(true);
    server_packet.first_set_ttl(MAX_TTL);
    server_packet.set_source(net_packet.source());
    //使用对应的目的地址
    server_packet.set_destination(net_packet.destination());
    server_packet.set_protocol(protocol::Protocol::IpTurn);
    server_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4Broadcast.into());

    let mut broadcast = BroadcastPacket::unchecked(server_packet.payload_mut());
    broadcast.set_address(&p2p_ips)?;
    broadcast.set_data(net_packet.buffer())?;
    server_cipher.encrypt_ipv4(&mut server_packet)?;
    sender.send_default(&server_packet, current_device.connect_server)?;
    Ok(())
}

/// 接收tun数据，并且转发到udp上
/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节结尾|
///
pub(crate) fn handle(
    context: &ChannelContext,
    buf: &mut [u8],
    data_len: usize, //数据总长度=12+ip包长度
    extend: &mut [u8],
    device_writer: &SyncDevice,
    current_device: CurrentDeviceInfo,
    ip_route: &ExternalRoute,
    #[cfg(feature = "ip_proxy")] proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
    device_map: &Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>,
    compressor: &Compressor,
    allow_wire_guard: bool,
) -> anyhow::Result<()> {
    //忽略掉结构不对的情况（ipv6数据、win tap会读到空数据），不然日志打印太多了
    let ipv4_packet = match IpV4Packet::new(&mut buf[12..data_len]) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    if src_ip == dest_ip {
        return icmp(&device_writer, ipv4_packet);
    }
    let protocol = ipv4_packet.protocol();
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    let mut net_packet = NetPacket::new0(data_len, buf)?;
    let mut out = NetPacket::unchecked(extend);
    net_packet.set_default_version();
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
    net_packet.first_set_ttl(6);
    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        // 发到网关的加密方式不一样，要单独处理
        if protocol == Protocol::Icmp {
            net_packet.set_gateway_flag(true);
            server_cipher.encrypt_ipv4(&mut net_packet)?;
            context.send_default(&net_packet, current_device.connect_server)?;
        }
        return Ok(());
    }
    if !dest_ip.is_multicast() && !dest_ip.is_broadcast() && current_device.broadcast_ip != dest_ip
    {
        if current_device.not_in_network(dest_ip) {
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
        }
        #[cfg(feature = "ip_proxy")]
        if let Some(proxy_map) = proxy_map {
            let mut ipv4_packet = IpV4Packet::new(net_packet.payload_mut())?;
            proxy_map.send_handle(&mut ipv4_packet)?;
        }
    }

    if dest_ip.is_multicast() {
        //当作广播处理
        dest_ip = Ipv4Addr::BROADCAST;
        net_packet.set_destination(Ipv4Addr::BROADCAST);
    }
    let is_broadcast = dest_ip.is_broadcast() || current_device.broadcast_ip == dest_ip;
    if allow_wire_guard {
        if is_broadcast {
            // wg客户端和vnt客户端分开广播
            let exists_wg = device_map
                .lock()
                .1
                .values()
                .any(|v| v.status.is_online() && v.wireguard);
            if exists_wg {
                send_to_wg_broadcast(context, &net_packet, server_cipher, &current_device)?;
            }
        } else {
            // 如果是wg客户端则发到vnts转发
            let guard = device_map.lock();
            if let Some(peer_info) = guard.1.get(&dest_ip) {
                if peer_info.status.is_offline() {
                    return Ok(());
                }
                if peer_info.wireguard {
                    drop(guard);
                    send_to_wg(context, &mut net_packet, server_cipher, &current_device)?;
                    return Ok(());
                }
            }
        }
    }

    let mut net_packet = if compressor.compress(&net_packet, &mut out)? {
        out.set_default_version();
        out.set_protocol(protocol::Protocol::IpTurn);
        out.set_transport_protocol(ip_turn_packet::Protocol::Ipv4.into());
        out.first_set_ttl(6);
        out.set_source(src_ip);
        out.set_destination(dest_ip);
        out
    } else {
        net_packet
    };
    if is_broadcast {
        // 广播 发送到直连目标
        client_cipher.encrypt_ipv4(&mut net_packet)?;
        broadcast(
            server_cipher,
            context,
            &mut net_packet,
            &current_device,
            device_map,
        )?;
        return Ok(());
    }

    client_cipher.encrypt_ipv4(&mut net_packet)?;
    context.send_ipv4_by_id(
        &net_packet,
        &dest_ip,
        current_device.connect_server,
        current_device.status.online(),
    )?;
    Ok(())
}
