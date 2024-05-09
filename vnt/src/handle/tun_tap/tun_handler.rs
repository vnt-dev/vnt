use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::ip::ipv4::protocol::Protocol;
use tun::device::IFace;
use tun::Device;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::channel_group::channel_group;
use crate::handle::{check_dest, CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::ip_proxy::ProxyHandler;
use crate::protocol;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::ip_turn_packet::BroadcastPacket;
use crate::protocol::{ip_turn_packet, NetPacket, MAX_TTL};
use crate::util::{SingleU64Adder, StopManager};

fn icmp(device_writer: &Device, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> io::Result<()> {
    if ipv4_packet.protocol() == Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            device_writer.write(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

/// 接收tun数据，并且转发到udp上
pub(crate) fn handle(
    context: &ChannelContext,
    data: &mut [u8],
    len: usize,
    device_writer: &Device,
    current_device: CurrentDeviceInfo,
    ip_route: &ExternalRoute,
    #[cfg(feature = "ip_proxy")] proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
) -> io::Result<()> {
    //忽略掉结构不对的情况（ipv6数据、win tap会读到空数据），不然日志打印太多了
    let ipv4_packet = match IpV4Packet::new(&mut data[12..len]) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    if src_ip == dest_ip {
        return icmp(&device_writer, ipv4_packet);
    }
    return base_handle(
        context,
        data,
        len,
        current_device,
        ip_route,
        #[cfg(feature = "ip_proxy")]
        proxy_map,
        client_cipher,
        server_cipher,
        device_list,
    );
}

pub fn start(
    stop_manager: StopManager,
    context: ChannelContext,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    parallel: usize,
    mut up_counter: SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
) -> io::Result<()> {
    if parallel > 1 {
        let (sender, receivers) = channel_group::<(Vec<u8>, usize)>(parallel, 16);
        for (index, receiver) in receivers.into_iter().enumerate() {
            let context = context.clone();
            let device = device.clone();
            let current_device = current_device.clone();
            let ip_route = ip_route.clone();
            #[cfg(feature = "ip_proxy")]
            let ip_proxy_map = ip_proxy_map.clone();
            let client_cipher = client_cipher.clone();
            let server_cipher = server_cipher.clone();
            let device_list = device_list.clone();
            thread::Builder::new()
                .name(format!("tunHandler-{}", index))
                .spawn(move || {
                    while let Ok((mut buf, len)) = receiver.recv() {
                        #[cfg(not(target_os = "macos"))]
                        let start = 0;
                        #[cfg(target_os = "macos")]
                        let start = 4;
                        match handle(
                            &context,
                            &mut buf[start..],
                            len,
                            &device,
                            current_device.load(),
                            &ip_route,
                            #[cfg(feature = "ip_proxy")]
                            &ip_proxy_map,
                            &client_cipher,
                            &server_cipher,
                            &device_list,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!("{:?}", e)
                            }
                        }
                    }
                })?;
        }
        thread::Builder::new()
            .name("tunHandlerM".into())
            .spawn(move || {
                if let Err(e) = crate::handle::tun_tap::start_multi(
                    stop_manager,
                    device,
                    sender,
                    &mut up_counter,
                ) {
                    log::warn!("stop:{}", e);
                }
            })?;
    } else {
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
                    &mut up_counter,
                    device_list,
                ) {
                    log::warn!("stop:{}", e);
                }
            })?;
    }
    Ok(())
}

fn broadcast(
    server_cipher: &Cipher,
    sender: &ChannelContext,
    net_packet: &mut NetPacket<&mut [u8]>,
    current_device: &CurrentDeviceInfo,
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
) -> io::Result<()> {
    let list: Vec<Ipv4Addr> = device_list
        .lock()
        .1
        .iter()
        .filter(|info| info.status.is_online())
        .map(|info| info.virtual_ip)
        .collect();
    const MAX_COUNT: usize = 8;
    let mut p2p_ips = Vec::with_capacity(8);
    let mut relay_ips = Vec::with_capacity(8);
    let mut overflow = false;
    for (index, peer_ip) in list.into_iter().enumerate() {
        if index > MAX_COUNT {
            overflow = true;
            break;
        }
        if let Some(route) = sender.route_table.route_one_p2p(&peer_ip) {
            if sender
                .send_by_key(net_packet.buffer(), route.route_key())
                .is_ok()
            {
                p2p_ips.push(peer_ip);
                continue;
            }
        }
        relay_ips.push(peer_ip);
    }
    if !overflow && relay_ips.is_empty() {
        //全部p2p,不需要服务器中转
        return Ok(());
    }

    if p2p_ips.is_empty() {
        //都没有p2p则直接由服务器转发
        if current_device.status.online() {
            sender.send_default(net_packet.buffer(), current_device.connect_server)?;
        }
        return Ok(());
    }
    if !overflow && relay_ips.len() == 2 {
        // 如果转发的ip数不多就直接发
        for peer_ip in relay_ips {
            //非直连的广播要改变目的地址，不然服务端收到了会再次广播
            net_packet.set_destination(peer_ip);
            sender.send_ipv4_by_id(
                net_packet.buffer(),
                &peer_ip,
                current_device.connect_server,
                current_device.status.online(),
            )?;
        }
        return Ok(());
    }
    if current_device.status.offline() {
        //离线的不再转发
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
    sender.send_default(server_packet.buffer(), current_device.connect_server)
}

/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节结尾|
///
#[inline]
fn base_handle(
    context: &ChannelContext,
    buf: &mut [u8],
    data_len: usize, //数据总长度=12+ip包长度
    current_device: CurrentDeviceInfo,
    ip_route: &ExternalRoute,
    #[cfg(feature = "ip_proxy")] proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
) -> io::Result<()> {
    let ipv4_packet = IpV4Packet::new(&buf[12..data_len])?;
    let protocol = ipv4_packet.protocol();
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    let mut net_packet = NetPacket::new0(data_len, buf)?;
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
            context.send_default(net_packet.buffer(), current_device.connect_server)?;
        }
        return Ok(());
    }
    if dest_ip.is_multicast() {
        //当作广播处理
        dest_ip = Ipv4Addr::BROADCAST;
        net_packet.set_destination(Ipv4Addr::BROADCAST);
    }
    if dest_ip.is_broadcast() || current_device.broadcast_ip == dest_ip {
        // 广播 发送到直连目标
        client_cipher.encrypt_ipv4(&mut net_packet)?;
        broadcast(
            server_cipher,
            context,
            &mut net_packet,
            &current_device,
            device_list,
        )?;
        return Ok(());
    }
    if !check_dest(
        dest_ip,
        current_device.virtual_netmask,
        current_device.virtual_network,
    ) {
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
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    context.send_ipv4_by_id(
        net_packet.buffer(),
        &dest_ip,
        current_device.connect_server,
        current_device.status.online(),
    )
}
