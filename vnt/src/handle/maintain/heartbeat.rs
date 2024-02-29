use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use rand::prelude::SliceRandom;

use crate::channel::context::Context;
use crate::cipher::Cipher;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{control_packet, NetPacket, Protocol, Version, MAX_TTL};
use crate::util::Scheduler;

/// 定时发送心跳包
pub fn heartbeat(
    scheduler: &Scheduler,
    context: Context,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    client_cipher: Cipher,
    server_cipher: Cipher,
) {
    heartbeat0(
        &context,
        &current_device_info.load(),
        &device_list,
        &client_cipher,
        &server_cipher,
    );
    // 心跳包 3秒发送一次
    let rs = scheduler.timeout(Duration::from_secs(3), |s| {
        heartbeat(
            s,
            context,
            current_device_info,
            device_list,
            client_cipher,
            server_cipher,
        )
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn heartbeat0(
    context: &Context,
    current_device: &CurrentDeviceInfo,
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
) {
    let gateway_ip = current_device.virtual_gateway;
    let src_ip = current_device.virtual_ip;
    // 可能服务器ip发生变化，导致发送失败
    let mut is_send_gateway = false;
    match heartbeat_packet_server(device_list, server_cipher, src_ip, gateway_ip) {
        Ok(net_packet) => {
            if let Err(e) = context.send_default(net_packet.buffer(), current_device.connect_server)
            {
                log::warn!("heartbeat err={:?}", e)
            } else {
                is_send_gateway = true
            }
        }
        Err(e) => {
            log::error!("heartbeat_packet err={:?}", e);
        }
    }

    for (dest_ip, routes) in context.route_table.route_table() {
        let net_packet = if current_device.is_gateway(&dest_ip) {
            if is_send_gateway {
                continue;
            }
            heartbeat_packet_server(device_list, server_cipher, src_ip, gateway_ip)
        } else {
            heartbeat_packet_client(client_cipher, src_ip, dest_ip)
        };
        let net_packet = match net_packet {
            Ok(net_packet) => net_packet,
            Err(e) => {
                log::error!("heartbeat_packet err={:?}", e);
                continue;
            }
        };
        for route in routes {
            if let Err(e) = context.send_by_key(net_packet.buffer(), route.route_key()) {
                log::warn!("heartbeat err={:?}", e)
            }
        }
    }
    let peer_list = { device_list.lock().1.clone() };
    for peer in &peer_list {
        if !peer.status.is_online() {
            continue;
        }
        if current_device.is_gateway(&peer.virtual_ip) {
            continue;
        }
        if context.route_table.route_one(&peer.virtual_ip).is_none() {
            //路由为空，则向服务端地址发送
            let net_packet = match heartbeat_packet_client(client_cipher, src_ip, peer.virtual_ip) {
                Ok(net_packet) => net_packet,
                Err(e) => {
                    log::error!("heartbeat_packet err={:?}", e);
                    continue;
                }
            };
            if let Err(e) = context.send_default(net_packet.buffer(), current_device.connect_server)
            {
                log::error!("heartbeat_packet send_default err={:?}", e);
            }
        }
    }
}

/// 客户端中继路径探测,延迟启动
pub fn client_relay(
    scheduler: &Scheduler,
    context: Context,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    client_cipher: Cipher,
) {
    let rs = scheduler.timeout(Duration::from_secs(30), move |s| {
        client_relay_(s, context, current_device, device_list, client_cipher)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

/// 客户端中继路径探测,每30秒探测一次
fn client_relay_(
    scheduler: &Scheduler,
    context: Context,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    client_cipher: Cipher,
) {
    if let Err(e) = client_relay0(
        &context,
        &current_device.load(),
        &device_list,
        &client_cipher,
    ) {
        log::error!("{:?}", e);
    }
    let rs = scheduler.timeout(Duration::from_secs(30), move |s| {
        client_relay_(s, context, current_device, device_list, client_cipher)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn client_relay0(
    context: &Context,
    current_device: &CurrentDeviceInfo,
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
    client_cipher: &Cipher,
) -> io::Result<()> {
    let peer_list = { device_list.lock().1.clone() };
    let mut routes = context.route_table.route_table_p2p();
    for peer in &peer_list {
        if peer.virtual_ip == current_device.virtual_ip {
            continue;
        }
        if let Some(route) = context.route_table.route_one(&peer.virtual_ip) {
            if route.is_p2p() && !context.first_latency() {
                continue;
            }
        }
        let client_packet =
            heartbeat_packet_client(client_cipher, current_device.virtual_ip, peer.virtual_ip)?;

        //随机发送到其他地址，看有没有客户端符合转发条件
        routes.shuffle(&mut rand::thread_rng());

        for (index, (ip, route)) in routes.iter().enumerate() {
            if current_device.is_gateway(ip) {
                continue;
            }
            if let Err(e) = context.send_by_key(client_packet.buffer(), route.route_key()) {
                log::error!("{:?}", e);
            }
            if index >= 2 {
                break;
            }
        }
    }
    Ok(())
}

/// 构建心跳包
fn heartbeat_packet(
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> io::Result<NetPacket<[u8; 12 + 4 + ENCRYPTION_RESERVED]>> {
    let mut net_packet = NetPacket::new_encrypt([0u8; 12 + 4 + ENCRYPTION_RESERVED])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(src);
    net_packet.set_destination(dest);
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_time(crate::handle::now_time() as u16);
    Ok(net_packet)
}

fn heartbeat_packet_client(
    client_cipher: &Cipher,
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> io::Result<NetPacket<[u8; 12 + 4 + ENCRYPTION_RESERVED]>> {
    let mut net_packet = heartbeat_packet(src, dest)?;
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}

fn heartbeat_packet_server(
    device_list: &Mutex<(u16, Vec<PeerDeviceInfo>)>,
    server_cipher: &Cipher,
    src: Ipv4Addr,
    dest: Ipv4Addr,
) -> io::Result<NetPacket<[u8; 12 + 4 + ENCRYPTION_RESERVED]>> {
    let mut net_packet = heartbeat_packet(src, dest)?;
    let mut ping = PingPacket::new(net_packet.payload_mut())?;
    ping.set_epoch(device_list.lock().0);
    net_packet.set_gateway_flag(true);
    server_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
