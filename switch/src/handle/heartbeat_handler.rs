use std::{io, thread};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use crossbeam::atomic::AtomicCell;
use parking_lot::Mutex;
use rand::prelude::SliceRandom;

use p2p_channel::channel::Route;
use p2p_channel::channel::sender::Sender;
use p2p_channel::idle::Idle;

use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::protocol::{control_packet, MAX_TTL, NetPacket, Protocol, Version};
use crate::protocol::control_packet::PingPacket;

pub fn start_idle(idle: Idle<Ipv4Addr>, sender: Sender<Ipv4Addr>) {
    thread::Builder::new().name("idle".into()).spawn(move || {
        if let Err(e) = start_idle_(idle, sender) {
            log::info!("空闲检测线程停止:{:?}",e);
        }
    }).unwrap();
}

fn start_idle_(idle: Idle<Ipv4Addr>, sender: Sender<Ipv4Addr>) -> io::Result<()> {
    loop {
        let (idle_status, peer_ips, route) = idle.next_idle()?;
        log::warn!("peer_ip:{:?},route:{:?},idle_status:{:?}",peer_ips,route,idle_status);
        for peer_ip in peer_ips {
            sender.remove_route(&peer_ip);
        }
    }
}

pub fn start_heartbeat(sender: Sender<Ipv4Addr>, device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) {
    thread::Builder::new().name("heartbeat".into()).spawn(move || {
        if let Err(e) = start_heartbeat_(sender, device_list, current_device) {
            log::info!("空闲检测线程停止:{:?}",e);
        }
    }).unwrap();
}

fn set_now_time(packet: &mut NetPacket<[u8; 16]>) -> io::Result<()> {
    let current_time = Local::now().timestamp_millis() as u16;
    let mut ping = PingPacket::new(packet.payload_mut())?;
    ping.set_time(current_time);
    Ok(())
}

fn start_heartbeat_(sender: Sender<Ipv4Addr>, device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> io::Result<()> {
    let mut net_packet = NetPacket::new([0u8; 16])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
    net_packet.first_set_ttl(MAX_TTL);
    let mut count = 0;
    loop {
        let current_device = current_device.load();
        net_packet.set_source(current_device.virtual_ip());
        {
            let mut ping = PingPacket::new(net_packet.payload_mut())?;
            let epoch = { device_list.lock().0 };
            ping.set_epoch(epoch);
        }
        if count < 7 || count % 7 == 0 {
            let mut route_list: Option<Vec<(Ipv4Addr, Route)>> = None;
            let peer_list = device_list.lock().1.clone();
            for peer in peer_list {
                set_now_time(&mut net_packet)?;
                net_packet.first_set_ttl(MAX_TTL);
                net_packet.set_destination(peer.virtual_ip);
                if sender.send_to_id(net_packet.buffer(), &peer.virtual_ip).is_err() {
                    //没有路由则发送到网关
                    let _ = sender.send_to_addr(net_packet.buffer(), current_device.connect_server);
                    //再随机发送到其他地址，看有没有客户端符合转发条件
                    let route_list = route_list.get_or_insert_with(|| {
                        let mut l = sender.route_table();
                        l.shuffle(&mut rand::thread_rng());
                        l
                    });
                    let mut num = 0;
                    net_packet.first_set_ttl(2);
                    for (peer_ip, route) in route_list.iter() {
                        if peer_ip != &peer.virtual_ip && route.metric == 1 {
                            set_now_time(&mut net_packet)?;
                            let _ = sender.send_to_route(net_packet.buffer(), &route.route_key());
                            num += 1;
                        }
                        if num >= 3 {
                            break;
                        }
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            set_now_time(&mut net_packet)?;
            net_packet.set_destination(current_device.virtual_gateway());
            if let Err(e) = sender.send_to_addr(net_packet.buffer(), current_device.connect_server) {
                log::warn!("connect_server:{:?},e:{:?}",current_device.connect_server,e);
            }
        } else {
            for (peer_ip, route) in sender.route_table().iter() {
                set_now_time(&mut net_packet)?;
                net_packet.set_destination(*peer_ip);
                if let Err(e) = sender.send_to_route(net_packet.buffer(), &route.route_key()) {
                    log::warn!("peer_ip:{:?},route:{:?},e:{:?}",peer_ip,route,e);
                }
                thread::sleep(Duration::from_millis(1));
            }
        }

        count += 1;
        thread::sleep(Duration::from_millis(5000));
    }
}