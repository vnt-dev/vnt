use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use std::io;

use chrono::Local;
use crossbeam::atomic::AtomicCell;
use parking_lot::Mutex;
use rand::prelude::SliceRandom;
use crate::channel::idle::Idle;
use crate::channel::Route;
use crate::channel::sender::ChannelSender;


use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{control_packet, NetPacket, Protocol, Version};

pub async fn start_idle(idle: Idle, sender: ChannelSender) {
    tokio::spawn(async move {
        match start_idle_(idle, sender).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("空闲检测任务停止:{:?}", e);
            }
        }
    });
}

async fn start_idle_(idle: Idle, sender: ChannelSender) -> io::Result<()> {
    loop {
        let (peer_ip, route) = idle.next_idle().await?;
        log::info!(
            "peer_ip:{:?},route:{:?}",
            peer_ip,
            route
        );
        sender.remove_route(&peer_ip, route);
    }
}

pub async fn start_heartbeat(
    sender: ChannelSender,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
) {
    tokio::spawn(async move {
        if let Err(e) = start_heartbeat_(sender, device_list, current_device).await {
            log::warn!("心跳任务停止:{:?}", e);
        }
    });
}

fn set_now_time(packet: &mut NetPacket<[u8; 16]>) -> io::Result<()> {
    let current_time = Local::now().timestamp_millis() as u16;
    let mut ping = PingPacket::new(packet.payload_mut())?;
    ping.set_time(current_time);
    Ok(())
}

async fn start_heartbeat_(
    sender: ChannelSender,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
) -> io::Result<()> {
    let mut net_packet = NetPacket::new([0u8; 16])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
    //只寻找两跳以内能到的目标
    net_packet.first_set_ttl(2);
    let mut count = 0;
    loop {
        let current_device = current_device.load();
        net_packet.set_source(current_device.virtual_ip());
        {
            let mut ping = PingPacket::new(net_packet.payload_mut())?;
            let epoch = { device_list.lock().0 };
            ping.set_epoch(epoch);
        }
        set_now_time(&mut net_packet)?;
        net_packet.set_destination(current_device.virtual_gateway());
        if let Err(e) = sender.send_main(net_packet.buffer(), current_device.connect_server).await
        {
            log::warn!(
                    "connect_server:{:?},e:{:?}",
                    current_device.connect_server,
                    e
                );
        }
        if count < 7 || count % 7 == 0 {
            let mut route_list: Option<Vec<(Ipv4Addr, Vec<Route>)>> = None;
            let peer_list = {device_list.lock().1.clone()};
            for peer in peer_list {
                set_now_time(&mut net_packet)?;
                net_packet.set_destination(peer.virtual_ip);
                if sender
                    .send_by_id(net_packet.buffer(), &peer.virtual_ip).await
                    .is_err()
                {
                    //没有路由则发送到网关
                    let _ = sender.try_send_main(net_packet.buffer(), current_device.connect_server);
                    //再随机发送到其他地址，看有没有客户端符合转发条件
                    let route_list = route_list.get_or_insert_with(|| {
                        let mut l = sender.route_table();
                        l.shuffle(&mut rand::thread_rng());
                        l
                    });
                    let mut num = 0;
                    'a: for (peer_ip, route_list) in route_list.iter() {
                        for route in route_list {
                            if peer_ip != &peer.virtual_ip && route.metric == 1 {
                                set_now_time(&mut net_packet)?;
                                let _ = sender.try_send_by_key(net_packet.buffer(), &route.route_key());
                                num += 1;
                                break;
                            }
                            if num >= 3 {
                                break 'a;
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

        } else {
            for (peer_ip, route_list) in sender.route_table().iter() {
                set_now_time(&mut net_packet)?;
                net_packet.set_destination(*peer_ip);
                for route in route_list {
                    if let Err(e) = sender.send_by_key(net_packet.buffer(), &route.route_key()).await {
                        log::warn!("peer_ip:{:?},route:{:?},e:{:?}", peer_ip, route, e);
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }

        count += 1;
        tokio::time::sleep(Duration::from_millis(5000)).await;
    }
}
