use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;
use std::{io, thread};

use protobuf::Message;
use rand::prelude::SliceRandom;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;

use crate::error::*;
use crate::handle::{ApplicationStatus, DIRECT_ROUTE_TABLE};
use crate::proto::message::{NatType, Punch};
use crate::protocol::control_packet::PunchRequestPacket;
use crate::protocol::turn_packet::TurnPacket;
use crate::protocol::{control_packet, turn_packet, NetPacket, Protocol, Version};
use crate::{handle::NatInfo, handle::NAT_INFO, CurrentDeviceInfo, DEVICE_LIST};

/// 每一种类型一个通道，减少相互干扰
pub fn bounded() -> (
    PunchSender,
    ConeReceiver,
    ReqSymmetricReceiver,
    ResSymmetricReceiver,
) {
    let (cone_sender, cone_receiver) = tokio::sync::mpsc::channel(3);
    let (req_symmetric_sender, req_symmetric_receiver) = tokio::sync::mpsc::channel(1);
    let (res_symmetric_sender, res_symmetric_receiver) = tokio::sync::mpsc::channel(1);
    (
        PunchSender::new(cone_sender, req_symmetric_sender, res_symmetric_sender),
        ConeReceiver(cone_receiver),
        ReqSymmetricReceiver(req_symmetric_receiver),
        ResSymmetricReceiver(res_symmetric_receiver),
    )
}

pub struct ConeReceiver(Receiver<Punch>);

pub struct ReqSymmetricReceiver(Receiver<Punch>);

pub struct ResSymmetricReceiver(Receiver<Punch>);

#[derive(Clone)]
pub struct PunchSender {
    cone_sender: Sender<Punch>,
    req_symmetric_sender: Sender<Punch>,
    res_symmetric_sender: Sender<Punch>,
}

impl PunchSender {
    pub fn new(
        cone_sender: Sender<Punch>,
        req_symmetric_sender: Sender<Punch>,
        res_symmetric_sender: Sender<Punch>,
    ) -> Self {
        Self {
            cone_sender,
            req_symmetric_sender,
            res_symmetric_sender,
        }
    }
    // pub fn send(&self, punch: Punch) -> std::result::Result<(), SendError<Punch>> {
    //     match punch.nat_type.enum_value_or_default() {
    //         NatType::Symmetric => {
    //             if punch.reply {
    //                 // 为true表示回应，也就是主动发起的打洞操作
    //                 self.res_symmetric_sender.blocking_send(punch)
    //             } else {
    //                 self.req_symmetric_sender.blocking_send(punch)
    //             }
    //         }
    //         NatType::Cone => {
    //             self.cone_sender.blocking_send(punch)
    //         }
    //     }
    // }
    pub fn try_send(&self, punch: Punch) -> std::result::Result<(), TrySendError<Punch>> {
        match punch.nat_type.enum_value_or_default() {
            NatType::Symmetric => {
                if punch.reply {
                    // 为true表示回应，也就是主动发起的打洞操作
                    self.res_symmetric_sender.try_send(punch)
                } else {
                    self.req_symmetric_sender.try_send(punch)
                }
            }
            NatType::Cone => self.cone_sender.try_send(punch),
        }
    }
}

fn handle(
    _status_watch: &watch::Receiver<ApplicationStatus>,
    udp: &UdpSocket,
    punch_list: Vec<Punch>,
    buf: &[u8],
) -> Result<()> {
    let mut counter = 0u64;
    for punch in punch_list {
        let dest = Ipv4Addr::from(punch.virtual_ip);
        if DIRECT_ROUTE_TABLE.contains_key(&dest) {
            continue;
        }
        // println!("punch {:?}", punch);
        match punch.nat_type.enum_value_or_default() {
            NatType::Symmetric => {
                // 碰撞概率 p = 1 - e^(-(k^2+k)/(2n))    n = max_port-min_port+1 关键词：生日攻击
                let mut send_f = |min_port: u16, max_port: u16, k: usize| -> io::Result<()> {
                    let mut nums: Vec<u16> = (min_port..max_port).collect();
                    nums.push(max_port);
                    let mut rng = rand::thread_rng();
                    nums.shuffle(&mut rng);
                    for pub_ip in &punch.public_ip_list {
                        let pub_ip = Ipv4Addr::from(*pub_ip);
                        for port in &nums[..k] {
                            udp.send_to(buf, SocketAddr::V4(SocketAddrV4::new(pub_ip, *port)))?;
                            select_sleep(&mut counter);
                        }
                    }
                    Ok(())
                };
                if punch.public_port_range < 600 {
                    //端口变化不大时，在预测的范围内随机发送
                    //如果公网端口在这个范围的话，碰撞的概率最低为70%;
                    let min_port = if punch.public_port > punch.public_port_range {
                        punch.public_port - punch.public_port_range
                    } else {
                        1
                    };
                    let max_port = if punch.public_port + punch.public_port_range > 65535 {
                        65535
                    } else {
                        punch.public_port + punch.public_port_range
                    };
                    let k = if max_port - min_port + 1 > 60 {
                        60
                    } else {
                        max_port - min_port + 1
                    };
                    send_f(min_port as u16, max_port as u16, k as usize)?;
                }
                // 全端口范围，随机取600个端口发送
                // 取600个端口碰撞的概率为 93.6%，理论上成功的概率还是很高的
                send_f(1, 65535, 600)?;
            }
            NatType::Cone => {
                for pub_ip in punch.public_ip_list {
                    udp.send_to(
                        buf,
                        SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(pub_ip),
                            punch.public_port as u16,
                        )),
                    )?;
                    select_sleep(&mut counter);
                }
            }
        }
    }
    Ok(())
}

/// 给对称nat发送打洞数据包
pub async fn req_symmetric_handler_start<F>(
    status_watch: watch::Receiver<ApplicationStatus>,
    receiver: ReqSymmetricReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
    stop_fn: F,
) where
    F: FnOnce() + Send + 'static,
{
    let receiver = receiver.0;
    tokio::spawn(async move {
        match handle_loop(status_watch, receiver, udp, cur_info).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
        stop_fn()
    });
}

// pub fn req_symmetric_handle_loop(
//     receiver: ReqSymmetricReceiver,
//     udp: UdpSocket,
//     cur_info: CurrentDeviceInfo,
// ) -> Result<()> {
//     let receiver = receiver.0;
//     handle_loop(receiver, udp, cur_info)
// }

/// 给对称nat发送打洞数据包，处理主动发起的打洞操作
pub async fn res_symmetric_handler_start<F>(
    status_watch: watch::Receiver<ApplicationStatus>,
    receiver: ResSymmetricReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
    stop_fn: F,
) where
    F: FnOnce() + Send + 'static,
{
    let receiver = receiver.0;
    tokio::spawn(async move {
        match res_symmetric_handle_loop(status_watch, receiver, udp, cur_info).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
        stop_fn()
    });
}

async fn res_symmetric_handle_loop(
    mut status_watch: watch::Receiver<ApplicationStatus>,
    mut receiver: Receiver<Punch>,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let mut buf = [0u8; 12];
    let mut packet = NetPacket::new(&mut buf)?;
    packet.set_version(Version::V1);
    packet.set_ttl(255);
    packet.set_protocol(Protocol::Control);
    packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
    {
        let mut punch_packet = PunchRequestPacket::new(packet.payload_mut())?;
        punch_packet.set_source(cur_info.virtual_ip);
    }
    loop {
        tokio::select! {
            rs = tokio::time::timeout(Duration::from_secs(20), receiver.recv()) =>{
                match rs {
                    Ok(punch) => {
                        if let Some(punch) = punch{
                            let mut list = Vec::new();
                            list.push(punch);
                            loop {
                                match receiver.try_recv() {
                                    Ok(punch) => {
                                        list.push(punch);
                                    }
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                            if let Err(e) = handle(&status_watch,&udp, list, packet.buffer()) {
                                log::warn!("{:?}",e)
                            }
                        }else {
                            return Err(Error::Stop("打洞线程通道关闭".to_string()));
                        }
                    }
                    Err(_) => {
                        punch_request_handle(&udp, &cur_info)?;
                    }
                }
            }
            status = status_watch.changed() =>{
                status?;
                if *status_watch.borrow() != ApplicationStatus::Starting{
                    return Ok(())
                }
            }
        }
    }
}

/// 给锥形nat发送打洞数据包
pub async fn cone_handler_start<F>(
    status_watch: watch::Receiver<ApplicationStatus>,
    receiver: ConeReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
    stop_fn: F,
) where
    F: FnOnce() + Send + 'static,
{
    let receiver = receiver.0;
    tokio::spawn(async move {
        match handle_loop(status_watch, receiver, udp, cur_info).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
        stop_fn();
    });
}

async fn handle_loop(
    mut status_watch: watch::Receiver<ApplicationStatus>,
    mut receiver: Receiver<Punch>,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let mut buf = [0u8; 12];
    let mut packet = NetPacket::new(&mut buf)?;
    packet.set_version(Version::V1);
    packet.set_ttl(255);
    packet.set_protocol(Protocol::Control);
    packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
    {
        let mut punch_packet = PunchRequestPacket::new(packet.payload_mut())?;
        punch_packet.set_source(cur_info.virtual_ip);
    }
    loop {
        tokio::select! {
            punch = receiver.recv() =>{
                 if let Some(punch) = punch{
                     let mut list = Vec::new();
                        list.push(punch);
                        loop {
                            match receiver.try_recv() {
                                Ok(punch) => {
                                    list.push(punch);
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                        if let Err(e) = handle(&status_watch,&udp, list, packet.buffer()) {
                            log::warn!("{:?}",e)
                        }
                 }else {
                     return Err(Error::Stop("打洞线程通道关闭".to_string()));
                 }
            }
             status = status_watch.changed() =>{
                status?;
                if *status_watch.borrow() != ApplicationStatus::Starting{
                    return Ok(())
                }
            }
        }
    }
}

fn select_sleep(counter: &mut u64) {
    *counter += 1;
    if *counter & 10 == 10 {
        thread::sleep(Duration::from_millis(2));
    } else {
        thread::sleep(Duration::from_millis(1));
    }
}

fn punch_request_handle(udp: &UdpSocket, cur_info: &CurrentDeviceInfo) -> Result<()> {
    let nat_info_lock = NAT_INFO.lock();
    let nat_info = nat_info_lock.clone();
    drop(nat_info_lock);
    if let Some(nat_info) = nat_info {
        if let Err(e) = send_punch(&udp, &cur_info, nat_info) {
            log::warn!("发送打洞数据失败 {:?}", e)
        }
        Ok(())
    } else {
        Err(Error::Stop("未初始化nat信息".to_string()))
    }
}

fn send_punch(udp: &UdpSocket, cur_info: &CurrentDeviceInfo, nat_info: NatInfo) -> Result<()> {
    let lock = DEVICE_LIST.lock();
    let list = lock.1.clone();
    drop(lock);
    for peer_info in list {
        let ip = peer_info.virtual_ip;
        //只向ip比自己大的发起打洞，避免双方同时发起打洞浪费流量
        if ip > cur_info.virtual_ip && !DIRECT_ROUTE_TABLE.contains_key(&ip) {
            log::info!("发起打洞  {:?}, peer_info:{:?}", nat_info, peer_info);
            let bytes = punch_packet(cur_info.virtual_ip, nat_info.clone(), ip)?;
            udp.send_to(&bytes, cur_info.connect_server)?;
        }
    }
    Ok(())
}

fn punch_packet(virtual_ip: Ipv4Addr, nat_info: NatInfo, dest: Ipv4Addr) -> Result<Vec<u8>> {
    let mut punch_reply = Punch::new();
    punch_reply.reply = false;
    punch_reply.virtual_ip = u32::from_be_bytes(virtual_ip.octets());
    punch_reply.public_ip_list = nat_info.public_ips;
    punch_reply.public_port = nat_info.public_port as u32;
    punch_reply.public_port_range = nat_info.public_port_range as u32;
    punch_reply.nat_type = protobuf::EnumOrUnknown::new(nat_info.nat_type);
    let bytes = punch_reply.write_to_bytes()?;
    let mut net_packet = NetPacket::new(vec![0u8; 4 + 8 + bytes.len()])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::OtherTurn);
    net_packet.set_transport_protocol(turn_packet::Protocol::Punch.into());
    net_packet.set_ttl(255);
    let mut turn_packet = TurnPacket::new(net_packet.payload_mut())?;
    turn_packet.set_source(virtual_ip);
    turn_packet.set_destination(dest);
    turn_packet.set_payload(&bytes);
    Ok(net_packet.into_buffer())
}
