use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::thread;
use std::time::Duration;

use crossbeam::channel::{Receiver, RecvTimeoutError, Sender, SendError, TrySendError};
use dashmap::DashMap;
use lazy_static::lazy_static;
use protobuf::Message;

use crate::{CurrentDeviceInfo, DEVICE_LIST, NAT_INFO, NatInfo};
use crate::error::*;
use crate::handle::DIRECT_ROUTE_TABLE;
use crate::proto::message::{NatType, Punch, Step};
use crate::protocol::{control_packet, NetPacket, Protocol, turn_packet, Version};
use crate::protocol::control_packet::PunchRequestPacket;
use crate::protocol::turn_packet::TurnPacket;

lazy_static! {
    pub static ref STEP_MAP:DashMap<Ipv4Addr,Step> = DashMap::new();
}
/// 每一种类型一个通道，减少相互干扰
pub fn bounded() -> (PunchSender, ConeReceiver, ReqSymmetricReceiver, ResSymmetricReceiver) {
    let (cone_sender, cone_receiver) = crossbeam::channel::bounded(3);
    let (req_symmetric_sender, req_symmetric_receiver) = crossbeam::channel::bounded(1);
    let (res_symmetric_sender, res_symmetric_receiver) = crossbeam::channel::bounded(1);
    (PunchSender::new(cone_sender, req_symmetric_sender, res_symmetric_sender),
     ConeReceiver(cone_receiver), ReqSymmetricReceiver(req_symmetric_receiver),
     ResSymmetricReceiver(res_symmetric_receiver))
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
    pub fn new(cone_sender: Sender<Punch>,
               req_symmetric_sender: Sender<Punch>,
               res_symmetric_sender: Sender<Punch>, ) -> Self {
        Self {
            cone_sender,
            req_symmetric_sender,
            res_symmetric_sender,
        }
    }
    pub fn send(&self, punch: Punch) -> std::result::Result<(), SendError<Punch>> {
        match punch.nat_type.enum_value_or_default() {
            NatType::Symmetric => {
                if punch.reply {
                    // 为true表示回应，也就是主动发起的打洞操作
                    self.res_symmetric_sender.send(punch)
                } else {
                    self.req_symmetric_sender.send(punch)
                }
            }
            NatType::Cone => {
                self.cone_sender.send(punch)
            }
        }
    }
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
            NatType::Cone => {
                self.cone_sender.try_send(punch)
            }
        }
    }
}

fn handle(udp: &UdpSocket, punch_list: Vec<Punch>, buf: &[u8]) -> Result<()> {
    let mut counter = 0u64;
    for punch in punch_list {
        let dest = Ipv4Addr::from(punch.virtual_ip);
        if DIRECT_ROUTE_TABLE.contains_key(&dest) {
            continue;
        }
        // println!("punch {:?}", punch);
        match punch.nat_type.enum_value_or_default() {
            NatType::Symmetric => {
                match punch.step.enum_value_or_default() {
                    Step::Step1 | Step::Step2 | Step::Step3 => {
                        //预测范围发送
                        for pub_ip in punch.public_ip_list {
                            let pub_ip = Ipv4Addr::from(pub_ip);
                            for range in 0..punch.public_port_range + 1 {
                                let right_port = ((punch.public_port + range) & 0xFFFF) as u16;
                                let left_port = ((0xFFFF + punch.public_port - range) & 0xFFFF) as u16;
                                if right_port != 0 {
                                    // println!("{:?}", SocketAddr::V4(SocketAddrV4::new(pub_ip, right_port)));
                                    udp.send_to(
                                        buf,
                                        SocketAddr::V4(SocketAddrV4::new(pub_ip, right_port)),
                                    )?;
                                    select_sleep(&mut counter);
                                }
                                if left_port != 0 && range != 0 {
                                    // println!("{:?}", SocketAddr::V4(SocketAddrV4::new(pub_ip, right_port)));
                                    if left_port == right_port {
                                        break;
                                    }
                                    udp.send_to(
                                        buf,
                                        SocketAddr::V4(SocketAddrV4::new(pub_ip, left_port)),
                                    )?;
                                    select_sleep(&mut counter);
                                }
                            }
                        }
                    }
                    Step::Step4 => {
                        //全范围发送
                        for pub_ip in punch.public_ip_list {
                            let pub_ip = Ipv4Addr::from(pub_ip);
                            for port in 1..0xFFFF {
                                udp.send_to(
                                    buf,
                                    SocketAddr::V4(SocketAddrV4::new(pub_ip, port)),
                                )?;
                                select_sleep(&mut counter);
                            }
                        }
                    }
                }
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
pub fn req_symmetric_handle_loop(
    receiver: ReqSymmetricReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let receiver = receiver.0;
    handle_loop(receiver, udp, cur_info)
}

/// 给对称nat发送打洞数据包，处理主动发起的打洞操作
pub fn res_symmetric_handle_loop(
    receiver: ResSymmetricReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let receiver = receiver.0;
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
        match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(punch) => {
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
                for punch in &list {
                    let dest = Ipv4Addr::from(punch.virtual_ip);
                    match punch.step.enum_value_or_default() {
                        Step::Step1 => {
                            STEP_MAP.insert(dest, Step::Step2);
                        }
                        Step::Step2 => {
                            STEP_MAP.insert(dest, Step::Step3);
                        }
                        Step::Step3 => {
                            STEP_MAP.insert(dest, Step::Step4);
                        }
                        Step::Step4 => {
                            STEP_MAP.insert(dest, Step::Step1);
                        }
                    }
                }
                if let Err(e) = handle(&udp, list, packet.buffer()) {
                    log::error!("{:?}",e)
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                punch_request_handle(&udp, &cur_info)?;
            }
            Err(_) => {
                return Err(Error::Stop("打洞线程通道关闭".to_string()));
            }
        }
    }
}

/// 给锥形nat发送打洞数据包
pub fn cone_handle_loop(
    receiver: ConeReceiver,
    udp: UdpSocket,
    cur_info: CurrentDeviceInfo,
) -> Result<()> {
    let receiver = receiver.0;
    handle_loop(receiver, udp, cur_info)
}

pub fn handle_loop(
    receiver: Receiver<Punch>,
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
        match receiver.recv() {
            Ok(punch) => {
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
                if let Err(e) = handle(&udp, list, packet.buffer()) {
                    log::error!("{:?}",e)
                }
            }
            Err(_) => {
                return Err(Error::Stop("打洞线程通道关闭".to_string()));
            }
        }
    }
}

fn select_sleep(counter: &mut u64) {
    *counter += 1;
    thread::sleep(Duration::from_millis(1));
    // if *counter > 1 {
    //     if cone_nat {
    //         thread::sleep(Duration::from_millis(2));
    //     } else {
    //         if (*counter) & 10 == 10 {
    //             thread::sleep(Duration::from_millis(1));
    //         }
    //     }
    // }
}


fn punch_request_handle(udp: &UdpSocket, cur_info: &CurrentDeviceInfo) -> Result<()> {
    let nat_info_lock = NAT_INFO.lock();
    let nat_info = nat_info_lock.clone();
    drop(nat_info_lock);
    if let Some(nat_info) = nat_info {
        if let Err(e) = send_punch(&udp,
                                   &cur_info,
                                   nat_info) {
            log::error!("发送打洞数据失败 {:?}",e)
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
    for ip in list {
        //只向ip比自己大的发起打洞，避免双方同时发起打洞浪费流量
        if ip > cur_info.virtual_ip && !DIRECT_ROUTE_TABLE.contains_key(&ip) {
            let step = if let Some(step) = STEP_MAP.get(&ip) {
                *step
            } else {
                Step::Step1
            };
            let bytes = punch_packet(cur_info.virtual_ip,
                                     nat_info.clone(), ip, step)?;
            udp.send_to(&bytes, cur_info.connect_server)?;
        }
    }
    Ok(())
}

fn punch_packet(virtual_ip: Ipv4Addr, nat_info: NatInfo, dest: Ipv4Addr, step: Step) -> Result<Vec<u8>> {
    let mut punch_reply = Punch::new();
    punch_reply.reply = false;
    punch_reply.virtual_ip = u32::from_be_bytes(virtual_ip.octets());
    punch_reply.step = protobuf::EnumOrUnknown::new(step);
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
