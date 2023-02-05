use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::thread;

use chrono::Local;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use protobuf::Message;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;

use crate::error::*;
use crate::handle::punch_handler::PunchSender;
use crate::handle::registration_handler::{fast_registration, CONNECTION_STATUS};
use crate::handle::{
    ConnectStatus, Route, ADDR_TABLE, DEVICE_LIST, DIRECT_ROUTE_TABLE, NAT_INFO, SERVER_RT,
};
use crate::proto::message::{DeviceList, Punch, RegistrationResponse};
use crate::protocol::control_packet::{ControlPacket, PunchResponsePacket};
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::turn_packet::TurnPacket;
use crate::protocol::{control_packet, service_packet, turn_packet, NetPacket, Protocol, Version};
use crate::tun_device::TunWriter;
use crate::{ApplicationStatus, CurrentDeviceInfo, PeerDeviceInfo};

const UDP_STOP_BUF: [u8; 1] = [0u8];

pub async fn udp_recv_start<F>(
    mut status_watch: watch::Receiver<ApplicationStatus>,
    udp: UdpSocket,
    server_addr: SocketAddr,
    other_sender: Sender<(SocketAddr, Vec<u8>)>,
    tun_writer: TunWriter,
    current_device: CurrentDeviceInfo,
    stop_fn: F,
) where
    F: FnOnce() + Send + 'static,
{
    {
        let udp = udp.try_clone().unwrap();
        tokio::spawn(async move {
            let _ = status_watch.changed().await;
            let mut addr = udp.local_addr().unwrap();
            addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            udp.send_to(&UDP_STOP_BUF, addr).unwrap();
        });
    }

    thread::spawn(move || {
        if let Err(e) = recv_loop(udp, server_addr, other_sender, tun_writer, current_device) {
            log::warn!("udp数据处理线程停止 {:?}", e);
        }
        stop_fn();
    });
}

fn recv_loop(
    udp: UdpSocket,
    server_addr: SocketAddr,
    other_sender: Sender<(SocketAddr, Vec<u8>)>,
    mut tun_writer: TunWriter,
    current_device: CurrentDeviceInfo,
) -> Result<()> {
    let mut buf = [0u8; 65536];
    let mut local_addr = udp.local_addr()?;
    local_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    loop {
        match udp.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if addr == local_addr {
                    if len == 1 && &buf[..len] == &UDP_STOP_BUF {
                        return Ok(());
                    }
                    //本地的包直接再发到网卡，这个主要用于处理当前虚拟ip的icmp ping
                    if let Ok(ip) = IpV4Packet::new(&buf[..len]) {
                        if ip.destination_ip() == current_device.virtual_ip {
                            let _ = tun_writer.write(&buf[..len]);
                        }
                    }
                    continue;
                }
                match recv_handle(
                    &udp,
                    addr,
                    &mut buf[..len],
                    &server_addr,
                    &other_sender,
                    &mut tun_writer,
                    &current_device,
                ) {
                    Ok(_) => {}
                    Err(Error::Stop(str)) => {
                        return Err(Error::Stop(str));
                    }
                    Err(e) => {
                        log::warn!("{:?}", e);
                    }
                }
            }
            Err(e) => {
                log::warn!("{:?}", e);
            }
        };
    }
}

fn recv_handle(
    udp: &UdpSocket,
    recv_addr: SocketAddr,
    buf: &mut [u8],
    _server_addr: &SocketAddr,
    other_sender: &Sender<(SocketAddr, Vec<u8>)>,
    tun_writer: &mut TunWriter,
    current_device: &CurrentDeviceInfo,
) -> Result<()> {
    let mut net_packet = NetPacket::new(buf)?;
    match net_packet.protocol() {
        Protocol::Ipv4Turn => {
            let mut ipv4_turn_packet = TurnPacket::new(net_packet.payload_mut())?;
            let source = ipv4_turn_packet.source();
            let destination = ipv4_turn_packet.destination();
            let mut ipv4 = IpV4Packet::new(ipv4_turn_packet.payload_mut())?;
            if ipv4.source_ip() == source
                && ipv4.destination_ip() == destination
                && current_device.virtual_ip == ipv4.destination_ip()
            {
                if ipv4.protocol() == ipv4::protocol::Protocol::Icmp {
                    let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                    if icmp_packet.kind() == Kind::EchoRequest {
                        //开启ping
                        icmp_packet.set_kind(Kind::EchoReply);
                        icmp_packet.update_checksum();
                        ipv4.set_source_ip(destination);
                        ipv4.set_destination_ip(source);
                        ipv4.update_checksum();
                        ipv4_turn_packet.set_source(destination);
                        ipv4_turn_packet.set_destination(source);
                        udp.send_to(net_packet.buffer(), recv_addr)?;
                    } else {
                        tun_writer.write(ipv4_turn_packet.payload())?;
                    }
                } else {
                    tun_writer.write(ipv4_turn_packet.payload())?;
                }
            }
        }
        Protocol::UnKnow(_) => {}
        _ => {
            //发送到子线程处理
            let v = net_packet.buffer().to_vec();
            match other_sender.try_send((recv_addr, v)) {
                Ok(_) => {}
                Err(TrySendError::Closed(_)) => {
                    return Err(Error::Stop("子处理线程停止".to_string()));
                }
                Err(e) => {
                    log::warn!("子线程处理 {:?}", e);
                }
            }
        }
    }
    Ok(())
}

pub async fn udp_other_recv_start<F>(
    status_watch: watch::Receiver<ApplicationStatus>,
    udp: UdpSocket,
    receiver: Receiver<(SocketAddr, Vec<u8>)>,
    current_device: CurrentDeviceInfo,
    sender: PunchSender,
    stop_fn: F,
) where
    F: FnOnce() + Send + 'static,
{
    tokio::spawn(async move {
        match other_loop(status_watch, udp, receiver, current_device, sender).await {
            Ok(_) => {
                log::info!("udp子处理线程停止");
            }
            Err(e) => {
                log::warn!("{:?}", e);
            }
        }
        stop_fn();
    });
}

async fn other_loop(
    mut status_watch: watch::Receiver<ApplicationStatus>,
    udp: UdpSocket,
    mut receiver: Receiver<(SocketAddr, Vec<u8>)>,
    current_device: CurrentDeviceInfo,
    sender: PunchSender,
) -> Result<()> {
    loop {
        tokio::select! {
            rs = receiver.recv()=>{
                if let Some((peer_addr, buf)) = rs {
                    match other_handle(&udp, buf, peer_addr, &current_device, &sender) {
                        Ok(_) => {}
                        Err(Error::Stop(str)) => {
                            return Err(Error::Stop(str));
                        }
                        Err(e) => {
                            log::warn!("other_loop {:?}",e);
                        }
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

fn other_handle(
    udp: &UdpSocket,
    buf: Vec<u8>,
    peer_addr: SocketAddr,
    current_device: &CurrentDeviceInfo,
    sender: &PunchSender,
) -> Result<()> {
    let server_addr = current_device.connect_server;
    let mut net_packet = NetPacket::new(buf)?;
    match net_packet.protocol() {
        Protocol::Service => {
            if peer_addr != current_device.connect_server {
                return Ok(());
            }
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationRequest => {}
                service_packet::Protocol::RegistrationResponse => {
                    let response = RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                    crate::handle::init_nat_info(response.public_ip, response.public_port as u16);
                    CONNECTION_STATUS.store(ConnectStatus::Connected);
                    //需要保证重连ip不变
                }
                service_packet::Protocol::UpdateDeviceList => {
                    let device_list = DeviceList::parse_from_bytes(net_packet.payload())?;
                    let ip_list = device_list
                        .device_info_list
                        .into_iter()
                        .map(|info| {
                            PeerDeviceInfo::new(
                                Ipv4Addr::from(info.virtual_ip),
                                info.name,
                                info.device_status as u8,
                            )
                        })
                        .collect();
                    let mut dev = DEVICE_LIST.lock();
                    if dev.0 < device_list.epoch || device_list.epoch - dev.0 > u32::MAX >> 2 {
                        dev.0 = device_list.epoch;
                        dev.1 = ip_list;
                    }
                }
                service_packet::Protocol::UnKnow(_) => {}
            }
        }
        Protocol::Error => {
            match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
                InErrorPacket::TokenError => {
                    if server_addr == peer_addr {
                        //停止整个应用
                        return Err(Error::Stop("token无效".to_string()));
                    }
                }
                InErrorPacket::Disconnect => {
                    if server_addr == peer_addr {
                        fast_registration(&udp, server_addr)?;
                    }
                }
                InErrorPacket::AddressExhausted => {
                    return Err(Error::Stop("IP address has been exhausted".to_string()));
                }
                InErrorPacket::OtherError(e) => {
                    log::error!("OtherError {:?}", e.message());
                }
            }
        }
        Protocol::Control => {
            match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
                ControlPacket::PingPacket(_ping) => {
                    net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                    udp.send_to(&net_packet.buffer()[..12], peer_addr)?;
                }
                ControlPacket::PongPacket(pong_packet) => {
                    let current_time = Local::now().timestamp_millis();
                    let rt = current_time - pong_packet.time();
                    if rt >= 0 {
                        if peer_addr == server_addr {
                            SERVER_RT.store(rt, Ordering::Relaxed)
                        } else {
                            //其他设备
                            if let Some(virtual_ip) = ADDR_TABLE.get(&peer_addr) {
                                if let Some(mut info) = DIRECT_ROUTE_TABLE.get_mut(&virtual_ip) {
                                    info.rt = rt;
                                    info.recv_time = current_time;
                                }
                            }
                        }
                    }
                }
                ControlPacket::PunchRequest(punch_request) => {
                    // println!("打洞请求:{:?}", punch_request);
                    let src = punch_request.source();
                    drop(punch_request);
                    //回应
                    let mut punch_response = PunchResponsePacket::new(net_packet.payload_mut())?;
                    punch_response.set_source(current_device.virtual_ip);
                    net_packet
                        .set_transport_protocol(control_packet::Protocol::PunchResponse.into());
                    udp.send_to(net_packet.buffer(), peer_addr)?;
                    let route = Route::new(peer_addr);
                    DIRECT_ROUTE_TABLE.insert(src, route);
                    ADDR_TABLE.insert(peer_addr, src);
                }
                ControlPacket::PunchResponse(punch_response) => {
                    // println!("打洞响应:{:?}", punch_response);
                    let route = Route::new(peer_addr);
                    DIRECT_ROUTE_TABLE.insert(punch_response.source(), route);
                    ADDR_TABLE.insert(peer_addr, punch_response.source());
                }
            }
        }
        Protocol::Ipv4Turn => {}
        Protocol::OtherTurn => {
            let turn_packet = TurnPacket::new(net_packet.payload())?;
            // println!("{:?}",turn_packet);
            let src = turn_packet.source();
            let dest = turn_packet.destination();
            if dest == current_device.virtual_ip {
                match turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    turn_packet::Protocol::Punch => {
                        let punch = Punch::parse_from_bytes(turn_packet.payload())?;
                        if punch.virtual_ip.to_be_bytes() == src.octets() {
                            if !punch.reply {
                                let mut punch_reply = Punch::new();
                                punch_reply.reply = true;
                                punch_reply.virtual_ip =
                                    u32::from_be_bytes(current_device.virtual_ip.octets());
                                if let Err(_) = sender.try_send(punch) {
                                    return Ok(());
                                }
                                let nat_info = NAT_INFO.lock();
                                if let Some(info) = nat_info.as_ref() {
                                    punch_reply.public_ip_list = info.public_ips.clone();
                                    punch_reply.public_port = info.public_port as u32;
                                    punch_reply.public_port_range = info.public_port_range as u32;
                                    punch_reply.nat_type =
                                        protobuf::EnumOrUnknown::new(info.nat_type);
                                    drop(nat_info);
                                    let bytes = punch_reply.write_to_bytes()?;
                                    let mut net_packet =
                                        NetPacket::new(vec![0u8; 4 + 8 + bytes.len()])?;
                                    net_packet.set_version(Version::V1);
                                    net_packet.set_protocol(Protocol::OtherTurn);
                                    net_packet.set_transport_protocol(
                                        turn_packet::Protocol::Punch.into(),
                                    );
                                    net_packet.set_ttl(255);
                                    let mut turn_packet =
                                        TurnPacket::new(net_packet.payload_mut())?;
                                    turn_packet.set_source(current_device.virtual_ip);
                                    turn_packet.set_destination(src);
                                    turn_packet.set_payload(&bytes);
                                    udp.send_to(net_packet.buffer(), peer_addr)?;
                                }
                            } else {
                                let _ = sender.try_send(punch);
                            }
                        }
                    }
                    turn_packet::Protocol::UnKnow(_) => {}
                }
            }
        }
        Protocol::UnKnow(p) => {
            log::warn!("未知协议 {}", p);
        }
    }
    Ok(())
}
