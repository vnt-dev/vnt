use std::{io, thread};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use chrono::Local;
use crossbeam::atomic::AtomicCell;
use crossbeam_skiplist::SkipMap;
use parking_lot::Mutex;
use protobuf::Message;

use p2p_channel::channel::{Channel, Route, RouteKey};
use p2p_channel::punch::NatInfo;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::error::Error;
use crate::handle::{check_dest, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::handle::registration_handler::Register;
use crate::nat::NatTest;
use crate::proto::message::{DeviceList, PunchInfo, PunchNatType, RegistrationResponse};
use crate::protocol::{control_packet, MAX_TTL, NetPacket, Protocol, service_packet, turn_packet, Version};
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::tun_device::TunWriter;

pub fn start(mut handler: RecvHandler) {
    thread::spawn(move || {
        let mut buf = [0; 4096];
        loop {
            match handler.channel.recv_from(&mut buf, None) {
                Ok((len, route)) => {
                    if let Err(e) = handler.handle(&mut buf[..len], &route) {
                        log::warn!("数据处理失败:{:?},e:{:?}",route,e);
                        if let Error::Stop(_) = e {
                            let _ = handler.channel.close();
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("{:?}",e);
                    // 检查关闭状态
                    if handler.channel.is_close() {
                        break;
                    }
                }
            }
        }
    });
}

pub struct RecvHandler {
    channel: Channel<Ipv4Addr>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    register: Arc<Register>,
    nat_test: NatTest,
    tun_writer: TunWriter,
    connect_status: Arc<AtomicCell<ConnectStatus>>,
    peer_nat_info_map: Arc<SkipMap<Ipv4Addr, NatInfo>>,
}

impl RecvHandler {
    pub fn new(channel: Channel<Ipv4Addr>,
               current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
               device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
               register: Arc<Register>,
               nat_test: NatTest,
               tun_writer: TunWriter,
               connect_status: Arc<AtomicCell<ConnectStatus>>,
               peer_nat_info_map: Arc<SkipMap<Ipv4Addr, NatInfo>>,
    ) -> Self {
        Self {
            channel,
            current_device,
            device_list,
            register,
            nat_test,
            tun_writer,
            connect_status,
            peer_nat_info_map,
        }
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            channel: self.channel.try_clone()?,
            current_device: self.current_device.clone(),
            device_list: self.device_list.clone(),
            register: self.register.clone(),
            nat_test: self.nat_test.clone(),
            tun_writer: self.tun_writer.clone(),
            connect_status: self.connect_status.clone(),
            peer_nat_info_map: self.peer_nat_info_map.clone(),
        })
    }
}

impl RecvHandler {
    fn handle(&self, buf: &mut [u8], route_key: &RouteKey) -> crate::Result<()> {
        let mut net_packet = NetPacket::new(buf)?;
        if net_packet.ttl() == 0 {
            return Ok(());
        }
        let source = net_packet.source();
        let current_device = self.current_device.load();
        if source == current_device.virtual_ip() {
            return Ok(());
        }
        let destination = net_packet.destination();
        if current_device.virtual_ip() != destination && self.connect_status.load() == ConnectStatus::Connected {
            if !check_dest(source, current_device.virtual_netmask, current_device.virtual_network) {
                log::warn!("转发数据，源地址错误:{:?},当前网络:{:?},route_key:{:?}",source,current_device.virtual_network,route_key);
                return Ok(());
            }
            if !check_dest(destination, current_device.virtual_netmask, current_device.virtual_network) {
                log::warn!("转发数据，目的地址错误:{:?},当前网络:{:?},route_key:{:?}",destination,current_device.virtual_network,route_key);
                return Ok(());
            }
            let ttl = net_packet.ttl();
            if ttl > 1 {
                // 转发
                net_packet.set_ttl(ttl - 1);
                if let Some(route) = self.channel.route(&destination) {
                    if route.metric <= net_packet.ttl() {
                        self.channel.send_to_route(net_packet.buffer(), &route.route_key())?;
                    }
                } else if (ttl > 2 || destination == current_device.virtual_gateway())
                    && source != current_device.virtual_gateway() {
                    //网关默认要转发一次，生存时间不够的发到网关也会被丢弃
                    self.channel.send_to_addr(net_packet.buffer(), current_device.connect_server)?;
                }
            }
            return Ok(());
        }
        match net_packet.protocol() {
            Protocol::Ipv4Turn => {
                let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                if ipv4.protocol() == ipv4::protocol::Protocol::Icmp {
                    let mut icmp_packet = icmp::IcmpPacket::new(ipv4.payload_mut())?;
                    if icmp_packet.kind() == Kind::EchoRequest {
                        //开启ping
                        icmp_packet.set_kind(Kind::EchoReply);
                        icmp_packet.update_checksum();
                        ipv4.set_source_ip(destination);
                        ipv4.set_destination_ip(source);
                        ipv4.update_checksum();
                        net_packet.set_source(destination);
                        net_packet.set_destination(source);
                        self.channel.send_to_route(net_packet.buffer(), route_key)?;
                        return Ok(());
                    }
                }
                self.tun_writer.write(net_packet.payload())?;
            }
            Protocol::Service => {
                self.service(current_device, source, net_packet, route_key)?;
            }
            Protocol::Error => {
                self.error(current_device, source, net_packet, route_key)?;
            }
            Protocol::Control => {
                self.control(current_device, source, net_packet, route_key)?;
            }
            Protocol::OtherTurn => {
                self.other_turn(current_device, source, net_packet, route_key)?;
            }
            Protocol::UnKnow(e) => {
                log::info!("不支持的协议:{}",e);
            }
        }
        Ok(())
    }
    fn service(&self, current_device: CurrentDeviceInfo, source: Ipv4Addr, net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        if route_key.addr != current_device.connect_server || source != current_device.virtual_gateway() {
            return Ok(());
        }
        match service_packet::Protocol::from(net_packet.transport_protocol()) {
            service_packet::Protocol::RegistrationRequest => {}
            service_packet::Protocol::RegistrationResponse => {
                let response = RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                let local_addr = self.channel.local_addr()?;
                let local_ip = if local_addr.ip().is_unspecified() {
                    local_ip_address::local_ip().unwrap_or(local_addr.ip())
                } else {
                    local_addr.ip()
                };
                let nat_info = self.nat_test.re_test(Ipv4Addr::from(response.public_ip), response.public_port as u16, local_ip, local_addr.port());
                self.channel.set_nat_type(nat_info.nat_type)?;
                let new_ip = Ipv4Addr::from(response.virtual_ip);
                let current_ip = current_device.virtual_ip();
                if current_ip != new_ip {
                    // ip发生变化
                    log::info!("ip发生变化,old_ip:{:?},new_ip:{:?}",current_ip,new_ip);
                    let old_netmask = current_device.virtual_netmask;
                    let old_gateway = current_device.virtual_gateway();
                    let virtual_ip = Ipv4Addr::from(response.virtual_ip);
                    let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
                    let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
                    self.tun_writer.change_ip(virtual_ip, virtual_netmask, virtual_gateway, old_netmask, old_gateway)?;
                    let new_current_device = CurrentDeviceInfo::new(virtual_ip, virtual_gateway,
                                                                    virtual_netmask, current_device.connect_server);
                    if let Err(e) = self.current_device.compare_exchange(current_device, new_current_device) {
                        log::warn!("替换失败:{:?}",e);
                    }
                }
                self.connect_status.store(ConnectStatus::Connected);
            }
            service_packet::Protocol::PollDeviceList => {}
            service_packet::Protocol::PushDeviceList => {
                let device_list_t = DeviceList::parse_from_bytes(net_packet.payload())?;
                let ip_list = device_list_t
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
                let mut dev = self.device_list.lock();
                if dev.0 != device_list_t.epoch as u16 {
                    dev.0 = device_list_t.epoch as u16;
                    dev.1 = ip_list;
                }
            }
            service_packet::Protocol::UnKnow(u) => {
                log::warn!("未知服务协议:{}",u);
            }
        }
        Ok(())
    }
    fn error(&self, current_device: CurrentDeviceInfo, source: Ipv4Addr, net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        if route_key.addr != current_device.connect_server || source != current_device.virtual_gateway() {
            return Ok(());
        }
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                return Err(Error::Stop("Token error".to_string()));
            }
            InErrorPacket::Disconnect => {
                self.connect_status.store(ConnectStatus::Connecting);
                self.register.fast_register()?;
            }
            InErrorPacket::AddressExhausted => {
                //地址用尽
                return Err(Error::Stop("IP address has been exhausted".to_string()));
            }
            InErrorPacket::OtherError(e) => {
                log::error!("OtherError {:?}", e.message());
            }
        }
        Ok(())
    }
    fn control(&self, current_device: CurrentDeviceInfo, source: Ipv4Addr, mut net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PingPacket(_) => {
                net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                net_packet.set_source(current_device.virtual_ip());
                net_packet.set_destination(source);
                net_packet.first_set_ttl(MAX_TTL);
                self.channel.send_to_route(net_packet.buffer(), route_key)?;
            }
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = Local::now().timestamp_millis() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let rt = (current_time - pong_packet.time()) as i64;
                let metric = net_packet.source_ttl() - net_packet.ttl() + 1;
                if let Some(current_route) = self.channel.route(&source) {
                    if &current_route.route_key() == route_key {
                        self.channel.update_route(&source, metric, rt);
                    } else if current_route.metric >= metric && current_route.rt > rt {
                        let route = Route::from(*route_key, metric, rt);
                        self.channel.add_route(source, route);
                    }
                } else {
                    let route = Route::from(*route_key, metric, rt);
                    self.channel.add_route(source, route);
                }
                if route_key.addr == current_device.connect_server && source == current_device.virtual_gateway() {
                    let epoch = self.device_list.lock().0;
                    if pong_packet.epoch() != epoch {
                        let mut poll_device = NetPacket::new([0; 12])?;
                        poll_device.set_source(current_device.virtual_ip());
                        poll_device.set_destination(source);
                        poll_device.set_version(Version::V1);
                        poll_device.first_set_ttl(MAX_TTL);
                        poll_device.set_protocol(Protocol::Service);
                        poll_device.set_transport_protocol(service_packet::Protocol::PollDeviceList.into());
                        self.channel.send_to_route(poll_device.buffer(), route_key)?;
                    }
                }
            }
            ControlPacket::PunchRequest => {
                log::info!("PunchRequest route_key:{:?}",route_key);
                //回应
                net_packet.set_transport_protocol(control_packet::Protocol::PunchResponse.into());
                net_packet.set_source(current_device.virtual_ip());
                net_packet.set_destination(source);
                net_packet.first_set_ttl(1);
                self.channel.send_to_route(net_packet.buffer(), route_key)?;
                let route = Route::from(*route_key, 1, -1);
                self.channel.add_route(source, route);
            }
            ControlPacket::PunchResponse => {
                log::info!("PunchResponse route_key:{:?}",route_key);
                let route = Route::from(*route_key, 1, -1);
                self.channel.add_route(net_packet.source(), route);
            }
        }
        Ok(())
    }
    fn other_turn(&self, current_device: CurrentDeviceInfo, source: Ipv4Addr, net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        match turn_packet::Protocol::from(net_packet.transport_protocol()) {
            turn_packet::Protocol::Punch => {
                let punch_info = PunchInfo::parse_from_bytes(net_packet.payload())?;
                let public_ips = punch_info.public_ip_list.
                    iter().map(|v| { IpAddr::from(v.to_be_bytes()) }).collect();
                let peer_nat_info = NatInfo::new(public_ips,
                                                 punch_info.public_port as u16,
                                                 punch_info.public_port_range as u16,
                                                 IpAddr::from(punch_info.local_ip.to_be_bytes()),
                                                 punch_info.local_port as u16,
                                                 punch_info.nat_type.enum_value_or_default().into());
                self.peer_nat_info_map.insert(source, peer_nat_info.clone());
                if !punch_info.reply {
                    let mut punch_reply = PunchInfo::new();
                    punch_reply.reply = true;
                    let nat_info = self.nat_test.nat_info();
                    punch_reply.public_ip_list = nat_info.public_ips.iter().map(|i| {
                        match i {
                            IpAddr::V4(ip) => {
                                u32::from_be_bytes(ip.octets())
                            }
                            IpAddr::V6(_) => {
                                panic!()
                            }
                        }
                    }).collect();
                    punch_reply.public_port = nat_info.public_port as u32;
                    punch_reply.public_port_range = nat_info.public_port_range as u32;
                    punch_reply.nat_type =
                        protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
                    let bytes = punch_reply.write_to_bytes()?;
                    let mut net_packet =
                        NetPacket::new(vec![0u8; 12 + bytes.len()])?;
                    net_packet.set_version(Version::V1);
                    net_packet.set_protocol(Protocol::OtherTurn);
                    net_packet.set_transport_protocol(
                        turn_packet::Protocol::Punch.into(),
                    );
                    net_packet.first_set_ttl(MAX_TTL);
                    net_packet.set_source(current_device.virtual_ip());
                    net_packet.set_destination(source);
                    net_packet.set_payload(&bytes);
                    if !peer_nat_info.local_ip.is_unspecified() && peer_nat_info.local_port != 0 {
                        let mut packet = NetPacket::new([0u8; 12])?;
                        packet.set_version(Version::V1);
                        packet.first_set_ttl(1);
                        packet.set_protocol(Protocol::Control);
                        packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
                        packet.set_source(current_device.virtual_ip());
                        packet.set_destination(source);
                        let _ = self.channel.send_to_addr(packet.buffer(), SocketAddr::new(peer_nat_info.local_ip, peer_nat_info.local_port));
                    }
                    if let Err(e) = self.channel.punch(source, peer_nat_info) {
                        log::warn!("发送到打洞通道失败 {:?}",e);
                        return Ok(());
                    }
                    self.channel.send_to_route(net_packet.buffer(), route_key)?;
                } else {
                    let _ = self.channel.punch(source, peer_nat_info);
                }
            }
            turn_packet::Protocol::UnKnow(e) => {
                log::warn!("不支持的转发协议 {:?},source:{:?}",e,source);
            }
        }
        Ok(())
    }
}