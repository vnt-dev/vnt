use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use parking_lot::Mutex;
use protobuf::Message;
use tokio::sync::mpsc::Sender;

use packet::icmp::{icmp, Kind};
use packet::icmp::icmp::HeaderOther;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::{Route, RouteKey};
use crate::channel::channel::Context;
use crate::channel::punch::{NatInfo, NatType};
use crate::cipher::{Cipher, RsaCipher};
use crate::error::Error;
use crate::external_route::AllowExternalRoute;
use crate::handle::{ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo, PeerDeviceStatus};
use crate::handle::handshake_handler::secret_handshake_req;
use crate::handle::registration_handler::Register;
use crate::igmp_server::IgmpServer;
use crate::ip_proxy::IpProxyMap;
use crate::nat;
use crate::nat::NatTest;
use crate::proto::message::{DeviceList, PunchInfo, PunchNatType, RegistrationResponse};
use crate::protocol::{control_packet, ip_turn_packet, MAX_TTL, NetPacket, other_turn_packet, Protocol, service_packet, Version};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::tun_tap_device::DeviceWriter;

#[derive(Clone)]
pub struct ChannelDataHandler {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    register: Arc<Register>,
    nat_test: NatTest,
    igmp_server: Option<IgmpServer>,
    device_writer: DeviceWriter,
    connect_status: Arc<AtomicCell<ConnectStatus>>,
    peer_nat_info_map: Arc<DashMap<Ipv4Addr, NatInfo>>,
    ip_proxy_map: Option<IpProxyMap>,
    out_external_route: AllowExternalRoute,
    cone_sender: Sender<(Ipv4Addr, NatInfo)>,
    symmetric_sender: Sender<(Ipv4Addr, NatInfo)>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    rsa_cipher: Option<RsaCipher>,
    relay: bool,
    token: String,
}

impl ChannelDataHandler {
    pub fn new(current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
               device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
               register: Arc<Register>,
               nat_test: NatTest,
               igmp_server: Option<IgmpServer>,
               device_writer: DeviceWriter,
               connect_status: Arc<AtomicCell<ConnectStatus>>,
               peer_nat_info_map: Arc<DashMap<Ipv4Addr, NatInfo>>,
               ip_proxy_map: Option<IpProxyMap>,
               out_external_route: AllowExternalRoute,
               cone_sender: Sender<(Ipv4Addr, NatInfo)>,
               symmetric_sender: Sender<(Ipv4Addr, NatInfo)>,
               client_cipher: Cipher,
               server_cipher: Cipher,
               rsa_cipher: Option<RsaCipher>,
               relay: bool, token: String, ) -> Self {
        Self {
            current_device,
            device_list,
            register,
            nat_test,
            igmp_server,
            device_writer,
            connect_status,
            peer_nat_info_map,
            ip_proxy_map,
            out_external_route,
            cone_sender,
            symmetric_sender,
            client_cipher,
            server_cipher,
            rsa_cipher,
            relay,
            token,
        }
    }
}


impl ChannelDataHandler {
    pub async fn handle(&self, buf: &mut [u8], start: usize, end: usize, route_key: RouteKey, context: &Context) {
        assert_eq!(start, 14);
        match self.handle0(&mut buf[..end], &route_key, context).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}",e);
            }
        }
    }
    async fn handle0(&self, buf: &mut [u8], route_key: &RouteKey, context: &Context) -> crate::Result<()> {
        let mut net_packet = NetPacket::new(&mut buf[14..])?;
        if net_packet.ttl() == 0 || net_packet.source_ttl() < net_packet.ttl() {
            return Ok(());
        }
        let source = net_packet.source();
        context.update_read_time(&source, route_key);
        let current_device = self.current_device.load();
        let destination = net_packet.destination();
        let not_broadcast = !destination.is_broadcast() && !destination.is_multicast() && destination != current_device.broadcast_address;
        if current_device.virtual_ip() != destination
            && not_broadcast && !destination.is_unspecified() {
            //校验指纹，不需要解密
            self.client_cipher.check_finger(&net_packet)?;
            net_packet.set_ttl(net_packet.ttl() - 1);
            let ttl = net_packet.ttl();
            if ttl > 0 {
                // 转发
                if let Some(route) = context.route_one(&destination) {
                    if route.metric <= net_packet.ttl() {
                        context.send_by_key(net_packet.buffer(), &route.route_key()).await?;
                    }
                } else if (ttl > 1 || destination == current_device.virtual_gateway())
                    && source != current_device.virtual_gateway() {
                    //网关默认要转发一次，生存时间不够的发到网关也会被丢弃
                    context.send_main(net_packet.buffer(), current_device.connect_server).await?;
                }
            }
            return Ok(());
        }
        if net_packet.is_gateway() {
            if net_packet.protocol() == Protocol::Error && net_packet.transport_protocol() == crate::protocol::error_packet::Protocol::NoKey.into() {
                if let Some(rsa_cipher) = &self.rsa_cipher {
                    secret_handshake_req(context, current_device.connect_server, rsa_cipher, &self.server_cipher, self.token.clone()).await?;
                }
            } else {
                //服务端解密
                self.server_cipher.decrypt_ipv4(&mut net_packet)?;
                let data_len = net_packet.data_len();
                self.server_packet_handle(context, current_device, buf, data_len, route_key).await?;
            }
            return Ok(());
        }
        self.client_cipher.decrypt_ipv4(&mut net_packet)?;
        match net_packet.protocol() {
            Protocol::IpTurn => {
                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    ip_turn_packet::Protocol::Ipv4 => {
                        let mut ipv4 = IpV4Packet::new(net_packet.payload_mut())?;
                        match ipv4.protocol() {
                            ipv4::protocol::Protocol::Igmp => {
                                if let Some(igmp_server) = &self.igmp_server {
                                    igmp_server.handle(ipv4.payload(), source)?;
                                }
                                return Ok(());
                            }
                            ipv4::protocol::Protocol::Icmp => {
                                if ipv4.destination_ip() == destination {
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
                                        //不管加不加密，和接收到的数据长度都一致
                                        self.client_cipher.encrypt_ipv4(&mut net_packet)?;
                                        context.send_by_key(net_packet.buffer(), route_key).await?;
                                        return Ok(());
                                    }
                                }
                            }
                            _ => {}
                        }
                        if not_broadcast && ipv4.destination_ip() != destination {
                            if let Some(ip_proxy_map) = &self.ip_proxy_map {
                                if self.out_external_route.allow(&ipv4.destination_ip()) {
                                    match ipv4.protocol() {
                                        ipv4::protocol::Protocol::Tcp => {
                                            let dest_ip = ipv4.destination_ip();
                                            //转发到代理目标地址
                                            let mut tcp_packet = packet::tcp::tcp::TcpPacket::new(source, destination, ipv4.payload_mut())?;
                                            let source_port = tcp_packet.source_port();
                                            let dest_port = tcp_packet.destination_port();
                                            tcp_packet.set_destination_port(ip_proxy_map.tcp_proxy_port);
                                            tcp_packet.update_checksum();
                                            ipv4.set_destination_ip(destination);
                                            ipv4.update_checksum();
                                            let key = SocketAddrV4::new(source, source_port);
                                            //https://github.com/crossbeam-rs/crossbeam/issues/1023
                                            ip_proxy_map.tcp_proxy_map.insert(key, SocketAddrV4::new(dest_ip, dest_port));
                                        }
                                        ipv4::protocol::Protocol::Udp => {
                                            let dest_ip = ipv4.destination_ip();
                                            //转发到代理目标地址
                                            let mut udp_packet = packet::udp::udp::UdpPacket::new(source, destination, ipv4.payload_mut())?;
                                            let source_port = udp_packet.source_port();
                                            let dest_port = udp_packet.destination_port();
                                            udp_packet.set_destination_port(ip_proxy_map.udp_proxy_port);
                                            udp_packet.update_checksum();
                                            ipv4.set_destination_ip(destination);
                                            ipv4.update_checksum();
                                            let key = SocketAddrV4::new(source, source_port);
                                            ip_proxy_map.udp_proxy_map.insert(key, SocketAddrV4::new(dest_ip, dest_port));
                                        }
                                        ipv4::protocol::Protocol::Icmp => {
                                            let dest_ip = ipv4.destination_ip();
                                            //转发到代理目标地址
                                            let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
                                            match icmp_packet.header_other() {
                                                HeaderOther::Identifier(id, seq) => {
                                                    ip_proxy_map.icmp_proxy_map.insert((dest_ip, id, seq), source);
                                                    ip_proxy_map.send_icmp(ipv4.payload(), &dest_ip)?;
                                                }
                                                _ => {
                                                    log::warn!("不支持的ip代理Icmp协议:{}",destination);
                                                    return Err(Error::Warn("不支持的ip代理Icmp协议".to_string()));
                                                }
                                            }
                                        }
                                        _ => {
                                            log::warn!("不支持的ip代理ipv4协议:{}",destination);
                                            return Err(Error::Warn("不支持的ip代理ipv4协议".to_string()));
                                        }
                                    }
                                } else {
                                    log::warn!("没有ip代理规则:{}",destination);
                                    return Err(Error::Warn("没有ip代理规则".to_string()));
                                }
                            } else {
                                log::warn!("不支持ip代理:{}",destination);
                                return Err(Error::Warn("不支持ip代理".to_string()));
                            }
                        }

                        //传输协议12字节
                        self.device_writer.write_ipv4(&mut buf[12..])?;
                        return Ok(());
                    }
                    ip_turn_packet::Protocol::Ipv4Broadcast => {
                        //客户端不帮忙转发广播包，所以不会出现这种类型的数据
                    }
                    ip_turn_packet::Protocol::Unknown(_) => {}
                }
            }
            Protocol::Service => {}
            Protocol::Error => {}
            Protocol::Control => {
                self.control(context, current_device, source, net_packet, route_key).await?;
            }
            Protocol::OtherTurn => {
                self.other_turn(context, current_device, source, net_packet, route_key).await?;
            }
            Protocol::UnKnow(e) => {
                log::info!("不支持的协议:{}",e);
            }
        }
        Ok(())
    }

    async fn pong_packet(&self, gateway: bool, metric: u8, context: &Context, current_device: CurrentDeviceInfo, source: Ipv4Addr, pong_packet: control_packet::PongPacket<&[u8]>, route_key: &RouteKey) -> crate::Result<()> {
        let current_time = crate::handle::now_time() as u16;
        if current_time < pong_packet.time() {
            return Ok(());
        }
        let rt = (current_time - pong_packet.time()) as i64;
        let route = Route::from(*route_key, metric, rt);
        context.add_route(source, route);
        if gateway {
            let epoch = self.device_list.lock().0;
            if pong_packet.epoch() != epoch {
                let mut poll_device = NetPacket::new_encrypt([0; 12 + ENCRYPTION_RESERVED])?;
                poll_device.set_source(current_device.virtual_ip());
                poll_device.set_destination(source);
                poll_device.set_version(Version::V1);
                poll_device.set_gateway_flag(true);
                poll_device.first_set_ttl(MAX_TTL);
                poll_device.set_protocol(Protocol::Service);
                poll_device.set_transport_protocol(service_packet::Protocol::PollDeviceList.into());
                self.server_cipher.encrypt_ipv4(&mut poll_device)?;
                context.send_main(poll_device.buffer(), current_device.connect_server).await?;
            }
        }
        Ok(())
    }
    async fn control(&self, context: &Context, current_device: CurrentDeviceInfo, source: Ipv4Addr, mut net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        let metric = net_packet.source_ttl() - net_packet.ttl() + 1;
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PingPacket(_) => {
                net_packet.set_transport_protocol(control_packet::Protocol::Pong.into());
                net_packet.set_source(current_device.virtual_ip());
                net_packet.set_destination(source);
                net_packet.first_set_ttl(MAX_TTL);
                self.client_cipher.encrypt_ipv4(&mut net_packet)?;
                context.send_by_key(net_packet.buffer(), route_key).await?;
                let route = Route::from(*route_key, metric, 199);
                context.add_route_if_absent(source, route);
            }
            ControlPacket::PongPacket(pong_packet) => {
                self.pong_packet(false, metric, context, current_device, source, pong_packet, route_key).await?;
            }
            ControlPacket::PunchRequest => {
                if self.relay {
                    return Ok(());
                }
                //回应
                net_packet.set_transport_protocol(control_packet::Protocol::PunchResponse.into());
                net_packet.set_source(current_device.virtual_ip());
                net_packet.set_destination(source);
                net_packet.first_set_ttl(1);
                self.client_cipher.encrypt_ipv4(&mut net_packet)?;
                context.send_by_key(net_packet.buffer(), route_key).await?;
                let route = Route::from(*route_key, 1, 199);
                context.add_route_if_absent(source, route);
            }
            ControlPacket::PunchResponse => {
                if self.relay {
                    return Ok(());
                }
                let route = Route::from(*route_key, 1, 199);
                context.add_route_if_absent(source, route);
            }
            ControlPacket::AddrRequest => {
                match route_key.addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        let mut packet = NetPacket::new_encrypt([0; 12 + 6 + ENCRYPTION_RESERVED])?;
                        packet.set_version(Version::V1);
                        packet.set_protocol(Protocol::Control);
                        packet.set_transport_protocol(
                            control_packet::Protocol::AddrResponse.into(),
                        );
                        packet.first_set_ttl(MAX_TTL);
                        packet.set_source(current_device.virtual_ip());
                        packet.set_destination(source);
                        let mut addr_packet = control_packet::AddrPacket::new(packet.payload_mut())?;
                        addr_packet.set_ipv4(ipv4);
                        addr_packet.set_port(route_key.addr.port());
                        self.client_cipher.encrypt_ipv4(&mut packet)?;
                        context.send_by_key(packet.buffer(), route_key).await?;
                    }
                    std::net::IpAddr::V6(_) => {}
                }
            }
            ControlPacket::AddrResponse(addr_packet) => {
                if !addr_packet.ipv4().is_multicast()
                    && !addr_packet.ipv4().is_broadcast()
                    && !addr_packet.ipv4().is_unspecified()
                    && !addr_packet.ipv4().is_loopback()
                    && !addr_packet.ipv4().is_private() && addr_packet.port() != 0 {
                    self.nat_test.update_addr(addr_packet.ipv4(), addr_packet.port())
                }
            }
        }
        Ok(())
    }
    async fn other_turn(&self, context: &Context, current_device: CurrentDeviceInfo, source: Ipv4Addr, net_packet: NetPacket<&mut [u8]>, route_key: &RouteKey) -> crate::Result<()> {
        if self.relay {
            return Ok(());
        }
        match other_turn_packet::Protocol::from(net_packet.transport_protocol()) {
            other_turn_packet::Protocol::Punch => {
                let punch_info = PunchInfo::parse_from_bytes(net_packet.payload())?;
                let public_ips = punch_info.public_ip_list.
                    iter().map(|v| { Ipv4Addr::from(v.to_be_bytes()) }).collect();
                let peer_nat_info = NatInfo::new(public_ips,
                                                 punch_info.public_port as u16,
                                                 punch_info.public_port_range as u16,
                                                 Ipv4Addr::from(punch_info.local_ip.to_be_bytes()),
                                                 punch_info.local_port as u16,
                                                 punch_info.nat_type.enum_value_or_default().into());
                self.peer_nat_info_map.insert(source, peer_nat_info.clone());
                if !punch_info.reply {
                    let mut punch_reply = PunchInfo::new();
                    punch_reply.reply = true;
                    let nat_info = self.nat_test.nat_info();
                    punch_reply.public_ip_list = nat_info.public_ips.iter().map(|ip| u32::from_be_bytes(ip.octets())).collect();
                    punch_reply.public_port = nat_info.public_port as u32;
                    punch_reply.public_port_range = nat_info.public_port_range as u32;
                    punch_reply.nat_type =
                        protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
                    punch_reply.local_ip = u32::from_be_bytes(nat_info.local_ip.octets());
                    punch_reply.local_port = nat_info.local_port as u32;
                    let bytes = punch_reply.write_to_bytes()?;
                    let mut punch_packet =
                        NetPacket::new_encrypt(vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED])?;
                    punch_packet.set_version(Version::V1);
                    punch_packet.set_protocol(Protocol::OtherTurn);
                    punch_packet.set_transport_protocol(
                        other_turn_packet::Protocol::Punch.into(),
                    );
                    punch_packet.first_set_ttl(MAX_TTL);
                    punch_packet.set_source(current_device.virtual_ip());
                    punch_packet.set_destination(source);
                    punch_packet.set_payload(&bytes)?;
                    if !peer_nat_info.local_ip.is_unspecified() && peer_nat_info.local_port != 0 {
                        let mut packet = NetPacket::new_encrypt([0u8; 12 + ENCRYPTION_RESERVED])?;
                        packet.set_version(Version::V1);
                        packet.first_set_ttl(1);
                        packet.set_protocol(Protocol::Control);
                        packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
                        packet.set_source(current_device.virtual_ip());
                        packet.set_destination(source);
                        self.client_cipher.encrypt_ipv4(&mut packet)?;
                        let _ = context.send_main(packet.buffer(), SocketAddr::V4(SocketAddrV4::new(peer_nat_info.local_ip, peer_nat_info.local_port))).await;
                    }
                    if self.punch(source, peer_nat_info).await {
                        self.client_cipher.encrypt_ipv4(&mut punch_packet)?;
                        context.send_by_key(punch_packet.buffer(), route_key).await?;
                    }
                } else {
                    self.punch(source, peer_nat_info).await;
                }
            }
            other_turn_packet::Protocol::Unknown(e) => {
                log::warn!("不支持的转发协议 {:?},source:{:?}",e,source);
            }
        }
        Ok(())
    }
    async fn punch(&self, peer_ip: Ipv4Addr, peer_nat_info: NatInfo) -> bool {
        match peer_nat_info.nat_type {
            NatType::Symmetric => {
                self.symmetric_sender.try_send((peer_ip, peer_nat_info)).is_ok()
            }
            NatType::Cone => {
                self.cone_sender.try_send((peer_ip, peer_nat_info)).is_ok()
            }
        }
    }
}

/// 处理服务端数据
impl ChannelDataHandler {
    async fn server_packet_handle(&self, context: &Context, current_device: CurrentDeviceInfo, buf: &mut [u8], data_len: usize, route_key: &RouteKey) -> crate::Result<()> {
        let net_packet = NetPacket::new0(data_len, &buf[14..])?;
        let source = net_packet.source();
        match net_packet.protocol() {
            Protocol::Service => {
                self.service(context, current_device, net_packet, route_key).await?;
            }
            Protocol::Error => {
                self.error(context, current_device, source, net_packet, route_key).await?;
            }
            Protocol::Control => {
                self.control_gateway(context, current_device, net_packet, route_key).await?;
            }
            Protocol::IpTurn => {
                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    ip_turn_packet::Protocol::Ipv4 => {
                        let ipv4 = IpV4Packet::new(net_packet.payload())?;
                        match ipv4.protocol() {
                            ipv4::protocol::Protocol::Igmp => {
                                if let Some(igmp_server) = &self.igmp_server {
                                    igmp_server.handle(ipv4.payload(), source)?;
                                }
                                return Ok(());
                            }
                            ipv4::protocol::Protocol::Icmp => {
                                if ipv4.destination_ip() == current_device.virtual_ip {
                                    let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
                                    if icmp_packet.kind() == Kind::EchoReply {
                                        self.device_writer.write_ipv4(&mut buf[12..])?;
                                        return Ok(());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    ip_turn_packet::Protocol::Ipv4Broadcast => {}
                    ip_turn_packet::Protocol::Unknown(_) => {}
                }
            }
            Protocol::OtherTurn => {}
            Protocol::UnKnow(_) => {}
        }
        return Ok(());
    }
    async fn control_gateway(&self, context: &Context, current_device: CurrentDeviceInfo, net_packet: NetPacket<&[u8]>, route_key: &RouteKey) -> crate::Result<()> {
        if net_packet.source() != current_device.virtual_gateway {
            return Ok(());
        }
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                let metric = net_packet.source_ttl() - net_packet.ttl() + 1;
                self.pong_packet(true, metric, context, current_device, net_packet.source(), pong_packet, route_key).await?;
            }
            ControlPacket::AddrResponse(addr_packet) => {
                if addr_packet.port() != 0
                    && !addr_packet.ipv4().is_multicast()
                    && !addr_packet.ipv4().is_broadcast()
                    && !addr_packet.ipv4().is_unspecified()
                    && !addr_packet.ipv4().is_loopback()
                    && !addr_packet.ipv4().is_private() {
                    self.nat_test.update_addr(addr_packet.ipv4(), addr_packet.port())
                }
            }
            _ => {}
        }
        Ok(())
    }
    async fn service(&self, context: &Context, current_device: CurrentDeviceInfo, net_packet: NetPacket<&[u8]>, route_key: &RouteKey) -> crate::Result<()> {
        match service_packet::Protocol::from(net_packet.transport_protocol()) {
            service_packet::Protocol::RegistrationRequest => {}
            service_packet::Protocol::RegistrationResponse => {
                let response = RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                let local_port = context.main_local_port()?;
                let local_ip = nat::local_ip()?;
                let nat_info = self.nat_test.re_test(Ipv4Addr::from(response.public_ip),
                                                     response.public_port as u16, local_ip, local_port).await;
                context.switch(nat_info.nat_type);
                let new_ip = Ipv4Addr::from(response.virtual_ip);
                let current_ip = current_device.virtual_ip();
                if current_ip != new_ip {
                    // ip发生变化
                    log::info!("ip发生变化,old_ip:{:?},new_ip:{:?}",current_ip,new_ip);
                    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                        let old_netmask = current_device.virtual_netmask;
                    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                        let old_gateway = current_device.virtual_gateway();
                    let virtual_ip = Ipv4Addr::from(response.virtual_ip);
                    let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
                    let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
                    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
                    self.device_writer.change_ip(virtual_ip, virtual_netmask, virtual_gateway, old_netmask, old_gateway)?;
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
                let ip_list: Vec<PeerDeviceInfo> = device_list_t
                    .device_info_list
                    .into_iter()
                    .map(|info| {
                        PeerDeviceInfo::new(
                            Ipv4Addr::from(info.virtual_ip),
                            info.name,
                            info.device_status as u8,
                            info.client_secret,
                        )
                    })
                    .collect();
                let route = Route::from(*route_key, 2, 99);
                for x in &ip_list {
                    if x.status == PeerDeviceStatus::Online {
                        context.add_route_if_absent(x.virtual_ip, route);
                    }
                }
                let mut dev = self.device_list.lock();
                if dev.0 != device_list_t.epoch as u16 {
                    dev.0 = device_list_t.epoch as u16;
                    dev.1 = ip_list;
                }
            }
            service_packet::Protocol::Unknown(u) => {
                log::warn!("未知服务协议:{}",u);
            }
            _ => {}
        }
        Ok(())
    }
    async fn error(&self, _context: &Context, current_device: CurrentDeviceInfo, _source: Ipv4Addr, net_packet: NetPacket<&[u8]>, _route_key: &RouteKey) -> crate::Result<()> {
        log::info!("current_device:{:?}",current_device);
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                return Err(Error::Stop("Token error".to_string()));
            }
            InErrorPacket::Disconnect => {
                {
                    //掉线epoch要归零
                    let mut dev = self.device_list.lock();
                    dev.0 = 0;
                }

                self.connect_status.store(ConnectStatus::Connecting);
                self.register.fast_register(current_device.virtual_ip).await?;
            }
            InErrorPacket::AddressExhausted => {
                //地址用尽
                return Err(Error::Stop("IP address has been exhausted".to_string()));
            }
            InErrorPacket::OtherError(e) => {
                log::error!("OtherError {:?}", e.message());
            }
            InErrorPacket::IpAlreadyExists => {
                log::error!("IpAlreadyExists");
            }
            InErrorPacket::InvalidIp => {
                log::error!("InvalidIp");
            }
            InErrorPacket::NoKey => {}
        }
        Ok(())
    }
}