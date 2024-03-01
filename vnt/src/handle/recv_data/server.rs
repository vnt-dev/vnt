use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(feature = "server_encrypt")]
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;

use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use tun::device::IFace;
use tun::Device;

use crate::channel::context::Context;
use crate::channel::{Route, RouteKey};
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::external_route::ExternalRoute;
use crate::handle::callback::{ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, VntCallback};
#[cfg(feature = "server_encrypt")]
use crate::handle::handshaker;
use crate::handle::recv_data::PacketHandler;
use crate::handle::{registrar, BaseConfigInfo, CurrentDeviceInfo, PeerDeviceInfo, GATEWAY_IP};
use crate::nat::NatTest;
use crate::proto;
use crate::proto::message::{DeviceList, HandshakeResponse, RegistrationResponse};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol, Version, MAX_TTL};

/// 处理来源于服务端的包
#[derive(Clone)]
pub struct ServerPacketHandler<Call> {
    #[cfg(feature = "server_encrypt")]
    rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
    server_cipher: Cipher,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device: Arc<Device>,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    config_info: BaseConfigInfo,
    nat_test: NatTest,
    callback: Call,
    #[cfg(feature = "server_encrypt")]
    up_key_time: Arc<AtomicCell<Instant>>,
    route_record: Arc<Mutex<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    external_route: ExternalRoute,
}

impl<Call> ServerPacketHandler<Call> {
    pub fn new(
        #[cfg(feature = "server_encrypt")] rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
        server_cipher: Cipher,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        device: Arc<Device>,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
        config_info: BaseConfigInfo,
        nat_test: NatTest,
        callback: Call,
        external_route: ExternalRoute,
    ) -> Self {
        Self {
            #[cfg(feature = "server_encrypt")]
            rsa_cipher,
            server_cipher,
            current_device,
            device,
            device_list,
            config_info,
            nat_test,
            callback,
            #[cfg(feature = "server_encrypt")]
            up_key_time: Arc::new(AtomicCell::new(Instant::now() - Duration::from_secs(60))),
            route_record: Arc::new(Mutex::default()),
            external_route,
        }
    }
}

impl<Call: VntCallback> PacketHandler for ServerPacketHandler<Call> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &Context,
        current_device: &CurrentDeviceInfo,
    ) -> io::Result<()> {
        if net_packet.protocol() == Protocol::Error
            && net_packet.transport_protocol()
                == crate::protocol::error_packet::Protocol::NoKey.into()
        {
            //开启服务端加密的情况下，只有这个回应是不加密的，是服务端通知客户端上传密钥
            #[cfg(feature = "server_encrypt")]
            {
                let mutex_guard = self.rsa_cipher.lock();
                if let Some(rsa_cipher) = mutex_guard.as_ref() {
                    let last = self.up_key_time.load();
                    if last.elapsed() < Duration::from_secs(1)
                        || self
                            .up_key_time
                            .compare_exchange(last, Instant::now())
                            .is_err()
                    {
                        //短时间不重复上传服务端密钥
                        return Ok(());
                    }
                    if let Some(key) = self.server_cipher.key() {
                        log::warn!("上传密钥到服务端:{:?}", route_key);
                        let packet = handshaker::secret_handshake_request_packet(
                            rsa_cipher,
                            self.config_info.token.clone(),
                            key,
                        )?;
                        context.send_by_key(packet.buffer(), route_key)?;
                    }
                }
            }
            return Ok(());
        } else if net_packet.protocol() == Protocol::Service
            && net_packet.transport_protocol() == service_packet::Protocol::HandshakeResponse.into()
        {
            let response =
                HandshakeResponse::parse_from_bytes(net_packet.payload()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("HandshakeResponse {:?}", e))
                })?;
            //如果开启了加密，则发送加密握手请求
            #[cfg(feature = "server_encrypt")]
            if let Some(key) = self.server_cipher.key() {
                let rsa_cipher = RsaCipher::new(&response.public_key)?;
                let handshake_info = HandshakeInfo::new(
                    rsa_cipher.public_key()?.clone(),
                    rsa_cipher.finger()?,
                    response.version,
                );
                log::warn!("加密握手请求:{:?}", handshake_info);

                if self.callback.handshake(handshake_info) {
                    let packet = handshaker::secret_handshake_request_packet(
                        &rsa_cipher,
                        self.config_info.token.clone(),
                        key,
                    )?;
                    context.send_by_key(packet.buffer(), route_key)?;
                    self.rsa_cipher.lock().replace(rsa_cipher);
                }
                return Ok(());
            }

            let handshake_info = HandshakeInfo::new_no_secret(response.version);
            if self.callback.handshake(handshake_info) {
                //没有加密，则发送注册请求
                self.register(current_device, context)?;
            }

            return Ok(());
        }
        //服务端数据解密
        self.server_cipher.decrypt_ipv4(&mut net_packet)?;
        match net_packet.protocol() {
            Protocol::Service => {
                self.service(context, current_device, net_packet, route_key)?;
            }
            Protocol::Error => {
                self.error(context, current_device, net_packet, route_key)?;
            }
            Protocol::Control => {
                self.control(context, current_device, net_packet, route_key)?;
            }
            Protocol::IpTurn => {
                match ip_turn_packet::Protocol::from(net_packet.transport_protocol()) {
                    ip_turn_packet::Protocol::Ipv4 => {
                        let ipv4 = IpV4Packet::new(net_packet.payload())?;
                        match ipv4.protocol() {
                            ipv4::protocol::Protocol::Icmp => {
                                if ipv4.destination_ip() == current_device.virtual_ip {
                                    let icmp_packet = icmp::IcmpPacket::new(ipv4.payload())?;
                                    if icmp_packet.kind() == Kind::EchoReply {
                                        //网关ip ping的回应
                                        self.device.write(net_packet.payload())?;
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
            Protocol::Unknown(_) => {}
        }
        Ok(())
    }
}

impl<Call: VntCallback> ServerPacketHandler<Call> {
    fn service(
        &self,
        context: &Context,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match service_packet::Protocol::from(net_packet.transport_protocol()) {
            service_packet::Protocol::RegistrationResponse => {
                let response = RegistrationResponse::parse_from_bytes(net_packet.payload())
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("RegistrationResponse {:?}", e),
                        )
                    })?;
                let virtual_ip = Ipv4Addr::from(response.virtual_ip);
                let virtual_netmask = Ipv4Addr::from(response.virtual_netmask);
                let virtual_gateway = Ipv4Addr::from(response.virtual_gateway);
                let virtual_network =
                    Ipv4Addr::from(response.virtual_ip & response.virtual_netmask);
                let register_info = RegisterInfo::new(virtual_ip, virtual_netmask, virtual_gateway);
                if self.callback.register(register_info) {
                    let route = Route::from(route_key, 1, 199);
                    context
                        .route_table
                        .add_route_if_absent(virtual_gateway, route);
                    let old = current_device;
                    let mut cur = *current_device;
                    loop {
                        let mut new_current_device = cur;
                        new_current_device.update(virtual_ip, virtual_netmask, virtual_gateway);
                        new_current_device.virtual_ip = virtual_ip;
                        new_current_device.virtual_netmask = virtual_netmask;
                        new_current_device.virtual_gateway = virtual_gateway;
                        if let Err(c) = self
                            .current_device
                            .compare_exchange(cur, new_current_device)
                        {
                            cur = c;
                        } else {
                            break;
                        }
                    }
                    let _ = context.change_status(&self.current_device);

                    let public_ip = response.public_ip.into();
                    let public_port = response.public_port as u16;
                    self.nat_test
                        .update_addr(route_key.index(), public_ip, public_port);
                    if old.virtual_ip != virtual_ip
                        || old.virtual_gateway != virtual_gateway
                        || old.virtual_netmask != virtual_netmask
                    {
                        if old.virtual_ip != Ipv4Addr::UNSPECIFIED {
                            log::info!("ip发生变化,old:{:?},response={:?}", old, response);
                        }
                        self.device.set_ip(virtual_ip, virtual_netmask)?;
                        let mut guard = self.route_record.lock();
                        for (dest, mask) in guard.drain(..) {
                            if let Err(e) = self.device.delete_route(dest, mask) {
                                log::warn!("删除路由失败 ={:?}", e);
                            }
                        }
                        if let Err(e) = self.device.add_route(virtual_network, virtual_netmask, 1) {
                            log::warn!("添加默认路由失败 ={:?}", e);
                        } else {
                            guard.push((virtual_network, virtual_netmask));
                        }
                        if let Err(e) =
                            self.device
                                .add_route(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, 1)
                        {
                            log::warn!("添加广播路由失败 ={:?}", e);
                        } else {
                            guard.push((Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST));
                        }

                        if let Err(e) = self.device.add_route(
                            Ipv4Addr::from([224, 0, 0, 0]),
                            Ipv4Addr::from([240, 0, 0, 0]),
                            1,
                        ) {
                            log::warn!("添加组播路由失败 ={:?}", e);
                        } else {
                            guard.push((
                                Ipv4Addr::from([224, 0, 0, 0]),
                                Ipv4Addr::from([240, 0, 0, 0]),
                            ));
                        }

                        for (dest, mask) in self.external_route.to_route() {
                            if let Err(e) = self.device.add_route(dest, mask, 1) {
                                log::warn!("添加路由失败 ={:?}", e);
                            } else {
                                guard.push((dest, mask));
                            }
                        }
                    }
                    self.set_device_info_list(response.device_info_list, response.epoch as _);
                }
            }
            service_packet::Protocol::RegistrationRequest => {
                //不处理注册包
            }
            service_packet::Protocol::PollDeviceList => {}
            service_packet::Protocol::PushDeviceList => {
                let response = DeviceList::parse_from_bytes(net_packet.payload()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("PushDeviceList {:?}", e))
                })?;
                self.set_device_info_list(response.device_info_list, response.epoch as _);
            }
            service_packet::Protocol::HandshakeRequest => {}
            service_packet::Protocol::HandshakeResponse => {}
            service_packet::Protocol::SecretHandshakeRequest => {}
            service_packet::Protocol::SecretHandshakeResponse => {
                //加密握手结束，发送注册数据
                self.register(current_device, context)?;
            }
            service_packet::Protocol::Unknown(e) => {
                log::warn!("service_packet::Protocol::Unknown = {}", e);
            }
        }
        Ok(())
    }
    fn set_device_info_list(&self, device_info_list: Vec<proto::message::DeviceInfo>, epoch: u16) {
        let ip_list: Vec<PeerDeviceInfo> = device_info_list
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
        let mut dev = self.device_list.lock();
        //这里可能会收到旧的消息，但是随着时间推移总会收到新的
        dev.0 = epoch;
        dev.1 = ip_list;
    }
    fn register(&self, current_device: &CurrentDeviceInfo, context: &Context) -> io::Result<()> {
        if current_device.status.online() {
            //已连接的不需要注册
            return Ok(());
        }
        let token = self.config_info.token.clone();
        let device_id = self.config_info.device_id.clone();
        let name = self.config_info.name.clone();
        let client_secret = self.config_info.client_secret;
        let ip = self.config_info.ip;
        let response = registrar::registration_request_packet(
            &self.server_cipher,
            token,
            device_id,
            name,
            ip,
            false,
            false,
            client_secret,
        )?;
        //注册请求只发送到默认通道
        context.send_default(response.buffer(), current_device.connect_server)
    }
    fn error(
        &self,
        _context: &Context,
        _current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        _route_key: RouteKey,
    ) -> io::Result<()> {
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                // token错误，可能是服务端设置了白名单
                let err = ErrorInfo::new(ErrorType::TokenError);
                self.callback.error(err);
            }
            InErrorPacket::Disconnect => {
                let err = ErrorInfo::new(ErrorType::Disconnect);
                self.callback.error(err);
                //掉线epoch要归零
                {
                    let mut dev = self.device_list.lock();
                    dev.0 = 0;
                    drop(dev);
                }
                // self.register(current_device, context, route_key)?;
            }
            InErrorPacket::AddressExhausted => {
                // 地址用尽
                let err = ErrorInfo::new(ErrorType::AddressExhausted);
                self.callback.error(err);
            }
            InErrorPacket::OtherError(e) => {
                let err = ErrorInfo::new_msg(ErrorType::Unknown, e.message()?);
                self.callback.error(err);
            }
            InErrorPacket::IpAlreadyExists => {
                log::error!("IpAlreadyExists");
                let err = ErrorInfo::new(ErrorType::IpAlreadyExists);
                self.callback.error(err);
            }
            InErrorPacket::InvalidIp => {
                log::error!("InvalidIp");
                let err = ErrorInfo::new(ErrorType::InvalidIp);
                self.callback.error(err);
            }
            InErrorPacket::NoKey => {
                //这个类型最开头已经处理过，这里忽略
            }
        }
        Ok(())
    }
    fn control(
        &self,
        context: &Context,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match ControlPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            ControlPacket::PongPacket(pong_packet) => {
                let current_time = crate::handle::now_time() as u16;
                if current_time < pong_packet.time() {
                    return Ok(());
                }
                let metric = net_packet.source_ttl() - net_packet.ttl() + 1;
                let rt = (current_time - pong_packet.time()) as i64;
                let route = Route::from(route_key, metric, rt);
                context.route_table.add_route(net_packet.source(), route);
                let epoch = self.device_list.lock().0;
                if pong_packet.epoch() != epoch {
                    //纪元不一致，可能有新客户端连接，向服务端拉取客户端列表
                    let mut poll_device = NetPacket::new_encrypt([0; 12 + ENCRYPTION_RESERVED])?;
                    poll_device.set_source(current_device.virtual_ip);
                    poll_device.set_destination(GATEWAY_IP);
                    poll_device.set_version(Version::V1);
                    poll_device.set_gateway_flag(true);
                    poll_device.first_set_ttl(MAX_TTL);
                    poll_device.set_protocol(Protocol::Service);
                    poll_device
                        .set_transport_protocol(service_packet::Protocol::PollDeviceList.into());
                    self.server_cipher.encrypt_ipv4(&mut poll_device)?;
                    //发送到默认服务端即可
                    context.send_default(poll_device.buffer(), current_device.connect_server)?;
                }
            }
            ControlPacket::AddrResponse(addr_packet) => {
                //更新本地公网ipv4
                self.nat_test.update_addr(
                    route_key.index(),
                    addr_packet.ipv4(),
                    addr_packet.port(),
                );
            }
            _ => {}
        }
        Ok(())
    }
}
