use anyhow::anyhow;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
#[cfg(feature = "server_encrypt")]
use std::time::{Duration, Instant};

use crossbeam_utils::atomic::AtomicCell;
use packet::icmp::{icmp, Kind};
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use parking_lot::Mutex;
use protobuf::Message;

use crate::channel::context::ChannelContext;
use crate::channel::{Route, RouteKey};
use crate::cipher::Cipher;
#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::external_route::ExternalRoute;
use crate::handle::callback::{ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, VntCallback};
#[cfg(feature = "server_encrypt")]
use crate::handle::handshaker;
use crate::handle::handshaker::Handshake;
use crate::handle::recv_data::PacketHandler;
use crate::handle::{registrar, BaseConfigInfo, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
use crate::proto::message::{DeviceList, HandshakeResponse, RegistrationResponse};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::control_packet::ControlPacket;
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{ip_turn_packet, service_packet, NetPacket, Protocol, MAX_TTL};
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::{proto, PeerClientInfo};

/// 处理来源于服务端的包
#[derive(Clone)]
pub struct ServerPacketHandler<Call, Device> {
    #[cfg(feature = "server_encrypt")]
    rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
    server_cipher: Cipher,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    device: Device,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    config_info: BaseConfigInfo,
    nat_test: NatTest,
    callback: Call,
    #[cfg(feature = "server_encrypt")]
    up_key_time: Arc<AtomicCell<Instant>>,
    external_route: ExternalRoute,
    handshake: Handshake,
    #[cfg(feature = "integrated_tun")]
    tun_device_helper: crate::tun_tap_device::tun_create_helper::TunDeviceHelper,
}

impl<Call, Device> ServerPacketHandler<Call, Device> {
    pub fn new(
        #[cfg(feature = "server_encrypt")] rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
        server_cipher: Cipher,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        device: Device,
        device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
        config_info: BaseConfigInfo,
        nat_test: NatTest,
        callback: Call,
        external_route: ExternalRoute,
        handshake: Handshake,
        #[cfg(feature = "integrated_tun")]
        tun_device_helper: crate::tun_tap_device::tun_create_helper::TunDeviceHelper,
    ) -> Self {
        Self {
            #[cfg(feature = "server_encrypt")]
            rsa_cipher,
            server_cipher,
            current_device,
            device,
            device_map,
            config_info,
            nat_test,
            callback,
            #[cfg(feature = "server_encrypt")]
            up_key_time: Arc::new(AtomicCell::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(Instant::now()),
            )),
            external_route,
            handshake,
            #[cfg(feature = "integrated_tun")]
            tun_device_helper,
        }
    }
}

impl<Call: VntCallback, Device: DeviceWrite> PacketHandler for ServerPacketHandler<Call, Device> {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &ChannelContext,
        current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        if !current_device.is_server_addr(route_key.addr) {
            //拦截不是服务端的流量
            log::warn!(
                "route_key={:?},不是来源于服务端地址{}",
                route_key,
                current_device.connect_server
            );
        }
        context
            .route_table
            .update_read_time(&net_packet.source(), &route_key);
        if net_packet.protocol() == Protocol::Error
            && net_packet.transport_protocol()
                == crate::protocol::error_packet::Protocol::NoKey.into()
        {
            //服务端通知客户端上传密钥
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
                        log::info!("上传密钥到服务端:{:?}", route_key);
                        let packet = handshaker::secret_handshake_request_packet(
                            rsa_cipher,
                            self.config_info.token.clone(),
                            key,
                        )?;
                        context.send_by_key(&packet, route_key)?;
                    }
                }
            }
            return Ok(());
        } else if net_packet.protocol() == Protocol::Service
            && net_packet.transport_protocol() == service_packet::Protocol::HandshakeResponse.into()
        {
            let response = HandshakeResponse::parse_from_bytes(net_packet.payload())
                .map_err(|e| anyhow!("HandshakeResponse {:?}", e))?;
            log::info!("握手响应:{:?},{}", route_key, response);
            //设置为默认通道
            context.set_default_route_key(route_key);
            //如果开启了加密，则发送加密握手请求
            #[cfg(feature = "server_encrypt")]
            if let Some(key) = self.server_cipher.key() {
                {
                    let guard = self.rsa_cipher.lock();
                    if let Some(rsa_cipher) = guard.as_ref() {
                        if rsa_cipher.finger() == &response.key_finger {
                            let packet = handshaker::secret_handshake_request_packet(
                                rsa_cipher,
                                self.config_info.token.clone(),
                                key,
                            )?;
                            drop(guard);
                            context.send_by_key(&packet, route_key)?;
                            return Ok(());
                        }
                        log::warn!(
                            "拒绝服务端密钥对变化,原指纹:{:?}，新指纹:{:?}，addr:{:?}",
                            rsa_cipher.finger(),
                            response.key_finger,
                            route_key
                        );
                        return Ok(());
                    }
                    drop(guard);
                }
                let rsa_cipher = RsaCipher::new(&response.public_key)?;
                if rsa_cipher.finger() != &response.key_finger {
                    log::info!(
                        "服务端密钥和指纹不匹 配拒绝握手,指纹1:{:?}，指纹2:{:?}",
                        rsa_cipher.finger(),
                        response.key_finger
                    );
                    return Ok(());
                }
                let handshake_info = HandshakeInfo::new(
                    rsa_cipher.public_key()?.clone(),
                    response.key_finger,
                    response.version,
                );
                log::info!("加密握手请求:{:?}", handshake_info);

                if self.callback.handshake(handshake_info) {
                    let packet = handshaker::secret_handshake_request_packet(
                        &rsa_cipher,
                        self.config_info.token.clone(),
                        key,
                    )?;
                    context.send_by_key(&packet, route_key)?;
                    self.rsa_cipher.lock().replace(rsa_cipher);
                }
                return Ok(());
            }
            #[cfg(feature = "server_encrypt")]
            if let Ok(rsa_cipher) = RsaCipher::new(&response.public_key) {
                self.rsa_cipher.lock().replace(rsa_cipher);
            }
            let handshake_info = HandshakeInfo::new_no_secret(response.version);
            if self.callback.handshake(handshake_info) {
                //没有加密，则发送注册请求
                self.register(current_device, context, route_key)?;
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
                    ip_turn_packet::Protocol::WGIpv4 => {
                        if self.config_info.allow_wire_guard {
                            self.device.write(net_packet.payload())?;
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

impl<Call: VntCallback, Device: DeviceWrite> ServerPacketHandler<Call, Device> {
    fn service(
        &self,
        context: &ChannelContext,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
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
                log::info!("注册成功：{:?}", register_info);
                if self.callback.register(register_info) {
                    let route = Route::from_default_rt(route_key, 1);
                    context
                        .route_table
                        .add_route_if_absent(virtual_gateway, route);
                    let public_ip = response.public_ip.into();
                    let public_port = response.public_port as u16;
                    self.nat_test
                        .update_addr(route_key.index(), public_ip, public_port);
                    if route_key.protocol().is_tcp() {
                        log::info!("更新公网tcp端口 {public_port}");
                        self.nat_test.update_tcp_port(public_port);
                    }
                    let old = current_device;
                    let mut cur = *current_device;
                    loop {
                        let mut new_current_device = cur;
                        new_current_device.update(virtual_ip, virtual_netmask, virtual_gateway);
                        new_current_device.virtual_ip = virtual_ip;
                        new_current_device.virtual_netmask = virtual_netmask;
                        new_current_device.virtual_gateway = virtual_gateway;
                        new_current_device.status = ConnectStatus::Connected;
                        if let Err(c) = self
                            .current_device
                            .compare_exchange(cur, new_current_device)
                        {
                            cur = c;
                        } else {
                            break;
                        }
                    }

                    if old.virtual_ip != virtual_ip
                        || old.virtual_gateway != virtual_gateway
                        || old.virtual_netmask != virtual_netmask
                    {
                        if old.virtual_ip != Ipv4Addr::UNSPECIFIED {
                            log::info!("ip发生变化,old:{:?},response={:?}", old, response);
                        }
                        let device_config = crate::handle::callback::DeviceConfig::new(
                            #[cfg(feature = "integrated_tun")]
                            #[cfg(target_os = "windows")]
                            self.config_info.tap,
                            #[cfg(feature = "integrated_tun")]
                            #[cfg(any(
                                target_os = "windows",
                                target_os = "linux",
                                target_os = "macos"
                            ))]
                            self.config_info.device_name.clone(),
                            self.config_info.mtu,
                            virtual_ip,
                            virtual_netmask,
                            virtual_gateway,
                            virtual_network,
                            self.external_route.to_route(),
                        );
                        #[cfg(not(feature = "integrated_tun"))]
                        self.callback.create_device(device_config);
                        #[cfg(feature = "integrated_tun")]
                        {
                            self.tun_device_helper.stop();
                            #[cfg(any(
                                target_os = "windows",
                                target_os = "linux",
                                target_os = "macos"
                            ))]
                            match crate::tun_tap_device::create_device(
                                device_config,
                                &self.callback,
                            ) {
                                Ok(device) => {
                                    let tun_info = crate::handle::callback::DeviceInfo::new(
                                        device.name().unwrap_or("unknown".into()),
                                        "".into(),
                                    );
                                    log::info!("tun信息{:?}", tun_info);
                                    self.callback.create_tun(tun_info);
                                    self.tun_device_helper
                                        .start(device, self.config_info.allow_wire_guard)?;
                                }
                                Err(e) => {
                                    log::error!("{:?}", e);
                                    self.callback.error(e);
                                }
                            }
                            #[cfg(target_os = "android")]
                            {
                                let device_config = crate::handle::callback::DeviceConfig::new(
                                    self.config_info.mtu,
                                    virtual_ip,
                                    virtual_netmask,
                                    virtual_gateway,
                                    virtual_network,
                                    self.external_route.to_route(),
                                );
                                let device_fd = self.callback.generate_tun(device_config);
                                if device_fd == 0 {
                                    self.callback.error(ErrorInfo::new_msg(
                                        ErrorType::FailedToCrateDevice,
                                        "device_fd == 0".into(),
                                    ));
                                } else {
                                    let device =
                                        unsafe { tun_rs::SyncDevice::from_fd(device_fd as _) };
                                    if let Err(e) = self
                                        .tun_device_helper
                                        .start(Arc::new(device), self.config_info.allow_wire_guard)
                                    {
                                        self.callback.error(ErrorInfo::new_msg(
                                            ErrorType::FailedToCrateDevice,
                                            format!("{:?}", e),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    self.set_device_info_list(response.device_info_list, response.epoch as _);
                    if old.status.offline() {
                        self.callback.success();
                    }
                }
            }
            service_packet::Protocol::PushDeviceList => {
                let response = DeviceList::parse_from_bytes(net_packet.payload()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("PushDeviceList {:?}", e))
                })?;
                self.set_device_info_list(response.device_info_list, response.epoch as _);
            }
            service_packet::Protocol::SecretHandshakeResponse => {
                log::info!("SecretHandshakeResponse");
                //加密握手结束，发送注册数据
                self.register(current_device, context, route_key)?;
            }
            _ => {
                log::warn!(
                    "service_packet::Protocol::Unknown = {:?}",
                    net_packet.head()
                );
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
                    info.client_secret_hash,
                    info.wireguard,
                )
            })
            .collect();
        {
            let mut dev = self.device_map.lock();
            //这里可能会收到旧的消息，但是随着时间推移总会收到新的
            dev.0 = epoch;
            dev.1.clear();
            for info in ip_list.clone() {
                dev.1.insert(info.virtual_ip, info);
            }
        }
        self.callback.peer_client_list(
            ip_list
                .into_iter()
                .map(|v| PeerClientInfo::new(v.virtual_ip, v.name, v.status, v.client_secret))
                .collect(),
        );
    }
    fn register(
        &self,
        current_device: &CurrentDeviceInfo,
        context: &ChannelContext,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
        if current_device.status.online() {
            log::info!("已连接的不需要注册，{:?}", self.config_info);
            return Ok(());
        }
        //设置为默认通道
        context.set_default_route_key(route_key);
        let token = self.config_info.token.clone();
        let device_id = self.config_info.device_id.clone();
        let name = self.config_info.name.clone();
        let client_secret = self
            .config_info
            .client_secret_hash
            .as_ref()
            .map(|v| v.as_ref());
        let mut ip = self.config_info.ip;
        if ip.is_none() {
            ip = Some(current_device.virtual_ip)
        }
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
        log::info!("发送注册请求，{:?}", self.config_info);
        //注册请求只发送到默认通道
        context.send_default(&response, current_device.connect_server)?;
        Ok(())
    }
    fn error(
        &self,
        context: &ChannelContext,
        _current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> io::Result<()> {
        match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload())? {
            InErrorPacket::TokenError => {
                // token错误，可能是服务端设置了白名单
                let err = ErrorInfo::new(ErrorType::TokenError);
                self.callback.error(err);
            }
            InErrorPacket::Disconnect => {
                crate::handle::change_status(&self.current_device, ConnectStatus::Connecting);
                let err = ErrorInfo::new(ErrorType::Disconnect);
                self.callback.error(err);
                //掉线epoch要归零
                {
                    let mut dev = self.device_map.lock();
                    dev.0 = 0;
                    drop(dev);
                }
                self.handshake
                    .send(context, self.config_info.server_secret, route_key.addr)?;
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
                let err = ErrorInfo::new(ErrorType::IpAlreadyExists);
                self.callback.error(err);
            }
            InErrorPacket::InvalidIp => {
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
        context: &ChannelContext,
        current_device: &CurrentDeviceInfo,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
    ) -> anyhow::Result<()> {
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
                let epoch = self.device_map.lock().0;
                if pong_packet.epoch() != epoch {
                    //纪元不一致，可能有新客户端连接，向服务端拉取客户端列表
                    let mut poll_device = NetPacket::new_encrypt([0; 12 + ENCRYPTION_RESERVED])?;
                    poll_device.set_source(current_device.virtual_ip);
                    poll_device.set_destination(current_device.virtual_gateway);
                    poll_device.set_default_version();
                    poll_device.set_gateway_flag(true);
                    poll_device.first_set_ttl(MAX_TTL);
                    poll_device.set_protocol(Protocol::Service);
                    poll_device
                        .set_transport_protocol(service_packet::Protocol::PullDeviceList.into());
                    self.server_cipher.encrypt_ipv4(&mut poll_device)?;
                    //发送到默认服务端即可
                    context.send_default(&poll_device, current_device.connect_server)?;
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
