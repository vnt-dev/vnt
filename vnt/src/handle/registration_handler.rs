use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use crossbeam_utils::atomic::AtomicCell;

use protobuf::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::handle::PeerDeviceInfo;

use crate::proto::message::{RegistrationRequest, RegistrationResponse};
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, Version, MAX_TTL};
use crate::protocol::body::ENCRYPTION_RESERVED;

pub enum ReqEnum {
    TokenError,
    AddressExhausted,
    IpAlreadyExists,
    InvalidIp,
    Timeout,
    ServerError(String),
    Other(String),
}

#[derive(Clone, Debug)]
pub struct RegResponse {
    pub virtual_ip: Ipv4Addr,
    pub virtual_gateway: Ipv4Addr,
    pub virtual_netmask: Ipv4Addr,
    pub epoch: u16,
    pub device_info_list: Vec<PeerDeviceInfo>,
    pub public_ip: Ipv4Addr,
    pub public_port: u16,
}

///向中继服务器注册，token标识一个虚拟网关，device_id防止多次注册时得到的ip不一致
pub async fn registration(
    main_channel: &UdpSocket,
    main_tcp_channel: Option<&mut TcpStream>,
    server_cipher: &Cipher,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
    ip: Ipv4Addr,
    client_secret: bool,
) -> Result<RegResponse, ReqEnum> {
    let request_packet =
        registration_request_packet(server_cipher, token.clone(), device_id.clone(), name.clone(), ip, false, false, client_secret).unwrap();
    let buf = request_packet.buffer();
    let mut recv_buf = [0u8; 10240];
    let recv_buf = if let Some(main_tcp_channel) = main_tcp_channel {
        let mut vec = vec![0; 4 + buf.len()];
        let len = buf.len();
        vec[2] = (len >> 8) as u8;
        vec[3] = (len & 0xFF) as u8;
        vec[4..].copy_from_slice(buf);
        if let Err(e) = main_tcp_channel.write_all(&vec).await {
            return Err(ReqEnum::Other(format!("send error:{}", e)));
        }
        if let Err(e) = main_tcp_channel.read_exact(&mut recv_buf[..4]).await {
            return Err(ReqEnum::Other(format!("read error:{}", e)));
        }
        let len = 4 + (((recv_buf[2] as u16) << 8) | recv_buf[3] as u16) as usize;
        if len > recv_buf.len() {
            return Err(ReqEnum::Other("too long".to_string()));
        }
        if let Err(e) = main_tcp_channel.read_exact(&mut recv_buf[4..len]).await {
            return Err(ReqEnum::Other(format!("read error:{}", e)));
        }
        &mut recv_buf[4..len]
    } else {
        if let Err(e) = main_channel.send_to(buf, server_address).await {
            return Err(ReqEnum::Other(format!("send error:{}", e)));
        }
        match tokio::time::timeout(Duration::from_millis(300), main_channel.recv_from(&mut recv_buf)).await {
            Ok(rs) => {
                match rs {
                    Ok((len, addr)) => {
                        if server_address != addr {
                            return Err(ReqEnum::Other(format!("invalid data,from {}", addr)));
                        }
                        &mut recv_buf[..len]
                    }
                    Err(e) => {
                        return Err(ReqEnum::Other(format!("receiver error:{}", e)));
                    }
                }
            }
            Err(_) => {
                return Err(ReqEnum::Timeout);
            }
        }
    };
    let mut net_packet = match NetPacket::new(recv_buf) {
        Ok(net_packet) => {
            net_packet
        }
        Err(e) => {
            return Err(ReqEnum::ServerError(format!("{}", e)));
        }
    };
    if let Err(e) = server_cipher.decrypt_ipv4(&mut net_packet) {
        return Err(ReqEnum::ServerError(format!("decrypt_ipv4 {}", e)));
    }
    match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationResponse => {
                    match RegistrationResponse::parse_from_bytes(net_packet.payload()) {
                        Ok(response) => {
                            let device_info_list: Vec<PeerDeviceInfo> = response
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
                            Ok(RegResponse {
                                virtual_ip: Ipv4Addr::from(response.virtual_ip),
                                virtual_gateway: Ipv4Addr::from(response.virtual_gateway),
                                virtual_netmask: Ipv4Addr::from(response.virtual_netmask),
                                epoch: response.epoch as u16,
                                device_info_list,
                                public_ip: Ipv4Addr::from(response.public_ip),
                                public_port: response.public_port as u16,
                            })
                        }
                        Err(_) => {
                            Err(ReqEnum::ServerError("invalid data".to_string()))
                        }
                    }
                }
                _ => {
                    Err(ReqEnum::ServerError("invalid data".to_string()))
                }
            }
        }
        Protocol::Error => {
            match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload()) {
                Ok(e) => match e {
                    InErrorPacket::TokenError => Err(ReqEnum::TokenError),
                    InErrorPacket::Disconnect => {
                        Err(ReqEnum::ServerError("disconnect".to_string()))
                    }
                    InErrorPacket::AddressExhausted => {
                        Err(ReqEnum::AddressExhausted)
                    }
                    InErrorPacket::OtherError(e) => match e.message() {
                        Ok(str) => {
                            Err(ReqEnum::ServerError(str))
                        }
                        Err(e) => Err(ReqEnum::Other(format!("{}", e))),
                    },
                    InErrorPacket::IpAlreadyExists => {
                        Err(ReqEnum::IpAlreadyExists)
                    }
                    InErrorPacket::InvalidIp => {
                        Err(ReqEnum::InvalidIp)
                    }
                    InErrorPacket::NoKey => {
                        Err(ReqEnum::ServerError("no key".to_string()))
                    }
                },
                Err(e) => Err(ReqEnum::Other(format!("{}", e))),
            }
        }
        _ => Err(ReqEnum::ServerError("invalid data".to_string())),
    }
}

fn registration_request_packet(
    server_cipher: &Cipher,
    token: String,
    device_id: String,
    name: String,
    ip: Ipv4Addr,
    is_fast: bool,
    allow_ip_change: bool,
    client_secret: bool,
) -> crate::Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.device_id = device_id;
    request.name = name;
    request.virtual_ip = ip.into();
    request.allow_ip_change = allow_ip_change;
    request.is_fast = is_fast;
    request.version = crate::VNT_VERSION.to_string();
    request.client_secret = client_secret;
    let bytes = request.write_to_bytes()?;
    let buf = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
    let mut net_packet = NetPacket::new_encrypt(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::RegistrationRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    server_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}

pub struct Register {
    server_cipher: Cipher,
    sender: ChannelSender,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
    time: AtomicCell<Instant>,
    client_secret: bool,
}

impl Register {
    pub fn new(
        server_cipher: Cipher,
        sender: ChannelSender,
        server_address: SocketAddr,
        token: String,
        device_id: String,
        name: String,
        client_secret: bool,
    ) -> Self {
        Self {
            server_cipher,
            sender,
            server_address,
            token,
            device_id,
            name,
            time: AtomicCell::new(Instant::now()),
            client_secret,
        }
    }
    pub async fn fast_register(&self, ip: Ipv4Addr) -> crate::Result<()> {
        let last = self.time.load();
        if last.elapsed() < Duration::from_secs(2)
            || self
            .time
            .compare_exchange(last, Instant::now())
            .is_err()
        {
            //短时间不重复注册
            return Ok(());
        }
        log::info!("重新连接");
        let request_packet = registration_request_packet(
            &self.server_cipher,
            self.token.clone(),
            self.device_id.clone(),
            self.name.clone(),
            ip,
            false,
            true,
            self.client_secret,
        )?;
        let buf = request_packet.buffer();
        self.sender.send_main(buf, self.server_address).await?;
        Ok(())
    }
}
