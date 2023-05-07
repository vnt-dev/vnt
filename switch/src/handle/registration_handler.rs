use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::Local;
use p2p_channel::channel::sender::Sender;
use p2p_channel::channel::Channel;
use protobuf::Message;

use crate::error::*;
use crate::proto::message::{RegistrationRequest, RegistrationResponse};
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, Version, MAX_TTL};

///向中继服务器注册，token标识一个虚拟网关，device_id防止多次注册时得到的ip不一致
pub fn registration(
    channel: &mut Channel<Ipv4Addr>,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
) -> Result<RegistrationResponse> {
    let request_packet =
        registration_request_packet(token.clone(), device_id.clone(), name.clone(), false)?;
    let buf = request_packet.buffer();
    let mut recv_buf = [0u8; 10240];
    channel.send_to_addr(buf, server_address)?;
    let (len, route) = channel.recv_from(&mut recv_buf, Some(Duration::from_millis(300)))?;
    if server_address != route.addr {
        return Err(Error::Warn(format!("数据来源错误：{:?}", route.addr)));
    }
    let net_packet = NetPacket::new(&recv_buf[..len])?;
    return match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::RegistrationResponse => {
                    let response = RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                    Ok(response)
                }
                _ => Err(Error::Warn(format!("数据错误：{:?}", net_packet))),
            }
        }
        Protocol::Error => {
            match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload()) {
                Ok(e) => match e {
                    InErrorPacket::TokenError => Err(Error::Stop("token错误".to_string())),
                    InErrorPacket::Disconnect => Err(Error::Warn("断开连接".to_string())),
                    InErrorPacket::AddressExhausted => Err(Error::Stop("地址用尽".to_string())),
                    InErrorPacket::OtherError(e) => match e.message() {
                        Ok(str) => Err(Error::Warn(str)),
                        Err(e) => Err(Error::Warn(format!("{:?}", e))),
                    },
                },
                Err(e) => Err(Error::Warn(format!("{:?}", e))),
            }
        }
        _ => Err(Error::Warn(format!("数据错误：{:?}", net_packet))),
    };
}

fn registration_request_packet(
    token: String,
    device_id: String,
    name: String,
    is_fast: bool,
) -> crate::Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.device_id = device_id;
    request.name = name;
    request.is_fast = is_fast;
    let bytes = request.write_to_bytes()?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::RegistrationRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes);
    Ok(net_packet)
}

pub struct Register {
    sender: Sender<Ipv4Addr>,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
    time: AtomicI64,
}

impl Register {
    pub fn new(
        sender: Sender<Ipv4Addr>,
        server_address: SocketAddr,
        token: String,
        device_id: String,
        name: String,
    ) -> Self {
        Self {
            sender,
            server_address,
            token,
            device_id,
            name,
            time: AtomicI64::new(0),
        }
    }
    pub fn fast_register(&self) -> io::Result<()> {
        let last = self.time.load(Ordering::Relaxed);
        let new = Local::now().timestamp_millis();
        if new - last < 1000
            || self
                .time
                .compare_exchange(last, new, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            //短时间不重复注册
            return Ok(());
        }
        log::info!("重新连接");
        let request_packet = registration_request_packet(
            self.token.clone(),
            self.device_id.clone(),
            self.name.clone(),
            false,
        )
        .unwrap();
        let buf = request_packet.buffer();
        self.sender.send_to_addr(buf, self.server_address)?;
        Ok(())
    }
}
