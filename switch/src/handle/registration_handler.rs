use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use chrono::Local;
use crossbeam::atomic::AtomicCell;
use parking_lot::RwLock;
use protobuf::Message;

use crate::error::*;
use crate::handle::ConnectStatus;
use crate::proto::message::{RegistrationRequest, RegistrationResponse};
use crate::protocol::{error_packet, NetPacket, Protocol, service_packet, Version};
use crate::protocol::error_packet::InErrorPacket;

lazy_static::lazy_static! {
    static ref REQUEST:RwLock<Option<(String,String,String)>> = parking_lot::const_rwlock(None);
    static ref REGISTRATION_TIME:AtomicI64=AtomicI64::new(0);
    pub(crate) static ref CONNECTION_STATUS:AtomicCell<ConnectStatus> = AtomicCell::new(ConnectStatus::Connecting);
}

///向中继服务器注册，token标识一个虚拟网关，mac_address防止多次注册时得到的ip不一致
pub fn registration(
    udp: &UdpSocket,
    server_address: SocketAddr,
    token: String,
    mac_address: String,
    name: String,
) -> Result<RegistrationResponse> {
    // todo 和服务器通信加密
    let request_packet = registration_request_packet(token.clone(), mac_address.clone(), name.clone(), false)?;
    let buf = request_packet.buffer();
    let mut counter = 0;
    let mut recv_buf = [0u8; 10240];
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;
    loop {
        counter += 1;
        if counter & 10 == 10 {
            return Err(Error::Stop("注册请求超时".to_string()));
        }
        udp.send_to(buf, server_address)?;
        let (len, addr) = match udp.recv_from(&mut recv_buf) {
            Ok(ok) => ok,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    continue;
                }
                return Err(Error::Io(e));
            }
        };
        if server_address != addr {
            continue;
        }
        let net_packet = NetPacket::new(&recv_buf[..len])?;
        match net_packet.protocol() {
            Protocol::Service => {
                match service_packet::Protocol::from(net_packet.transport_protocol()) {
                    service_packet::Protocol::RegistrationResponse => {
                        let response =
                            RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                        let _ = REQUEST.write().replace((token, mac_address, name));
                        udp.set_read_timeout(None)?;
                        CONNECTION_STATUS.store(ConnectStatus::Connected);
                        return Ok(response);
                    }
                    _ => {}
                }
            }
            Protocol::Error => {
                return match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload()) {
                    Ok(e) => {
                        match e {
                            InErrorPacket::TokenError => {
                                Err(Error::Stop("token错误".to_string()))
                            }
                            InErrorPacket::Disconnect => {
                                Err(Error::Stop("断开连接".to_string()))
                            }
                            InErrorPacket::OtherError(e) => {
                                match e.message() {
                                    Ok(str) => {
                                        Err(Error::Stop(str))
                                    }
                                    Err(e) => {
                                        Err(Error::Stop(format!("{:?}", e)))
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        Err(Error::Stop(format!("{:?}", e)))
                    }
                };
            }
            _ => {
                return Err(Error::Stop(format!("数据错误：{:?}", net_packet)));
            }
        }
    }
}

fn registration_request_packet(token: String, mac_address: String, name: String, is_fast: bool) -> Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.mac_address = mac_address;
    request.name = name;
    request.is_fast = is_fast;
    let bytes = request.write_to_bytes()?;
    let buf = vec![0u8; 4 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::RegistrationRequest.into());
    net_packet.set_ttl(255);
    net_packet.set_payload(&bytes);
    Ok(net_packet)
}

pub fn fast_registration(udp: &UdpSocket, server_address: SocketAddr) -> Result<()> {
    let last = REGISTRATION_TIME.load(Ordering::Relaxed);
    let new = Local::now().timestamp_millis();
    if new - last < 2000
        || REGISTRATION_TIME
        .compare_exchange(last, new, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        //短时间不重复注册
        return Ok(());
    }
    CONNECTION_STATUS.store(ConnectStatus::Connecting);
    let lock = REQUEST.read();
    let option = lock.clone();
    drop(lock);
    if let Some((token, mac_address, name)) = option {
        let request_packet = registration_request_packet(token, mac_address, name, true)?;
        udp.send_to(request_packet.buffer(), server_address)?;
        REGISTRATION_TIME.store(Local::now().timestamp_millis(), Ordering::Relaxed);
        return Ok(());
    }
    return Err(Error::Stop("注册信息不存在".to_string()));
}
