use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use crossbeam_utils::atomic::AtomicCell;

use protobuf::Message;
use tokio::net::UdpSocket;
use crate::channel::sender::ChannelSender;

use crate::error::*;
use crate::proto::message::{RegistrationRequest, RegistrationResponse};
use crate::protocol::error_packet::InErrorPacket;
use crate::protocol::{service_packet, NetPacket, Protocol, Version, MAX_TTL};

///向中继服务器注册，token标识一个虚拟网关，device_id防止多次注册时得到的ip不一致
pub async fn registration(
    main_channel: &UdpSocket,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
) -> Result<RegistrationResponse> {
    let request_packet =
        registration_request_packet(token.clone(), device_id.clone(), name.clone(), false)?;
    let buf = request_packet.buffer();
    let mut recv_buf = [0u8; 10240];
    let mut count = 0;
    loop {
        match main_channel.send_to(buf, server_address).await {
            Ok(_) => {
                match tokio::time::timeout(Duration::from_millis(300), main_channel.recv_from(&mut recv_buf)).await {
                    Ok(rs) => {
                        match rs {
                            Ok((len, addr)) => {
                                if server_address == addr {
                                    let net_packet = NetPacket::new(&recv_buf[..len])?;
                                    match net_packet.protocol() {
                                        Protocol::Service => {
                                            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                                                service_packet::Protocol::RegistrationResponse => {
                                                    let response = RegistrationResponse::parse_from_bytes(net_packet.payload())?;
                                                    return Ok(response);
                                                }
                                                _ => println!("响应数据错误"),
                                            }
                                        }
                                        Protocol::Error => {
                                            match InErrorPacket::new(net_packet.transport_protocol(), net_packet.payload()) {
                                                Ok(e) => match e {
                                                    InErrorPacket::TokenError => return Err(Error::Stop("token错误".to_string())),
                                                    InErrorPacket::Disconnect => {
                                                        println!("断开连接");
                                                    }
                                                    InErrorPacket::AddressExhausted => {
                                                        println!("地址用尽");
                                                        log::warn!("地址用尽");
                                                    }
                                                    InErrorPacket::OtherError(e) => match e.message() {
                                                        Ok(str) => {
                                                            println!("其他异常:{:?}", str);
                                                            log::warn!("其他异常{:?}",str);
                                                        }
                                                        Err(e) => println!("其他异常:{:?}", e),
                                                    },
                                                },
                                                Err(e) => println!("数据解析异常:{:?}", e),
                                            }
                                        }
                                        _ => println!("响应数据错误"),
                                    };
                                }
                            }
                            Err(e) => {
                                println!("接收服务器数据失败:{:?}", e);
                                log::warn!("接收服务器数据失败:{:?}",e);
                            }
                        }
                    }
                    Err(_) => {
                        println!("接收超时");
                        log::warn!("接收超时");
                    }
                }
            }
            Err(e) => {
                println!("发送数据到服务器失败:{:?}", e);
                log::warn!("发送数据到服务器失败:{:?}",e);
            }
        }
        count += 1;
        println!("重试中(retrying)...");
        std::thread::sleep(Duration::from_secs(count % 10 + 1));
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
    request.version = "1.0.7".to_string();
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
    sender: ChannelSender,
    server_address: SocketAddr,
    token: String,
    device_id: String,
    name: String,
    time: AtomicCell<Instant>,
}

impl Register {
    pub fn new(
        sender: ChannelSender,
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
            time: AtomicCell::new(Instant::now()),
        }
    }
    pub async fn fast_register(&self) -> io::Result<()> {
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
            self.token.clone(),
            self.device_id.clone(),
            self.name.clone(),
            false,
        )
            .unwrap();
        let buf = request_packet.buffer();
        self.sender.send_main(buf, self.server_address).await?;
        Ok(())
    }
}
