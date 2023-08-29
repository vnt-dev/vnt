use std::net::SocketAddr;
use std::time::Duration;

use protobuf::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::channel::channel::Context;
use crate::cipher::{Cipher, RsaCipher};
use crate::proto::message::{HandshakeRequest, HandshakeResponse, SecretHandshakeRequest};
use crate::protocol::{MAX_TTL, NetPacket, Protocol, service_packet, Version};
use crate::protocol::body::ENCRYPTION_RESERVED;


pub enum HandshakeEnum {
    NotSecret,
    KeyError,
    Timeout,
    ServerError(String),
    Other(String),
}

fn handshake_request_packet(secret: bool) -> crate::Result<NetPacket<Vec<u8>>> {
    let mut request = HandshakeRequest::new();
    request.secret = secret;
    request.version = crate::VNT_VERSION.to_string();
    let bytes = request.write_to_bytes()?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::HandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}

fn secret_handshake_request_packet(rsa_cipher: &RsaCipher, token: String, key: &[u8]) -> crate::Result<NetPacket<Vec<u8>>> {
    let mut request = SecretHandshakeRequest::new();
    request.token = token;
    request.key = key.to_vec();
    let bytes = request.write_to_bytes()?;
    let mut net_packet = NetPacket::new_encrypt(vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED])?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::SecretHandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(rsa_cipher.encrypt(&mut net_packet)?)
}

/// 第一次握手，拿到公钥
pub async fn handshake(main_channel: &UdpSocket, main_tcp_channel: Option<&mut TcpStream>,
                       server_address: SocketAddr, secret: bool) -> Result<Option<RsaCipher>, HandshakeEnum> {
    let request_packet = handshake_request_packet(secret).unwrap();
    let send_buf = request_packet.buffer();
    let mut recv_buf = [0u8; 10240];
    let len = send_recv(main_channel, main_tcp_channel, server_address, send_buf, &mut recv_buf).await?;
    let net_packet = match NetPacket::new(&recv_buf[..len]) {
        Ok(net_packet) => {
            net_packet
        }
        Err(e) => {
            return Err(HandshakeEnum::Other(format!("net_packet {}", e)));
        }
    };
    match net_packet.protocol() {
        Protocol::Service => {
            match service_packet::Protocol::from(net_packet.transport_protocol()) {
                service_packet::Protocol::HandshakeResponse => {
                    match HandshakeResponse::parse_from_bytes(net_packet.payload()) {
                        Ok(response) => {
                            if !response.secret && secret {
                                //客户端要加密，服务端不支持加密
                                return Err(HandshakeEnum::NotSecret);
                            }
                            if secret {
                                //转换公钥 
                                match RsaCipher::new(&response.public_key) {
                                    Ok(rsa) => {
                                        match rsa.finger() {
                                            Ok(finger) => {
                                                if finger != response.key_finger {
                                                    return Err(HandshakeEnum::Other("finger error".to_string()));
                                                }
                                            }
                                            Err(e) => {
                                                return Err(HandshakeEnum::Other(format!("finger {}", e)));
                                            }
                                        }
                                        Ok(Some(rsa))
                                    }
                                    Err(e) => {
                                        return Err(HandshakeEnum::Other(format!("RsaCipher {}", e)));
                                    }
                                }
                            } else {
                                Ok(None)
                            }
                        }
                        Err(e) => {
                            return Err(HandshakeEnum::Other(format!("parse_from_bytes {}", e)));
                        }
                    }
                }
                _ => {
                    return Err(HandshakeEnum::Other("not match".to_string()));
                }
            }
        }
        _ => {
            return Err(HandshakeEnum::Other("not match".to_string()));
        }
    }
}

async fn send_recv(main_channel: &UdpSocket, main_tcp_channel: Option<&mut TcpStream>,
                   server_address: SocketAddr, send_buf: &[u8], recv_buf: &mut [u8]) -> Result<usize, HandshakeEnum> {
    if let Some(main_tcp_channel) = main_tcp_channel {
        let mut head = [0; 4];
        let len = send_buf.len();
        head[2] = (len >> 8) as u8;
        head[3] = (len & 0xFF) as u8;
        if let Err(e) = main_tcp_channel.write_all(&head).await {
            return Err(HandshakeEnum::Other(format!("send error:{}", e)));
        }
        if let Err(e) = main_tcp_channel.write_all(send_buf).await {
            return Err(HandshakeEnum::Other(format!("send error:{}", e)));
        }
        if let Err(e) = main_tcp_channel.read_exact(&mut head).await {
            return Err(HandshakeEnum::Other(format!("read error:{}", e)));
        }
        let len = (((head[2] as u16) << 8) | head[3] as u16) as usize;
        if len > recv_buf.len() {
            return Err(HandshakeEnum::Other("too long".to_string()));
        }
        if let Err(e) = main_tcp_channel.read_exact(&mut recv_buf[..len]).await {
            return Err(HandshakeEnum::Other(format!("read error:{}", e)));
        }
        Ok(len)
    } else {
        if let Err(e) = main_channel.send_to(send_buf, server_address).await {
            return Err(HandshakeEnum::Other(format!("send error:{}", e)));
        }
        match tokio::time::timeout(Duration::from_millis(300), main_channel.recv_from(recv_buf)).await {
            Ok(rs) => {
                match rs {
                    Ok((len, addr)) => {
                        if server_address != addr {
                            return Err(HandshakeEnum::Other(format!("invalid data,from {}", addr)));
                        }
                        Ok(len)
                    }
                    Err(e) => {
                        return Err(HandshakeEnum::Other(format!("receiver error:{}", e)));
                    }
                }
            }
            Err(_) => {
                return Err(HandshakeEnum::Timeout);
            }
        }
    }
}

/// 第二次握手，同步对称密钥，后续将使用对称加密
pub async fn secret_handshake(main_channel: &UdpSocket, main_tcp_channel: Option<&mut TcpStream>,
                              server_address: SocketAddr, rsa_cipher: &RsaCipher, server_cipher: &Cipher, token: String)
                              -> Result<(), HandshakeEnum> {
    let secret_packet = match secret_handshake_request_packet(rsa_cipher, token, server_cipher.key().unwrap()) {
        Ok(secret_packet) => {
            secret_packet
        }
        Err(e) => {
            return Err(HandshakeEnum::Other(format!("secret_handshake_request_packet {}", e)));
        }
    };
    let send_buf = secret_packet.buffer();
    let mut recv_buf = [0u8; 10240];
    let len = send_recv(main_channel, main_tcp_channel, server_address, send_buf, &mut recv_buf).await?;
    let mut net_packet = match NetPacket::new(&mut recv_buf[..len]) {
        Ok(net_packet) => { net_packet }
        Err(e) => {
            return Err(HandshakeEnum::Other(format!("secret_net_packet {}", e)));
        }
    };
    match server_cipher.decrypt_ipv4(&mut net_packet) {
        Ok(_) => {
            if net_packet.is_gateway() && net_packet.protocol() == Protocol::Service
                && service_packet::Protocol::from(net_packet.transport_protocol()) ==
                service_packet::Protocol::SecretHandshakeResponse {
                Ok(())
            } else {
                Err(HandshakeEnum::Other("not match".to_string()))
            }
        }
        Err(e) => {
            Err(HandshakeEnum::Other(format!("decrypt_ipv4 {}", e)))
        }
    }
}

pub async fn secret_handshake_req(context: &Context,
                                  server_address: SocketAddr, rsa_cipher: &RsaCipher, server_cipher: &Cipher, token: String, ) -> crate::Result<()> {
    let secret_packet = secret_handshake_request_packet(rsa_cipher, token, server_cipher.key().unwrap())?;
    context.send_main(secret_packet.buffer(), server_address).await?;
    if context.is_main_tcp(){
        context.send_main_udp(secret_packet.buffer(),server_address).await?;
    }
    Ok(())
}
