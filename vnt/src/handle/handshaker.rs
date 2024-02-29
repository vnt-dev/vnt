use std::io;

use protobuf::Message;

#[cfg(feature = "server_encrypt")]
use crate::cipher::RsaCipher;
use crate::handle::{GATEWAY_IP, SELF_IP};
use crate::proto::message::HandshakeRequest;
#[cfg(feature = "server_encrypt")]
use crate::proto::message::SecretHandshakeRequest;
#[cfg(feature = "server_encrypt")]
use crate::protocol::body::RSA_ENCRYPTION_RESERVED;
use crate::protocol::{service_packet, NetPacket, Protocol, Version, MAX_TTL};

pub enum HandshakeEnum {
    NotSecret,
    KeyError,
    Timeout,
    ServerError(String),
    Other(String),
}

/// 第一次握手数据
pub fn handshake_request_packet(secret: bool) -> io::Result<NetPacket<Vec<u8>>> {
    let mut request = HandshakeRequest::new();
    request.secret = secret;
    request.version = crate::VNT_VERSION.to_string();
    let bytes = request.write_to_bytes().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("handshake_request_packet {:?}", e),
        )
    })?;
    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::HandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(net_packet)
}

/// 第二次加密握手
#[cfg(feature = "server_encrypt")]
pub fn secret_handshake_request_packet(
    rsa_cipher: &RsaCipher,
    token: String,
    key: &[u8],
) -> io::Result<NetPacket<Vec<u8>>> {
    let mut request = SecretHandshakeRequest::new();
    request.token = token;
    request.key = key.to_vec();
    let bytes = request.write_to_bytes().map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("secret_handshake_request_packet {:?}", e),
        )
    })?;
    let mut net_packet = NetPacket::new0(
        12 + bytes.len(),
        vec![0u8; 12 + bytes.len() + RSA_ENCRYPTION_RESERVED],
    )?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::SecretHandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    Ok(rsa_cipher.encrypt(&mut net_packet)?)
}
