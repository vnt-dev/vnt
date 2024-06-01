use anyhow::anyhow;
use std::net::Ipv4Addr;

use protobuf::Message;

use crate::cipher::Cipher;
use crate::handle::{GATEWAY_IP, SELF_IP};
use crate::proto::message::RegistrationRequest;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{service_packet, NetPacket, Protocol, MAX_TTL};

/// 注册数据
pub fn registration_request_packet(
    server_cipher: &Cipher,
    token: String,
    device_id: String,
    name: String,
    ip: Option<Ipv4Addr>,
    is_fast: bool,
    allow_ip_change: bool,
    client_secret_hash: Option<&[u8]>,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::new();
    request.token = token;
    request.device_id = device_id;
    request.name = name;
    if let Some(ip) = ip {
        request.virtual_ip = ip.into();
    }
    request.allow_ip_change = allow_ip_change;
    request.is_fast = is_fast;
    request.version = crate::VNT_VERSION.to_string();
    if let Some(client_secret_hash) = client_secret_hash {
        request.client_secret = true;
        request
            .client_secret_hash
            .extend_from_slice(client_secret_hash);
    }
    let bytes = request
        .write_to_bytes()
        .map_err(|e| anyhow!("RegistrationRequest {:?}", e))?;
    let buf = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
    let mut net_packet = NetPacket::new_encrypt(buf)?;
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_default_version();
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service_packet::Protocol::RegistrationRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(&bytes)?;
    server_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
