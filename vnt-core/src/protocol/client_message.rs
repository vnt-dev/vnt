mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.client.rs"));
}

use anyhow::bail;
use bytes::BytesMut;
use prost::Message;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::ProtoToBytesMut;
pub use proto::*;

pub fn encode_nat_info(nat_info: &rust_p2p_core::nat::NatInfo) -> proto::NatInfo {
    let nat_type = match nat_info.nat_type {
        rust_p2p_core::nat::NatType::Cone => proto::NatType::Cone,
        rust_p2p_core::nat::NatType::Symmetric => proto::NatType::Symmetric,
    };

    proto::NatInfo {
        nat_type: nat_type.into(),
        public_ips: nat_info.public_ips.iter().map(|v| (*v).into()).collect(),
        public_udp_ports: nat_info
            .public_udp_ports
            .iter()
            .map(|v| (*v).into())
            .collect(),
        public_port_range: nat_info.public_port_range.into(),
        local_ipv4s: nat_info.local_ipv4s.iter().map(|v| (*v).into()).collect(),
        ipv6: nat_info.ipv6.map(|v| v.octets().to_vec()),
        local_udp_ports: nat_info
            .local_udp_ports
            .iter()
            .map(|v| (*v).into())
            .collect(),
        local_tcp_port: nat_info.local_tcp_port.into(),
        public_tcp_port: nat_info.public_tcp_port.into(),
    }
}
pub fn decode_nat_info(msg: proto::NatInfo) -> anyhow::Result<rust_p2p_core::nat::NatInfo> {
    let nat_type = match msg.nat_type() {
        proto::NatType::Cone => rust_p2p_core::nat::NatType::Cone,
        proto::NatType::Symmetric => rust_p2p_core::nat::NatType::Symmetric,
    };
    let ipv6: Option<[u8; 16]> = msg.ipv6.and_then(|v| v.as_slice().try_into().ok());

    // Validate all ports fit in u16
    let validate_port = |p: u32| -> anyhow::Result<u16> {
        u16::try_from(p).map_err(|_| anyhow::anyhow!("invalid port number: {}", p))
    };

    let public_udp_ports: Result<Vec<_>, _> = msg
        .public_udp_ports
        .into_iter()
        .map(validate_port)
        .collect();
    let local_udp_ports: Result<Vec<_>, _> =
        msg.local_udp_ports.into_iter().map(validate_port).collect();

    Ok(rust_p2p_core::nat::NatInfo {
        nat_type,
        public_ips: msg.public_ips.into_iter().map(|v| v.into()).collect(),
        public_udp_ports: public_udp_ports?,
        mapping_tcp_addr: vec![],
        mapping_udp_addr: vec![],
        public_port_range: validate_port(msg.public_port_range)?,
        local_ipv4: msg
            .local_ipv4s
            .first()
            .map(|v| (*v).into())
            .unwrap_or(Ipv4Addr::UNSPECIFIED),
        local_ipv4s: msg.local_ipv4s.into_iter().map(|v| v.into()).collect(),
        ipv6: ipv6.map(Ipv6Addr::from),
        local_udp_ports: local_udp_ports?,
        local_tcp_port: validate_port(msg.local_tcp_port)?,
        public_tcp_port: validate_port(msg.public_tcp_port)?,
    })
}
#[derive(Clone, Debug)]
pub struct PunchInfo {
    pub nat_info: rust_p2p_core::nat::NatInfo,
}

impl PunchInfo {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::PunchInfo::decode(buf)?;
        let Some(nat_info) = msg.nat_info else {
            bail!("Punched info decode failed.");
        };
        let nat_info = decode_nat_info(nat_info)?;
        Ok(Self { nat_info })
    }
    pub fn encode(&self) -> BytesMut {
        let message = proto::PunchInfo {
            nat_info: Some(encode_nat_info(&self.nat_info)),
        };
        message.encode_bytes_mut()
    }
}
