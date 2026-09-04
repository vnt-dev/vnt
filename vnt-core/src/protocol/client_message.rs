mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.client.rs"));
}

use anyhow::bail;
use bytes::BytesMut;
use prost::Message;
use rustp2p_core::punch::{PunchPolicy, PunchPolicySet};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::ProtoToBytesMut;
pub use proto::*;

pub fn encode_nat_info(nat_info: &rustp2p_core::nat::NatInfo) -> proto::NatInfo {
    let nat_type = match nat_info.nat_type {
        rustp2p_core::nat::NatType::Cone => proto::NatType::Cone,
        rustp2p_core::nat::NatType::Symmetric => proto::NatType::Symmetric,
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
pub fn decode_nat_info(msg: proto::NatInfo) -> anyhow::Result<rustp2p_core::nat::NatInfo> {
    let nat_type = match msg.nat_type() {
        proto::NatType::Cone => rustp2p_core::nat::NatType::Cone,
        proto::NatType::Symmetric => rustp2p_core::nat::NatType::Symmetric,
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

    Ok(rustp2p_core::nat::NatInfo {
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
        stun_mapped_ports: vec![],
    })
}
#[derive(Clone, Debug)]
pub struct PunchInfo {
    pub nat_info: rustp2p_core::nat::NatInfo,
    pub punch_model: PunchPolicySet,
}

impl PunchInfo {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::PunchInfo::decode(buf)?;
        let Some(nat_info) = msg.nat_info else {
            bail!("Punched info decode failed.");
        };
        let nat_info = decode_nat_info(nat_info)?;
        let punch_model = decode_punch_model(msg.punch_model);
        Ok(Self {
            nat_info,
            punch_model,
        })
    }
    pub fn encode(&self) -> BytesMut {
        let message = proto::PunchInfo {
            nat_info: Some(encode_nat_info(&self.nat_info)),
            punch_model: encode_punch_model(&self.punch_model),
        };
        message.encode_bytes_mut()
    }
}

const IPV4_TCP: u32 = 1 << 0;
const IPV4_UDP: u32 = 1 << 1;
const IPV6_TCP: u32 = 1 << 2;
const IPV6_UDP: u32 = 1 << 3;

fn encode_punch_model(model: &PunchPolicySet) -> u32 {
    let mut bits = 0;
    for (policy, bit) in [
        (PunchPolicy::IPv4Tcp, IPV4_TCP),
        (PunchPolicy::IPv4Udp, IPV4_UDP),
        (PunchPolicy::IPv6Tcp, IPV6_TCP),
        (PunchPolicy::IPv6Udp, IPV6_UDP),
    ] {
        if model.is_match(policy) {
            bits |= bit;
        }
    }
    bits
}

fn decode_punch_model(bits: u32) -> PunchPolicySet {
    if bits == 0 {
        return PunchPolicySet::all();
    }
    let mut model = PunchPolicySet::empty();
    for (policy, bit) in [
        (PunchPolicy::IPv4Tcp, IPV4_TCP),
        (PunchPolicy::IPv4Udp, IPV4_UDP),
        (PunchPolicy::IPv6Tcp, IPV6_TCP),
        (PunchPolicy::IPv6Udp, IPV6_UDP),
    ] {
        if bits & bit != 0 {
            model.or(policy);
        }
    }
    model
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_punch_info(punch_model: u32) -> Vec<u8> {
        proto::PunchInfo {
            nat_info: Some(proto::NatInfo {
                nat_type: proto::NatType::Cone.into(),
                public_ips: Vec::new(),
                public_udp_ports: Vec::new(),
                public_port_range: 0,
                local_ipv4s: Vec::new(),
                ipv6: None,
                local_udp_ports: Vec::new(),
                local_tcp_port: 0,
                public_tcp_port: 0,
            }),
            punch_model,
        }
        .encode_to_vec()
    }

    #[test]
    fn punch_model_bits_round_trip() {
        for bits in 1..=(IPV4_TCP | IPV4_UDP | IPV6_TCP | IPV6_UDP) {
            let decoded = PunchInfo::from_slice(&encoded_punch_info(bits)).unwrap();
            assert_eq!(encode_punch_model(&decoded.punch_model), bits);

            let encoded = decoded.encode();
            let wire = proto::PunchInfo::decode(encoded.as_ref()).unwrap();
            assert_eq!(wire.punch_model, bits);
        }
    }

    #[test]
    fn legacy_zero_means_all_and_unknown_bits_do_not_open_modes() {
        let legacy = PunchInfo::from_slice(&encoded_punch_info(0))
            .unwrap()
            .punch_model;
        for policy in [
            PunchPolicy::IPv4Tcp,
            PunchPolicy::IPv4Udp,
            PunchPolicy::IPv6Tcp,
            PunchPolicy::IPv6Udp,
        ] {
            assert!(legacy.is_match(policy));
        }

        let unknown_only = PunchInfo::from_slice(&encoded_punch_info(1 << 20))
            .unwrap()
            .punch_model;
        for policy in [
            PunchPolicy::IPv4Tcp,
            PunchPolicy::IPv4Udp,
            PunchPolicy::IPv6Tcp,
            PunchPolicy::IPv6Udp,
        ] {
            assert!(!unknown_only.is_match(policy));
        }
    }
}
