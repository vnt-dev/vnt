mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.client.rs"));
}

use anyhow::bail;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prost::Message;
use ring::digest::{SHA256, digest};
use rustp2p_core::punch::{PunchPolicy, PunchPolicySet};
use std::net::{Ipv4Addr, Ipv6Addr};
use subtle::ConstantTimeEq;

use crate::protocol::ProtoToBytesMut;
pub use proto::*;

pub const NETWORK_CODE_HASH_LEN: usize = 16;
const NETWORK_CODE_HASH_DOMAIN: &[u8] = b"VNT-NETWORK-CODE-V1\0";

/// Returns the compact, domain-separated network identifier used only by the
/// UDP punch handshake. Full identity exchange happens after the route exists.
pub fn network_code_hash(network_code: &str) -> [u8; NETWORK_CODE_HASH_LEN] {
    let mut input = Vec::with_capacity(NETWORK_CODE_HASH_DOMAIN.len() + network_code.len());
    input.extend_from_slice(NETWORK_CODE_HASH_DOMAIN);
    input.extend_from_slice(network_code.as_bytes());
    let value = digest(&SHA256, &input);
    let mut output = [0; NETWORK_CODE_HASH_LEN];
    output.copy_from_slice(&value.as_ref()[..NETWORK_CODE_HASH_LEN]);
    output
}

pub fn network_code_hash_matches(network_code: &str, candidate: &[u8]) -> bool {
    candidate.len() == NETWORK_CODE_HASH_LEN
        && network_code_hash(network_code)
            .as_slice()
            .ct_eq(candidate)
            .into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalNodeIdentity {
    pub ip: Ipv4Addr,
    pub name: String,
    pub version: String,
    pub network_code: String,
    pub advertised_subnets: Vec<Ipv4Net>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeIdentityTemplate {
    pub name: String,
    pub version: String,
    pub network_code: String,
    pub advertised_subnets: Vec<Ipv4Net>,
}

impl NodeIdentityTemplate {
    pub fn with_ip(&self, ip: Ipv4Addr) -> LocalNodeIdentity {
        LocalNodeIdentity {
            ip,
            name: self.name.clone(),
            version: self.version.clone(),
            network_code: self.network_code.clone(),
            advertised_subnets: self.advertised_subnets.clone(),
        }
    }
}

impl LocalNodeIdentity {
    fn to_proto(&self) -> proto::NodeIdentity {
        proto::NodeIdentity {
            ip: self.ip.into(),
            name: self.name.clone(),
            version: self.version.clone(),
            network_code: self.network_code.clone(),
            advertised_subnets: self
                .advertised_subnets
                .iter()
                .map(|net| proto::NodeSubnet {
                    network: net.network().into(),
                    prefix_len: net.prefix_len().into(),
                })
                .collect(),
        }
    }

    fn from_proto(value: proto::NodeIdentity) -> anyhow::Result<Self> {
        let ip = Ipv4Addr::from(value.ip);
        if ip.is_unspecified() || ip.is_broadcast() {
            bail!("invalid node identity ip: {ip}")
        }
        if value.name.len() > crate::context::config::MAX_NAME_LEN
            || value.version.len() > crate::context::config::MAX_VERSION_LEN
            || value.network_code.len() > crate::context::config::MAX_NETWORK_CODE_LEN
        {
            bail!("node identity field exceeds the configured size limit")
        }
        if value.advertised_subnets.len() > 256 {
            bail!("node identity advertises too many subnets")
        }
        let mut advertised_subnets = Vec::with_capacity(value.advertised_subnets.len());
        for subnet in value.advertised_subnets {
            let prefix_len = u8::try_from(subnet.prefix_len)?;
            let net = Ipv4Net::new(Ipv4Addr::from(subnet.network), prefix_len)?;
            if net.network() != Ipv4Addr::from(subnet.network) {
                bail!("non-canonical advertised subnet: {net}")
            }
            advertised_subnets.push(net);
        }
        Ok(Self {
            ip,
            name: value.name,
            version: value.version,
            network_code: value.network_code,
            advertised_subnets,
        })
    }

    fn to_public_proto(&self) -> proto::PublicNodeIdentity {
        proto::PublicNodeIdentity {
            name: self.name.clone(),
            version: self.version.clone(),
            advertised_subnets: self
                .advertised_subnets
                .iter()
                .map(|net| proto::NodeSubnet {
                    network: net.network().into(),
                    prefix_len: net.prefix_len().into(),
                })
                .collect(),
        }
    }

    fn from_public_proto(value: proto::PublicNodeIdentity, ip: Ipv4Addr) -> anyhow::Result<Self> {
        if ip.is_unspecified() || ip.is_broadcast() {
            bail!("invalid node identity ip: {ip}")
        }
        if value.name.len() > crate::context::config::MAX_NAME_LEN
            || value.version.len() > crate::context::config::MAX_VERSION_LEN
        {
            bail!("node identity field exceeds the configured size limit")
        }
        if value.advertised_subnets.len() > 256 {
            bail!("node identity advertises too many subnets")
        }
        let mut advertised_subnets = Vec::with_capacity(value.advertised_subnets.len());
        for subnet in value.advertised_subnets {
            let prefix_len = u8::try_from(subnet.prefix_len)?;
            let net = Ipv4Net::new(Ipv4Addr::from(subnet.network), prefix_len)?;
            if net.network() != Ipv4Addr::from(subnet.network) {
                bail!("non-canonical advertised subnet: {net}")
            }
            advertised_subnets.push(net);
        }
        Ok(Self {
            ip,
            name: value.name,
            version: value.version,
            network_code: String::new(),
            advertised_subnets,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerHandshake {
    pub identity: LocalNodeIdentity,
    pub request_id: u64,
}

impl PeerHandshake {
    pub fn encode(&self) -> BytesMut {
        proto::PeerHandshake {
            identity: Some(self.identity.to_proto()),
            request_id: self.request_id,
        }
        .encode_bytes_mut()
    }

    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let message = proto::PeerHandshake::decode(buf)?;
        let identity = message
            .identity
            .ok_or_else(|| anyhow::anyhow!("missing node identity"))?;
        Ok(Self {
            identity: LocalNodeIdentity::from_proto(identity)?,
            request_id: message.request_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeDiscovery {
    pub identity: LocalNodeIdentity,
    pub request_id: u64,
}

impl NodeDiscovery {
    pub fn encode(&self) -> BytesMut {
        proto::NodeDiscovery {
            identity: Some(self.identity.to_public_proto()),
            request_id: self.request_id,
        }
        .encode_bytes_mut()
    }

    pub fn from_slice(buf: &[u8], source: Ipv4Addr) -> anyhow::Result<Self> {
        let message = proto::NodeDiscovery::decode(buf)?;
        let identity = message
            .identity
            .ok_or_else(|| anyhow::anyhow!("missing node identity"))?;
        Ok(Self {
            identity: LocalNodeIdentity::from_public_proto(identity, source)?,
            request_id: message.request_id,
        })
    }
}

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

    #[test]
    fn node_identity_round_trip_excludes_device_id_by_design() {
        let handshake = PeerHandshake {
            identity: LocalNodeIdentity {
                ip: "10.26.0.2".parse().unwrap(),
                name: "node-a".to_string(),
                version: "2.0.8".to_string(),
                network_code: "mesh-a".to_string(),
                advertised_subnets: vec!["192.168.10.0/24".parse().unwrap()],
            },
            request_id: 42,
        };
        let decoded = PeerHandshake::from_slice(&handshake.encode()).unwrap();
        assert_eq!(decoded, handshake);
    }

    #[test]
    fn node_discovery_wire_identity_omits_source_ip_and_network_code() {
        let discovery = NodeDiscovery {
            identity: LocalNodeIdentity {
                ip: "10.26.0.2".parse().unwrap(),
                name: "node-a".to_string(),
                version: "2.0.8".to_string(),
                network_code: "must-not-be-broadcast".to_string(),
                advertised_subnets: vec!["192.168.10.0/24".parse().unwrap()],
            },
            request_id: 43,
        };
        let encoded = discovery.encode();
        assert!(
            !encoded
                .windows("must-not-be-broadcast".len())
                .any(|window| window == b"must-not-be-broadcast")
        );

        let wire = proto::NodeDiscovery::decode(encoded.as_ref()).unwrap();
        let public = wire.identity.unwrap();
        assert_eq!(public.name, "node-a");
        assert_eq!(public.version, "2.0.8");

        let source = Ipv4Addr::new(10, 26, 0, 2);
        let decoded = NodeDiscovery::from_slice(encoded.as_ref(), source).unwrap();
        assert_eq!(decoded.identity.ip, source);
        assert!(decoded.identity.network_code.is_empty());
        assert_eq!(
            decoded.identity.advertised_subnets,
            discovery.identity.advertised_subnets
        );
    }

    #[test]
    fn node_identity_rejects_oversized_remote_metadata() {
        let encoded = proto::NodeIdentity {
            ip: Ipv4Addr::new(10, 26, 0, 2).into(),
            name: "x".repeat(crate::context::config::MAX_NAME_LEN + 1),
            version: "2".to_string(),
            network_code: "mesh".to_string(),
            advertised_subnets: Vec::new(),
        };
        assert!(LocalNodeIdentity::from_proto(encoded).is_err());
    }

    #[test]
    fn network_code_hash_is_stable_domain_separated_and_fixed_size() {
        let hash = network_code_hash("mesh-a");
        assert_eq!(hash.len(), NETWORK_CODE_HASH_LEN);
        assert_eq!(hash, network_code_hash("mesh-a"));
        assert_ne!(hash, network_code_hash("mesh-b"));

        let plain = digest(&SHA256, b"mesh-a");
        assert_ne!(hash.as_slice(), &plain.as_ref()[..NETWORK_CODE_HASH_LEN]);
        assert!(network_code_hash_matches("mesh-a", &hash));
        assert!(!network_code_hash_matches("mesh-b", &hash));
        assert!(!network_code_hash_matches("mesh-a", &hash[..8]));
    }

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
