//! Deterministic overlay IPv6 addresses. The final four octets are the existing node ID.
use pnet_packet::ipv6::Ipv6Packet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const PREFIX_LEN: u8 = 96;
pub const ROUTE: &str = "fd76:6e74::/96";
pub const PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd76, 0x6e74, 0, 0, 0, 0, 0, 0);

pub fn address(node: Ipv4Addr) -> Ipv6Addr {
    let mut bytes = PREFIX.octets();
    bytes[12..].copy_from_slice(&node.octets());
    Ipv6Addr::from(bytes)
}

pub fn node_id(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let bytes = address.octets();
    if bytes[..12] != PREFIX.octets()[..12] {
        return None;
    }
    let node = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    if node.is_unspecified() || node.is_broadcast() || node.is_multicast() {
        return None;
    }
    Some(node)
}

/// Validate the fixed header and advertised payload length. Jumbograms are not supported.
/// Ethernet padding is accepted and is removed by the L2-to-L3 caller.
pub(crate) fn packet(data: &[u8]) -> Option<Ipv6Packet<'_>> {
    let ip = Ipv6Packet::new(data)?;
    let length = 40 + usize::from(ip.get_payload_length());
    if ip.get_version() != 6 || length > data.len() {
        return None;
    }
    Ipv6Packet::new(&data[..length])
}

/// Locate ICMPv6 through bounded extension headers. Fragmented NDP is never accepted.
pub(crate) fn icmp_offset(data: &[u8]) -> Option<(usize, bool)> {
    let ip = packet(data)?;
    let end = 40 + usize::from(ip.get_payload_length());
    let mut next = data[6];
    let mut offset = 40;
    let mut fragmented = false;
    for _ in 0..16 {
        match next {
            58 if offset < end => return Some((offset, fragmented)),
            0 | 43 | 60 | 51 => {
                let header = data.get(offset..end)?;
                if header.len() < 2 {
                    return None;
                }
                let len = if next == 51 {
                    (usize::from(header[1]) + 2) * 4
                } else {
                    (usize::from(header[1]) + 1) * 8
                };
                if len > header.len() {
                    return None;
                }
                next = header[0];
                offset += len;
            }
            44 => {
                let header = data.get(offset..offset + 8)?;
                if offset + 8 > end {
                    return None;
                }
                // Only the first fragment can contain the ICMP header.
                if header[2] != 0 || header[3] & 0xf8 != 0 {
                    return None;
                }
                fragmented = true;
                next = header[0];
                offset += 8;
            }
            _ => return None,
        }
    }
    None
}

pub(crate) fn is_ndp(data: &[u8]) -> bool {
    icmp_offset(data)
        .is_some_and(|(offset, _)| data.get(offset).is_some_and(|t| (133..=137).contains(t)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_and_validation() {
        let node = Ipv4Addr::new(10, 26, 0, 2);
        assert_eq!(address(node).to_string(), "fd76:6e74::a1a:2");
        assert_eq!(node_id(address(node)), Some(node));
        assert_eq!(node_id("2001:db8::a1a:2".parse().unwrap()), None);
        for node in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert_eq!(node_id(address(node)), None);
        }
        let mut data = [0u8; 40];
        data[0] = 0x60;
        assert!(packet(&data).is_some());
        data[5] = 1;
        assert!(packet(&data).is_none());
        assert!(packet(&data[..39]).is_none());
    }
}
