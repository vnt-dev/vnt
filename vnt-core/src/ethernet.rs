use crate::context::NetworkAddr;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use parking_lot::RwLock;
use pnet_base::MacAddr;
use pnet_packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet_packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::vlan::VlanPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const VLAN_HEADER_LEN: usize = 4;
pub const MAX_VLAN_TAGS: usize = 4;
const MAC_ENTRY_TTL: Duration = Duration::from_secs(300);
const MAC_TABLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_MAC_ENTRIES: usize = 65_536;

#[derive(Debug, Copy, Clone)]
struct MacEntry {
    peer: Ipv4Addr,
    last_seen: Instant,
}

#[derive(Debug)]
struct MacTableInner {
    entries: HashMap<MacAddr, MacEntry>,
    last_cleanup: Instant,
}

impl Default for MacTableInner {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
}

/// Ethernet forwarding database. It maps an inner source MAC address to the
/// authenticated overlay peer from which the frame was received.
#[derive(Debug, Clone, Default)]
pub(crate) struct MacTable {
    inner: Arc<RwLock<MacTableInner>>,
}

impl MacTable {
    pub fn learn_remote(&self, mac: MacAddr, peer: Ipv4Addr) {
        if mac.is_zero() || mac.is_multicast() {
            return;
        }
        let now = Instant::now();
        let mut inner = self.inner.write();
        if now.duration_since(inner.last_cleanup) >= MAC_TABLE_CLEANUP_INTERVAL {
            inner
                .entries
                .retain(|_, entry| now.duration_since(entry.last_seen) < MAC_ENTRY_TTL);
            inner.last_cleanup = now;
        }
        if inner.entries.len() >= MAX_MAC_ENTRIES
            && !inner.entries.contains_key(&mac)
            && let Some(oldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(mac, _)| *mac)
        {
            inner.entries.remove(&oldest);
        }
        inner.entries.insert(
            mac,
            MacEntry {
                peer,
                last_seen: now,
            },
        );
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        let entry = self.inner.read().entries.get(&mac).copied()?;
        if entry.last_seen.elapsed() < MAC_ENTRY_TTL {
            return Some(entry.peer);
        }
        let mut inner = self.inner.write();
        if inner
            .entries
            .get(&mac)
            .is_some_and(|current| current.last_seen == entry.last_seen)
        {
            inner.entries.remove(&mac);
        }
        None
    }

    /// A source MAC read from the local TAP is now local to this tunnel edge,
    /// so discard any stale remote location learned before a MAC move.
    pub fn observe_local_source(&self, mac: MacAddr) {
        if !mac.is_zero() && !mac.is_multicast() {
            self.inner.write().entries.remove(&mac);
        }
    }

    pub fn remove_peer(&self, peer: Ipv4Addr) {
        self.inner
            .write()
            .entries
            .retain(|_, entry| entry.peer != peer);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FrameInfo {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: EtherType,
    pub payload_offset: usize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ArpIpv4 {
    pub operation: ArpOperation,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

pub fn mac_from_ip(ip: Ipv4Addr) -> MacAddr {
    let octets = ip.octets();
    MacAddr::new(0x02, 0x00, octets[0], octets[1], octets[2], octets[3])
}

pub fn parse_frame(frame: &[u8]) -> Option<FrameInfo> {
    let ethernet = EthernetPacket::new(frame)?;
    let destination = ethernet.get_destination();
    let source = ethernet.get_source();
    let mut ethertype = ethernet.get_ethertype();
    let mut payload_offset = ETHERNET_HEADER_LEN;
    // Support stacked VLAN tags. Four tags is already beyond normal Q-in-Q usage
    // and bounds work performed for an untrusted frame.
    for _ in 0..MAX_VLAN_TAGS {
        if !matches!(
            ethertype,
            EtherTypes::Vlan | EtherTypes::PBridge | EtherTypes::QinQ
        ) {
            break;
        }
        let vlan = VlanPacket::new(&frame[payload_offset..])?;
        ethertype = vlan.get_ethertype();
        payload_offset += VLAN_HEADER_LEN;
    }
    Some(FrameInfo {
        destination,
        source,
        ethertype,
        payload_offset,
    })
}

pub fn parse_arp_ipv4(frame: &[u8]) -> Option<ArpIpv4> {
    let info = parse_frame(frame)?;
    if info.ethertype != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(&frame[info.payload_offset..])?;
    if arp.get_hardware_type() != ArpHardwareTypes::Ethernet
        || arp.get_protocol_type() != EtherTypes::Ipv4
        || arp.get_hw_addr_len() != 6
        || arp.get_proto_addr_len() != 4
    {
        return None;
    }
    Some(ArpIpv4 {
        operation: arp.get_operation(),
        sender_mac: arp.get_sender_hw_addr(),
        sender_ip: arp.get_sender_proto_addr(),
        target_mac: arp.get_target_hw_addr(),
        target_ip: arp.get_target_proto_addr(),
    })
}

pub fn build_arp_reply(request: &[u8], own_ip: Ipv4Addr) -> Option<TransmissionBytes> {
    let info = parse_frame(request)?;
    let arp = parse_arp_ipv4(request)?;
    if arp.operation != ArpOperations::Request || arp.target_ip != own_ip {
        return None;
    }
    let frame_len = request
        .len()
        .max(info.payload_offset + ArpPacket::minimum_packet_size());
    let mut bytes = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + frame_len);
    bytes.put(request).ok()?;
    if bytes.len() < frame_len {
        bytes.extend_end(frame_len - bytes.len());
    }
    let own_mac = mac_from_ip(own_ip);
    let mut ethernet = MutableEthernetPacket::new(bytes.as_mut())?;
    ethernet.set_destination(arp.sender_mac);
    ethernet.set_source(own_mac);
    let mut reply = MutableArpPacket::new(&mut bytes[info.payload_offset..])?;
    reply.set_operation(ArpOperations::Reply);
    reply.set_sender_hw_addr(own_mac);
    reply.set_sender_proto_addr(own_ip);
    reply.set_target_hw_addr(arp.sender_mac);
    reply.set_target_proto_addr(arp.sender_ip);
    Some(bytes)
}

pub fn strip_ipv4(mut frame: TransmissionBytes) -> Option<TransmissionBytes> {
    let info = parse_frame(frame.as_ref())?;
    if info.ethertype != EtherTypes::Ipv4 {
        return None;
    }
    frame.advance_head(info.payload_offset).ok()?;
    Some(frame)
}

pub fn wrap_ipv4(
    mut packet: TransmissionBytes,
    src_node: Ipv4Addr,
    net: &NetworkAddr,
) -> Option<TransmissionBytes> {
    let ipv4 = pnet_packet::ipv4::Ipv4Packet::new(packet.as_ref())?;
    let destination_ip = ipv4.get_destination();
    let destination_mac = if destination_ip.is_broadcast() || destination_ip == net.broadcast {
        MacAddr::broadcast()
    } else if destination_ip.is_multicast() {
        let octets = destination_ip.octets();
        MacAddr::new(0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3])
    } else {
        mac_from_ip(net.ip)
    };
    packet.retreat_head(ETHERNET_HEADER_LEN).ok()?;
    let mut ethernet = MutableEthernetPacket::new(packet.as_mut())?;
    ethernet.set_destination(destination_mac);
    ethernet.set_source(mac_from_ip(src_node));
    ethernet.set_ethertype(EtherTypes::Ipv4);
    Some(packet)
}

pub fn is_broadcast_or_multicast(mac: MacAddr) -> bool {
    mac.is_broadcast() || mac.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_mac_is_stable() {
        let ip = Ipv4Addr::new(10, 26, 1, 9);
        assert_eq!(mac_from_ip(ip), MacAddr::new(2, 0, 10, 26, 1, 9));
    }

    #[test]
    fn mac_table_learns_bridge_macs_and_handles_moves() {
        let table = MacTable::default();
        let mac = MacAddr::new(0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x01);
        let second_mac = MacAddr::new(0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x02);
        let first_peer = Ipv4Addr::new(10, 26, 0, 8);
        let second_peer = Ipv4Addr::new(10, 26, 0, 9);

        table.learn_remote(mac, first_peer);
        table.learn_remote(second_mac, first_peer);
        assert_eq!(table.lookup(mac), Some(first_peer));
        assert_eq!(table.lookup(second_mac), Some(first_peer));

        table.learn_remote(mac, second_peer);
        assert_eq!(table.lookup(mac), Some(second_peer));

        table.observe_local_source(mac);
        assert_eq!(table.lookup(mac), None);

        table.remove_peer(first_peer);
        assert_eq!(table.lookup(second_mac), None);
    }

    #[test]
    fn mac_table_ignores_non_unicast_sources() {
        let table = MacTable::default();
        let peer = Ipv4Addr::new(10, 26, 0, 8);

        table.learn_remote(MacAddr::zero(), peer);
        table.learn_remote(MacAddr::broadcast(), peer);

        assert_eq!(table.lookup(MacAddr::zero()), None);
        assert_eq!(table.lookup(MacAddr::broadcast()), None);
    }

    #[test]
    fn parses_vlan_ipv4() {
        let mut frame = vec![0u8; 18 + 20];
        frame[12..14].copy_from_slice(&EtherTypes::Vlan.0.to_be_bytes());
        frame[16..18].copy_from_slice(&EtherTypes::Ipv4.0.to_be_bytes());
        let info = parse_frame(&frame).unwrap();
        assert_eq!(info.ethertype, EtherTypes::Ipv4);
        assert_eq!(info.payload_offset, 18);
        assert!(parse_frame(&[0u8; 13]).is_none());
        let mut truncated_vlan = vec![0u8; 16];
        truncated_vlan[12..14].copy_from_slice(&EtherTypes::Vlan.0.to_be_bytes());
        assert!(parse_frame(&truncated_vlan).is_none());
    }

    #[test]
    fn parses_stacked_vlan_arp_with_pnet_packets() {
        let sender_ip = Ipv4Addr::new(10, 26, 0, 8);
        let target_ip = Ipv4Addr::new(10, 26, 0, 9);
        let sender_mac = mac_from_ip(sender_ip);
        let mut request = vec![0u8; ETHERNET_HEADER_LEN + VLAN_HEADER_LEN * 2 + 28];
        request[0..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&sender_mac.octets());
        request[12..14].copy_from_slice(&EtherTypes::PBridge.0.to_be_bytes());
        request[16..18].copy_from_slice(&EtherTypes::Vlan.0.to_be_bytes());
        request[20..22].copy_from_slice(&EtherTypes::Arp.0.to_be_bytes());
        let arp_offset = ETHERNET_HEADER_LEN + VLAN_HEADER_LEN * 2;
        request[arp_offset..arp_offset + 2]
            .copy_from_slice(&ArpHardwareTypes::Ethernet.0.to_be_bytes());
        request[arp_offset + 2..arp_offset + 4].copy_from_slice(&EtherTypes::Ipv4.0.to_be_bytes());
        request[arp_offset + 4] = 6;
        request[arp_offset + 5] = 4;
        request[arp_offset + 6..arp_offset + 8]
            .copy_from_slice(&ArpOperations::Request.0.to_be_bytes());
        request[arp_offset + 8..arp_offset + 14].copy_from_slice(&sender_mac.octets());
        request[arp_offset + 14..arp_offset + 18].copy_from_slice(&sender_ip.octets());
        request[arp_offset + 24..arp_offset + 28].copy_from_slice(&target_ip.octets());

        let info = parse_frame(&request).unwrap();
        assert_eq!(info.ethertype, EtherTypes::Arp);
        assert_eq!(info.payload_offset, arp_offset);
        let arp = parse_arp_ipv4(&request).unwrap();
        assert_eq!(arp.sender_mac, sender_mac);
        assert_eq!(arp.sender_ip, sender_ip);
        assert_eq!(arp.target_ip, target_ip);
    }

    #[test]
    fn builds_arp_reply_for_node_ip() {
        let sender_ip = Ipv4Addr::new(10, 26, 0, 8);
        let target_ip = Ipv4Addr::new(10, 26, 0, 9);
        let sender_mac = mac_from_ip(sender_ip);
        let mut request = vec![0u8; 42];
        request[0..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&sender_mac.octets());
        request[12..14].copy_from_slice(&EtherTypes::Arp.0.to_be_bytes());
        request[14..16].copy_from_slice(&ArpHardwareTypes::Ethernet.0.to_be_bytes());
        request[16..18].copy_from_slice(&EtherTypes::Ipv4.0.to_be_bytes());
        request[18] = 6;
        request[19] = 4;
        request[20..22].copy_from_slice(&ArpOperations::Request.0.to_be_bytes());
        request[22..28].copy_from_slice(&sender_mac.octets());
        request[28..32].copy_from_slice(&sender_ip.octets());
        request[38..42].copy_from_slice(&target_ip.octets());

        let reply = build_arp_reply(&request, target_ip).unwrap();
        let arp = parse_arp_ipv4(reply.as_ref()).unwrap();
        assert_eq!(arp.operation, ArpOperations::Reply);
        assert_eq!(arp.sender_ip, target_ip);
        assert_eq!(arp.sender_mac, mac_from_ip(target_ip));
        assert_eq!(arp.target_ip, sender_ip);
        assert_eq!(arp.target_mac, sender_mac);
    }

    #[test]
    fn wraps_ipv4_for_tap_and_strips_it_again() {
        let net = NetworkAddr {
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
            ip: Ipv4Addr::new(10, 26, 0, 9),
            prefix_len: 24,
        };
        let src = Ipv4Addr::new(10, 26, 0, 8);
        let mut packet = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + 20);
        packet.put(&[0u8; 20]).unwrap();
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&net.ip.octets());
        let original = packet.as_ref().to_vec();

        let frame = wrap_ipv4(packet, src, &net).unwrap();
        let info = parse_frame(frame.as_ref()).unwrap();
        assert_eq!(info.source, mac_from_ip(src));
        assert_eq!(info.destination, mac_from_ip(net.ip));
        assert_eq!(strip_ipv4(frame).unwrap().as_ref(), original);
    }
}
