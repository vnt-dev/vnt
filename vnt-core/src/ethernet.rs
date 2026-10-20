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

pub fn strip_ip(mut frame: TransmissionBytes) -> Option<TransmissionBytes> {
    let info = parse_frame(frame.as_ref())?;
    if !matches!(info.ethertype, EtherTypes::Ipv4 | EtherTypes::Ipv6) {
        return None;
    }
    frame.advance_head(info.payload_offset).ok()?;
    if info.ethertype == EtherTypes::Ipv6 {
        let ip = crate::virtual_ipv6::packet(frame.as_ref())?;
        let length = 40 + usize::from(ip.get_payload_length());
        // Rebuild only when Ethernet padding is present.
        frame.set_len(length).ok()?;
    }
    Some(frame)
}

pub fn ipv6_multicast_mac(ip: std::net::Ipv6Addr) -> MacAddr {
    let bytes = ip.octets();
    MacAddr::new(0x33, 0x33, bytes[12], bytes[13], bytes[14], bytes[15])
}

pub fn wrap_ipv6(
    mut packet: TransmissionBytes,
    src_node: Ipv4Addr,
    net: &NetworkAddr,
) -> Option<TransmissionBytes> {
    let ip = crate::virtual_ipv6::packet(packet.as_ref())?;
    let dest = ip.get_destination();
    let destination = if dest.is_multicast() {
        ipv6_multicast_mac(dest)
    } else {
        mac_from_ip(net.ip)
    };
    packet.retreat_head(ETHERNET_HEADER_LEN).ok()?;
    let mut frame = MutableEthernetPacket::new(packet.as_mut())?;
    frame.set_destination(destination);
    frame.set_source(mac_from_ip(src_node));
    frame.set_ethertype(EtherTypes::Ipv6);
    Some(packet)
}

/// Reply to a TAP neighbor solicitation for this TUN node, including DAD probes.
pub fn build_ndp_reply(request: &[u8], node: Ipv4Addr) -> Option<TransmissionBytes> {
    use pnet_packet::{
        Packet,
        icmpv6::{Icmpv6Packet, checksum},
    };
    use std::net::Ipv6Addr;
    let frame = parse_frame(request)?;
    if frame.ethertype != EtherTypes::Ipv6 || frame.source.is_multicast() || frame.source.is_zero()
    {
        return None;
    }
    let data = request.get(frame.payload_offset..)?;
    let ip = crate::virtual_ipv6::packet(data)?;
    let (offset, fragmented) = crate::virtual_ipv6::icmp_offset(data)?;
    let end = 40 + usize::from(ip.get_payload_length());
    let ns = data.get(offset..end)?;
    let own = crate::virtual_ipv6::address(node);
    if fragmented
        || ip.get_hop_limit() != 255
        || ns.len() < 24
        || ns[0] != 135
        || ns[1] != 0
        || ns[8..24] != own.octets()
        || ip.get_source().is_multicast()
    {
        return None;
    }
    let icmp = Icmpv6Packet::new(ns)?;
    if checksum(&icmp, &ip.get_source(), &ip.get_destination()) != icmp.get_checksum() {
        return None;
    }
    let dad = ip.get_source().is_unspecified();
    let target_bytes = own.octets();
    let solicited = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(target_bytes[13]),
        u16::from_be_bytes([target_bytes[14], target_bytes[15]]),
    );
    if (dad && ip.get_destination() != solicited)
        || (!dad && ip.get_destination() != solicited && ip.get_destination() != own)
    {
        return None;
    }
    let mut options = &ns[24..];
    while !options.is_empty() {
        if options.len() < 2 || options[1] == 0 {
            return None;
        }
        let length = usize::from(options[1]) * 8;
        if length > options.len() || (options[0] == 1 && (dad || length != 8)) {
            return None;
        }
        options = &options[length..];
    }
    let dest = if dad {
        "ff02::1".parse().ok()?
    } else {
        ip.get_source()
    };
    let mac = mac_from_ip(node);
    let size = frame.payload_offset + 40 + 32;
    let mut reply = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + size);
    reply.put(&vec![0; size]).ok()?;
    reply[..frame.payload_offset].copy_from_slice(&request[..frame.payload_offset]);
    let mut ethernet = MutableEthernetPacket::new(reply.as_mut())?;
    ethernet.set_source(mac);
    ethernet.set_destination(if dad {
        ipv6_multicast_mac(dest)
    } else {
        frame.source
    });
    let mut ipv6 = pnet_packet::ipv6::MutableIpv6Packet::new(&mut reply[frame.payload_offset..])?;
    ipv6.set_version(6);
    ipv6.set_payload_length(32);
    ipv6.set_next_header(pnet_packet::ip::IpNextHeaderProtocols::Icmpv6);
    ipv6.set_hop_limit(255);
    ipv6.set_source(own);
    ipv6.set_destination(dest);
    let start = frame.payload_offset + 40;
    reply[start] = 136;
    reply[start + 4] = if dad { 0x20 } else { 0x60 }; // Override, plus Solicited for normal NS.
    reply[start + 8..start + 24].copy_from_slice(&own.octets());
    reply[start + 24] = 2; // Target link-layer address.
    reply[start + 25] = 1;
    reply[start + 26..start + 32].copy_from_slice(&mac.octets());
    let na = Icmpv6Packet::new(&reply[start..])?;
    let sum = checksum(&na, &own, &dest);
    reply[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
    debug_assert_eq!(Icmpv6Packet::new(&reply[start..])?.packet().len(), 32);
    Some(reply)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn ipv6_ns(node: Ipv4Addr, dad: bool, vlan: bool) -> Vec<u8> {
        use pnet_packet::icmpv6::{Icmpv6Packet, checksum};
        let target = crate::virtual_ipv6::address(node);
        let bytes = target.octets();
        let dest = std::net::Ipv6Addr::new(
            0xff02,
            0,
            0,
            0,
            0,
            1,
            0xff00 | u16::from(bytes[13]),
            u16::from_be_bytes([bytes[14], bytes[15]]),
        );
        let source = if dad {
            std::net::Ipv6Addr::UNSPECIFIED
        } else {
            "fe80::1234".parse().unwrap()
        };
        let offset = if vlan { 18 } else { 14 };
        let mut data = vec![0u8; offset + 40 + 24];
        data[..6].copy_from_slice(&ipv6_multicast_mac(dest).octets());
        data[6..12].copy_from_slice(&[2, 0, 10, 26, 0, 8]);
        if vlan {
            data[12..18].copy_from_slice(&[0x81, 0, 0, 42, 0x86, 0xdd]);
        } else {
            data[12..14].copy_from_slice(&[0x86, 0xdd]);
        }
        data[offset] = 0x60;
        data[offset + 5] = 24;
        data[offset + 6] = 58;
        data[offset + 7] = 255;
        data[offset + 8..offset + 24].copy_from_slice(&source.octets());
        data[offset + 24..offset + 40].copy_from_slice(&dest.octets());
        data[offset + 40] = 135;
        data[offset + 48..offset + 64].copy_from_slice(&target.octets());
        let sum = checksum(
            &Icmpv6Packet::new(&data[offset + 40..]).unwrap(),
            &source,
            &dest,
        );
        data[offset + 42..offset + 44].copy_from_slice(&sum.to_be_bytes());
        data
    }

    #[test]
    fn ipv6_neighbor_resolution_and_dad_preserve_vlan_and_checksum() {
        use pnet_packet::icmpv6::{Icmpv6Packet, checksum};
        let node = Ipv4Addr::new(10, 26, 0, 2);
        for dad in [false, true] {
            for vlan in [false, true] {
                let request = ipv6_ns(node, dad, vlan);
                let reply = build_ndp_reply(&request, node).unwrap();
                let frame = parse_frame(&reply).unwrap();
                assert_eq!(frame.payload_offset, if vlan { 18 } else { 14 });
                assert_eq!(
                    &reply[12..frame.payload_offset],
                    &request[12..frame.payload_offset]
                );
                assert_eq!(frame.source, mac_from_ip(node));
                let ip = crate::virtual_ipv6::packet(&reply[frame.payload_offset..]).unwrap();
                assert_eq!(ip.get_hop_limit(), 255);
                let na = Icmpv6Packet::new(&reply[frame.payload_offset + 40..]).unwrap();
                assert_eq!(na.get_icmpv6_type().0, 136);
                assert_eq!(
                    checksum(&na, &ip.get_source(), &ip.get_destination()),
                    na.get_checksum()
                );
                assert_eq!(
                    reply[frame.payload_offset + 44],
                    if dad { 0x20 } else { 0x60 }
                );
                assert_eq!(
                    ip.get_destination(),
                    if dad {
                        "ff02::1".parse::<std::net::Ipv6Addr>().unwrap()
                    } else {
                        "fe80::1234".parse::<std::net::Ipv6Addr>().unwrap()
                    }
                );
            }
        }
    }

    #[test]
    fn ipv6_ndp_rejects_malformed_and_other_targets() {
        let node = Ipv4Addr::new(10, 26, 0, 2);
        let request = ipv6_ns(node, false, false);
        assert!(build_ndp_reply(&request, Ipv4Addr::new(10, 26, 0, 3)).is_none());
        for (offset, value) in [(21, 64), (54, 134), (55, 1), (56, 0xff)] {
            let mut bad = request.clone();
            bad[offset] = value;
            assert!(build_ndp_reply(&bad, node).is_none());
        }
        for len in 0..request.len() {
            assert!(build_ndp_reply(&request[..len], node).is_none());
        }
        let mut fragment = request.clone();
        fragment[20] = 44;
        fragment.splice(54..54, [58, 0, 0, 1, 0, 0, 0, 1]);
        fragment[19] = 32;
        assert!(build_ndp_reply(&fragment, node).is_none());
    }

    #[test]
    fn ipv6_ndp_unicast_probe_and_option_validation() {
        use pnet_packet::icmpv6::{Icmpv6Packet, checksum};
        fn update_checksum(frame: &mut [u8]) {
            frame[56..58].fill(0);
            let ip = crate::virtual_ipv6::packet(&frame[14..]).unwrap();
            let sum = checksum(
                &Icmpv6Packet::new(&frame[54..]).unwrap(),
                &ip.get_source(),
                &ip.get_destination(),
            );
            frame[56..58].copy_from_slice(&sum.to_be_bytes());
        }
        let node = Ipv4Addr::new(10, 26, 0, 2);
        let mut request = ipv6_ns(node, false, false);
        request[38..54].copy_from_slice(&crate::virtual_ipv6::address(node).octets());
        update_checksum(&mut request);
        assert!(build_ndp_reply(&request, node).is_some());
        request.extend_from_slice(&[1, 1, 2, 0, 10, 26, 0, 8]);
        request[19] = 32;
        update_checksum(&mut request);
        assert!(build_ndp_reply(&request, node).is_some());
        request[79] = 0;
        update_checksum(&mut request);
        assert!(build_ndp_reply(&request, node).is_none());
        request[79] = 2;
        update_checksum(&mut request);
        assert!(build_ndp_reply(&request, node).is_none());
        let mut dad = ipv6_ns(node, true, false);
        dad.extend_from_slice(&[1, 1, 2, 0, 10, 26, 0, 8]);
        dad[19] = 32;
        update_checksum(&mut dad);
        assert!(build_ndp_reply(&dad, node).is_none());
    }

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
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
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
