use crate::context::NetworkAddr;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use pnet_packet::arp::{ArpHardwareTypes, ArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::vlan::VlanPacket;
use std::net::Ipv4Addr;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const VLAN_HEADER_LEN: usize = 4;
pub const MAX_VLAN_TAGS: usize = 4;
pub const MAX_ETHERNET_HEADER_LEN: usize = ETHERNET_HEADER_LEN + VLAN_HEADER_LEN * MAX_VLAN_TAGS;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_VLAN_9100: u16 = 0x9100;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FrameInfo {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub payload_offset: usize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ArpIpv4 {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

pub fn mac_from_ip(ip: Ipv4Addr) -> [u8; 6] {
    let octets = ip.octets();
    [0x02, 0x00, octets[0], octets[1], octets[2], octets[3]]
}

pub fn ip_from_mac(mac: [u8; 6]) -> Option<Ipv4Addr> {
    (mac[0] == 0x02 && mac[1] == 0x00).then(|| Ipv4Addr::new(mac[2], mac[3], mac[4], mac[5]))
}

pub fn parse_frame(frame: &[u8]) -> Option<FrameInfo> {
    let ethernet = EthernetPacket::new(frame)?;
    let destination = ethernet.get_destination().octets();
    let source = ethernet.get_source().octets();
    let mut ethertype = ethernet.get_ethertype();
    let mut payload_offset = ETHERNET_HEADER_LEN;
    // Support stacked VLAN tags. Four tags is already beyond normal Q-in-Q usage
    // and bounds work performed for an untrusted frame.
    for _ in 0..MAX_VLAN_TAGS {
        if !matches!(
            ethertype.0,
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_9100
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
        ethertype: ethertype.0,
        payload_offset,
    })
}

pub fn parse_arp_ipv4(frame: &[u8]) -> Option<ArpIpv4> {
    let info = parse_frame(frame)?;
    if info.ethertype != EtherTypes::Arp.0 {
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
        operation: arp.get_operation().0,
        sender_mac: arp.get_sender_hw_addr().octets(),
        sender_ip: arp.get_sender_proto_addr(),
        target_mac: arp.get_target_hw_addr().octets(),
        target_ip: arp.get_target_proto_addr(),
    })
}

pub fn build_arp_reply(request: &[u8], own_ip: Ipv4Addr) -> Option<TransmissionBytes> {
    let info = parse_frame(request)?;
    let arp = parse_arp_ipv4(request)?;
    if arp.operation != 1 || arp.target_ip != own_ip {
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
    bytes[0..6].copy_from_slice(&arp.sender_mac);
    bytes[6..12].copy_from_slice(&own_mac);
    let payload = info.payload_offset;
    bytes[payload + 6..payload + 8].copy_from_slice(&2u16.to_be_bytes());
    bytes[payload + 8..payload + 14].copy_from_slice(&own_mac);
    bytes[payload + 14..payload + 18].copy_from_slice(&own_ip.octets());
    bytes[payload + 18..payload + 24].copy_from_slice(&arp.sender_mac);
    bytes[payload + 24..payload + 28].copy_from_slice(&arp.sender_ip.octets());
    Some(bytes)
}

pub fn strip_ipv4(mut frame: TransmissionBytes) -> Option<TransmissionBytes> {
    let info = parse_frame(frame.as_ref())?;
    if info.ethertype != ETHERTYPE_IPV4 {
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
        [0xff; 6]
    } else if destination_ip.is_multicast() {
        let octets = destination_ip.octets();
        [0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3]]
    } else {
        mac_from_ip(net.ip)
    };
    packet.retreat_head(ETHERNET_HEADER_LEN).ok()?;
    packet[0..6].copy_from_slice(&destination_mac);
    packet[6..12].copy_from_slice(&mac_from_ip(src_node));
    packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    Some(packet)
}

pub fn is_broadcast_or_multicast(mac: [u8; 6]) -> bool {
    mac == [0xff; 6] || mac[0] & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_mac_round_trip() {
        let ip = Ipv4Addr::new(10, 26, 1, 9);
        assert_eq!(mac_from_ip(ip), [2, 0, 10, 26, 1, 9]);
        assert_eq!(ip_from_mac(mac_from_ip(ip)), Some(ip));
        assert_eq!(ip_from_mac([0; 6]), None);
    }

    #[test]
    fn parses_vlan_ipv4() {
        let mut frame = vec![0u8; 18 + 20];
        frame[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let info = parse_frame(&frame).unwrap();
        assert_eq!(info.ethertype, ETHERTYPE_IPV4);
        assert_eq!(info.payload_offset, 18);
        assert!(parse_frame(&[0u8; 13]).is_none());
        let mut truncated_vlan = vec![0u8; 16];
        truncated_vlan[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        assert!(parse_frame(&truncated_vlan).is_none());
    }

    #[test]
    fn parses_stacked_vlan_arp_with_pnet_packets() {
        let sender_ip = Ipv4Addr::new(10, 26, 0, 8);
        let target_ip = Ipv4Addr::new(10, 26, 0, 9);
        let sender_mac = mac_from_ip(sender_ip);
        let mut request = vec![0u8; ETHERNET_HEADER_LEN + VLAN_HEADER_LEN * 2 + 28];
        request[0..6].copy_from_slice(&[0xff; 6]);
        request[6..12].copy_from_slice(&sender_mac);
        request[12..14].copy_from_slice(&ETHERTYPE_QINQ.to_be_bytes());
        request[16..18].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        request[20..22].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        let arp_offset = ETHERNET_HEADER_LEN + VLAN_HEADER_LEN * 2;
        request[arp_offset..arp_offset + 2].copy_from_slice(&1u16.to_be_bytes());
        request[arp_offset + 2..arp_offset + 4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        request[arp_offset + 4] = 6;
        request[arp_offset + 5] = 4;
        request[arp_offset + 6..arp_offset + 8].copy_from_slice(&1u16.to_be_bytes());
        request[arp_offset + 8..arp_offset + 14].copy_from_slice(&sender_mac);
        request[arp_offset + 14..arp_offset + 18].copy_from_slice(&sender_ip.octets());
        request[arp_offset + 24..arp_offset + 28].copy_from_slice(&target_ip.octets());

        let info = parse_frame(&request).unwrap();
        assert_eq!(info.ethertype, ETHERTYPE_ARP);
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
        request[6..12].copy_from_slice(&sender_mac);
        request[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        request[14..16].copy_from_slice(&1u16.to_be_bytes());
        request[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        request[18] = 6;
        request[19] = 4;
        request[20..22].copy_from_slice(&1u16.to_be_bytes());
        request[22..28].copy_from_slice(&sender_mac);
        request[28..32].copy_from_slice(&sender_ip.octets());
        request[38..42].copy_from_slice(&target_ip.octets());

        let reply = build_arp_reply(&request, target_ip).unwrap();
        let arp = parse_arp_ipv4(reply.as_ref()).unwrap();
        assert_eq!(arp.operation, 2);
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
