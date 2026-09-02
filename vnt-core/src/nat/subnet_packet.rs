use anyhow::{Context, bail};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::protocol::transmission::TransmissionBytes;

const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DATAGRAMS_PER_DIRECTION: usize = 128;
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Direction {
    Forward,
    Reverse,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FragmentKey {
    direction: Direction,
    peer: Ipv4Addr,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
}

struct FragmentPart {
    data: TransmissionBytes,
    ip_offset: usize,
    total_len: usize,
    payload_offset: usize,
    payload_len: usize,
    fragment_offset: usize,
}

struct FragmentGroup {
    created: Instant,
    final_payload_len: Option<usize>,
    parts: Vec<FragmentPart>,
}

#[derive(Default)]
struct FragmentCache {
    groups: HashMap<FragmentKey, FragmentGroup>,
}

#[derive(Clone, Default)]
pub(crate) struct SubnetPacketMapper {
    fragments: Arc<Mutex<FragmentCache>>,
}

impl SubnetPacketMapper {
    pub fn map_destination(
        &self,
        peer: Ipv4Addr,
        data: TransmissionBytes,
        ip_offset: usize,
        mapped: Ipv4Addr,
        actual: Ipv4Addr,
    ) -> anyhow::Result<Vec<TransmissionBytes>> {
        self.map_packet(Direction::Forward, peer, data, ip_offset, mapped, actual)
    }

    pub fn map_source(
        &self,
        peer: Ipv4Addr,
        data: TransmissionBytes,
        ip_offset: usize,
        actual: Ipv4Addr,
        mapped: Ipv4Addr,
    ) -> anyhow::Result<Vec<TransmissionBytes>> {
        self.map_packet(Direction::Reverse, peer, data, ip_offset, actual, mapped)
    }

    fn map_packet(
        &self,
        direction: Direction,
        peer: Ipv4Addr,
        mut data: TransmissionBytes,
        ip_offset: usize,
        old: Ipv4Addr,
        new: Ipv4Addr,
    ) -> anyhow::Result<Vec<TransmissionBytes>> {
        let meta = parse_ipv4(&data, ip_offset)?;
        let address = match direction {
            Direction::Forward => meta.destination,
            Direction::Reverse => meta.source,
        };
        if address != old {
            bail!(
                "subnet mapping address changed while processing packet: expected {old}, got {address}"
            );
        }
        if !meta.fragmented() {
            rewrite_complete_ipv4(
                &mut data[ip_offset..ip_offset + meta.total_len],
                direction,
                old,
                new,
            )?;
            return Ok(vec![data]);
        }

        let key = FragmentKey {
            direction,
            peer,
            source: meta.source,
            destination: meta.destination,
            protocol: meta.protocol,
            identification: meta.identification,
        };
        let mut cache = self.fragments.lock();
        let now = Instant::now();
        cache
            .groups
            .retain(|_, group| now.duration_since(group.created) < FRAGMENT_TIMEOUT);
        let direction_count = cache
            .groups
            .keys()
            .filter(|candidate| candidate.direction == direction)
            .count();
        if !cache.groups.contains_key(&key) && direction_count >= MAX_DATAGRAMS_PER_DIRECTION {
            bail!("subnet mapping fragment cache is full");
        }

        let fragment_offset = meta.fragment_offset as usize * 8;
        let payload_len = meta.total_len - meta.header_len;
        if payload_len == 0 {
            bail!("empty IPv4 fragment payload");
        }
        if meta.more_fragments && payload_len % 8 != 0 {
            bail!("non-final IPv4 fragment payload is not a multiple of 8 bytes");
        }
        let payload_end = fragment_offset
            .checked_add(payload_len)
            .context("IPv4 fragment offset overflow")?;
        if payload_end > u16::MAX as usize - meta.header_len {
            bail!("reassembled IPv4 datagram exceeds the IPv4 size limit");
        }

        let group = cache.groups.entry(key).or_insert_with(|| FragmentGroup {
            created: now,
            final_payload_len: None,
            parts: Vec::new(),
        });
        for part in &group.parts {
            let part_end = part.fragment_offset + part.payload_len;
            let overlaps = fragment_offset < part_end && part.fragment_offset < payload_end;
            if !overlaps {
                continue;
            }
            let duplicate = fragment_offset == part.fragment_offset
                && payload_len == part.payload_len
                && meta.total_len == part.total_len
                && data[ip_offset..ip_offset + meta.total_len]
                    == part.data[part.ip_offset..part.ip_offset + part.total_len];
            if duplicate {
                return Ok(Vec::new());
            }
            cache.groups.remove(&key);
            bail!("conflicting overlapping IPv4 fragments in mapped datagram");
        }
        if group.parts.len() >= MAX_FRAGMENTS_PER_DATAGRAM {
            cache.groups.remove(&key);
            bail!("too many IPv4 fragments for one mapped datagram");
        }
        if group
            .final_payload_len
            .is_some_and(|final_len| payload_end > final_len)
        {
            cache.groups.remove(&key);
            bail!("IPv4 fragment extends beyond the final mapped datagram length");
        }
        if !meta.more_fragments {
            if group
                .final_payload_len
                .is_some_and(|length| length != payload_end)
            {
                cache.groups.remove(&key);
                bail!("mapped IPv4 datagram has inconsistent final fragments");
            }
            if group
                .parts
                .iter()
                .any(|part| part.fragment_offset + part.payload_len > payload_end)
            {
                cache.groups.remove(&key);
                bail!("final IPv4 fragment is shorter than previously received fragments");
            }
            group.final_payload_len = Some(payload_end);
        }
        group.parts.push(FragmentPart {
            data,
            ip_offset,
            total_len: meta.total_len,
            payload_offset: ip_offset + meta.header_len,
            payload_len,
            fragment_offset,
        });
        group.parts.sort_by_key(|part| part.fragment_offset);

        let Some(final_payload_len) = group.final_payload_len else {
            return Ok(Vec::new());
        };
        let mut cursor = 0;
        for part in &group.parts {
            if part.fragment_offset != cursor {
                return Ok(Vec::new());
            }
            cursor += part.payload_len;
        }
        if cursor != final_payload_len {
            return Ok(Vec::new());
        }

        let mut group = cache.groups.remove(&key).expect("fragment group exists");
        drop(cache);
        let first = group
            .parts
            .iter()
            .find(|part| part.fragment_offset == 0)
            .context("mapped fragmented datagram has no first fragment")?;
        let first_meta = parse_ipv4(&first.data, first.ip_offset)?;
        let mut reassembled = vec![0u8; first_meta.header_len + final_payload_len];
        reassembled[..first_meta.header_len]
            .copy_from_slice(&first.data[first.ip_offset..first.ip_offset + first_meta.header_len]);
        let reassembled_len = reassembled.len() as u16;
        reassembled[2..4].copy_from_slice(&reassembled_len.to_be_bytes());
        let flags = u16::from_be_bytes([reassembled[6], reassembled[7]]) & 0x4000;
        reassembled[6..8].copy_from_slice(&flags.to_be_bytes());
        for part in &group.parts {
            let start = first_meta.header_len + part.fragment_offset;
            let end = start + part.payload_len;
            reassembled[start..end].copy_from_slice(
                &part.data[part.payload_offset..part.payload_offset + part.payload_len],
            );
        }
        rewrite_complete_ipv4(&mut reassembled, direction, old, new)?;

        for part in &mut group.parts {
            let payload_start = first_meta.header_len + part.fragment_offset;
            part.data[part.payload_offset..part.payload_offset + part.payload_len]
                .copy_from_slice(&reassembled[payload_start..payload_start + part.payload_len]);
            let address_offset = match direction {
                Direction::Forward => part.ip_offset + 16,
                Direction::Reverse => part.ip_offset + 12,
            };
            part.data[address_offset..address_offset + 4].copy_from_slice(&new.octets());
            update_ipv4_header_checksum(&mut part.data, part.ip_offset)?;
        }
        Ok(group.parts.into_iter().map(|part| part.data).collect())
    }
}

#[derive(Clone, Copy)]
struct Ipv4Meta {
    header_len: usize,
    total_len: usize,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
}

impl Ipv4Meta {
    fn fragmented(self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

fn parse_ipv4(data: &[u8], offset: usize) -> anyhow::Result<Ipv4Meta> {
    let packet = data
        .get(offset..)
        .context("IPv4 packet offset exceeds buffer")?;
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        bail!("invalid IPv4 packet");
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header_len < 20 || total_len < header_len || total_len > packet.len() {
        bail!("invalid IPv4 header or total length");
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    Ok(Ipv4Meta {
        header_len,
        total_len,
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        identification: u16::from_be_bytes([packet[4], packet[5]]),
        fragment_offset: flags_offset & 0x1fff,
        more_fragments: flags_offset & 0x2000 != 0,
    })
}

fn rewrite_complete_ipv4(
    packet: &mut [u8],
    direction: Direction,
    old: Ipv4Addr,
    new: Ipv4Addr,
) -> anyhow::Result<()> {
    let meta = parse_ipv4(packet, 0)?;
    let address_offset = match direction {
        Direction::Forward => 16,
        Direction::Reverse => 12,
    };
    if packet[address_offset..address_offset + 4] != old.octets() {
        bail!("IPv4 address does not match subnet mapping");
    }
    packet[address_offset..address_offset + 4].copy_from_slice(&new.octets());

    let source = <[u8; 4]>::try_from(&packet[12..16]).expect("IPv4 source length");
    let destination = <[u8; 4]>::try_from(&packet[16..20]).expect("IPv4 destination length");
    let payload = &mut packet[meta.header_len..meta.total_len];
    match meta.protocol {
        6 if payload.len() >= 18 => {
            payload[16..18].fill(0);
            let checksum = transport_checksum(&source, &destination, meta.protocol, payload);
            payload[16..18].copy_from_slice(&checksum.to_be_bytes());
        }
        17 if payload.len() >= 8 => {
            let had_checksum = payload[6] != 0 || payload[7] != 0;
            if had_checksum {
                let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                if udp_len < 8 || udp_len > payload.len() {
                    bail!("invalid UDP length in mapped IPv4 packet");
                }
                payload[6..8].fill(0);
                let checksum =
                    transport_checksum(&source, &destination, meta.protocol, &payload[..udp_len]);
                payload[6..8]
                    .copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());
            }
        }
        1 if payload.len() >= 4 => {
            if direction == Direction::Reverse
                && is_icmp_error(payload[0])
                && payload.len() >= 8 + 20
            {
                rewrite_quoted_destination(&mut payload[8..], old, new)?;
            }
            payload[2..4].fill(0);
            let checksum = internet_checksum(payload);
            payload[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => {}
    }
    update_ipv4_header_checksum(packet, 0)
}

fn is_icmp_error(kind: u8) -> bool {
    matches!(kind, 3 | 4 | 5 | 11 | 12)
}

fn rewrite_quoted_destination(
    packet: &mut [u8],
    old: Ipv4Addr,
    new: Ipv4Addr,
) -> anyhow::Result<()> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Ok(());
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Ok(());
    }
    if packet[16..20] == old.octets() {
        packet[16..20].copy_from_slice(&new.octets());
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..header_len]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
    Ok(())
}

fn update_ipv4_header_checksum(packet: &mut [u8], offset: usize) -> anyhow::Result<()> {
    let meta = parse_ipv4(packet, offset)?;
    let header = &mut packet[offset..offset + meta.header_len];
    header[10..12].fill(0);
    let checksum = internet_checksum(header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn transport_checksum(source: &[u8], destination: &[u8], protocol: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_words(&mut sum, source);
    add_words(&mut sum, destination);
    sum += protocol as u32;
    sum += payload.len() as u32;
    add_words(&mut sum, payload);
    finish_checksum(sum)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    add_words(&mut sum, data);
    finish_checksum(sum)
}

fn add_words(sum: &mut u32, data: &[u8]) {
    let mut chunks = data.chunks_exact(2);
    for word in &mut chunks {
        *sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        *sum += (*last as u32) << 8;
    }
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(destination: Ipv4Addr, checksum: u16) -> TransmissionBytes {
        let mut bytes = vec![0u8; 32];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(32u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&Ipv4Addr::new(10, 26, 0, 8).octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..22].copy_from_slice(&1234u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&12u16.to_be_bytes());
        bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
        bytes[28..].copy_from_slice(b"test");
        update_ipv4_header_checksum(&mut bytes, 0).unwrap();
        bytes.as_slice().into()
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> TransmissionBytes {
        let mut bytes = vec![0u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let total_len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..].copy_from_slice(payload);
        update_ipv4_header_checksum(&mut bytes, 0).unwrap();
        bytes.as_slice().into()
    }

    #[test]
    fn rewrites_udp_destination_and_preserves_disabled_checksum() {
        let mapper = SubnetPacketMapper::default();
        let output = mapper
            .map_destination(
                Ipv4Addr::new(10, 26, 0, 2),
                udp_packet(Ipv4Addr::new(192, 168, 2, 2), 0),
                0,
                Ipv4Addr::new(192, 168, 2, 2),
                Ipv4Addr::new(192, 168, 1, 3),
            )
            .unwrap();
        assert_eq!(&output[0][16..20], &[192, 168, 1, 3]);
        assert_eq!(&output[0][26..28], &[0, 0]);
        assert_eq!(internet_checksum(&output[0][..20]), 0);
    }

    #[test]
    fn waits_for_fragments_then_preserves_fragment_layout() {
        let mapper = SubnetPacketMapper::default();
        let full = udp_packet(Ipv4Addr::new(192, 168, 2, 2), 1);
        let mut first = full[..28].to_vec();
        first[2..4].copy_from_slice(&28u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        update_ipv4_header_checksum(&mut first, 0).unwrap();
        let mut last = Vec::from(&full[..20]);
        last.extend_from_slice(&full[28..32]);
        last[2..4].copy_from_slice(&24u16.to_be_bytes());
        last[6..8].copy_from_slice(&1u16.to_be_bytes());
        update_ipv4_header_checksum(&mut last, 0).unwrap();
        let args = (
            Ipv4Addr::new(10, 26, 0, 2),
            Ipv4Addr::new(192, 168, 2, 2),
            Ipv4Addr::new(192, 168, 1, 3),
        );
        assert!(
            mapper
                .map_destination(args.0, last.as_slice().into(), 0, args.1, args.2)
                .unwrap()
                .is_empty()
        );
        let output = mapper
            .map_destination(args.0, first.as_slice().into(), 0, args.1, args.2)
            .unwrap();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].len(), 28);
        assert_eq!(output[1].len(), 24);
        assert!(
            output
                .iter()
                .all(|packet| packet[16..20] == [192, 168, 1, 3])
        );
    }

    #[test]
    fn accepts_identical_fragment_duplicates_and_rejects_conflicting_overlap() {
        let mapper = SubnetPacketMapper::default();
        let full = udp_packet(Ipv4Addr::new(192, 168, 2, 2), 1);
        let mut first = full[..28].to_vec();
        first[2..4].copy_from_slice(&28u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        update_ipv4_header_checksum(&mut first, 0).unwrap();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let mapped = Ipv4Addr::new(192, 168, 2, 2);
        let actual = Ipv4Addr::new(192, 168, 1, 3);
        assert!(
            mapper
                .map_destination(peer, first.as_slice().into(), 0, mapped, actual)
                .unwrap()
                .is_empty()
        );
        assert!(
            mapper
                .map_destination(peer, first.as_slice().into(), 0, mapped, actual)
                .unwrap()
                .is_empty()
        );

        let mut conflicting = first.clone();
        conflicting[27] ^= 0xff;
        update_ipv4_header_checksum(&mut conflicting, 0).unwrap();
        assert!(
            mapper
                .map_destination(peer, conflicting.as_slice().into(), 0, mapped, actual)
                .is_err()
        );
        assert!(mapper.fragments.lock().groups.is_empty());
    }

    #[test]
    fn expires_incomplete_fragment_groups() {
        let mapper = SubnetPacketMapper::default();
        let full = udp_packet(Ipv4Addr::new(192, 168, 2, 2), 1);
        let mut first = full[..28].to_vec();
        first[2..4].copy_from_slice(&28u16.to_be_bytes());
        first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        update_ipv4_header_checksum(&mut first, 0).unwrap();
        let peer = Ipv4Addr::new(10, 26, 0, 2);
        let mapped = Ipv4Addr::new(192, 168, 2, 2);
        let actual = Ipv4Addr::new(192, 168, 1, 3);
        mapper
            .map_destination(peer, first.as_slice().into(), 0, mapped, actual)
            .unwrap();
        for group in mapper.fragments.lock().groups.values_mut() {
            group.created = Instant::now() - FRAGMENT_TIMEOUT - Duration::from_secs(1);
        }

        let mut last = Vec::from(&full[..20]);
        last.extend_from_slice(&full[28..32]);
        last[2..4].copy_from_slice(&24u16.to_be_bytes());
        last[6..8].copy_from_slice(&1u16.to_be_bytes());
        update_ipv4_header_checksum(&mut last, 0).unwrap();
        assert!(
            mapper
                .map_destination(peer, last.as_slice().into(), 0, mapped, actual)
                .unwrap()
                .is_empty()
        );
        assert_eq!(mapper.fragments.lock().groups.len(), 1);
    }

    #[test]
    fn recalculates_udp_and_tcp_pseudo_header_checksums() {
        let mapper = SubnetPacketMapper::default();
        let mapped = Ipv4Addr::new(192, 168, 2, 2);
        let actual = Ipv4Addr::new(192, 168, 1, 3);
        let udp = mapper
            .map_destination(
                Ipv4Addr::new(10, 26, 0, 2),
                udp_packet(mapped, 1),
                0,
                mapped,
                actual,
            )
            .unwrap()
            .remove(0);
        assert_eq!(
            transport_checksum(&udp[12..16], &udp[16..20], 17, &udp[20..32]),
            0
        );

        let mut tcp_payload = [0u8; 24];
        tcp_payload[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp_payload[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp_payload[12] = 5 << 4;
        let tcp = mapper
            .map_destination(
                Ipv4Addr::new(10, 26, 0, 2),
                ipv4_packet(Ipv4Addr::new(10, 26, 0, 8), mapped, 6, &tcp_payload),
                0,
                mapped,
                actual,
            )
            .unwrap()
            .remove(0);
        assert_eq!(
            transport_checksum(&tcp[12..16], &tcp[16..20], 6, &tcp[20..]),
            0
        );
    }

    #[test]
    fn reverse_mapping_updates_icmp_error_and_quoted_destination() {
        let actual = Ipv4Addr::new(192, 168, 1, 3);
        let mapped = Ipv4Addr::new(192, 168, 2, 2);
        let mut quoted = ipv4_packet(Ipv4Addr::new(10, 26, 0, 8), actual, 17, &[0; 8])
            .into_bytes()
            .to_vec();
        quoted.truncate(28);
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3;
        icmp[1] = 1;
        icmp.extend_from_slice(&quoted);
        let packet = ipv4_packet(actual, Ipv4Addr::new(10, 26, 0, 8), 1, &icmp);
        let output = SubnetPacketMapper::default()
            .map_source(Ipv4Addr::new(10, 26, 0, 8), packet, 0, actual, mapped)
            .unwrap()
            .remove(0);
        assert_eq!(&output[12..16], &mapped.octets());
        assert_eq!(&output[44..48], &mapped.octets());
        assert_eq!(internet_checksum(&output[20..]), 0);
        assert_eq!(internet_checksum(&output[28..48]), 0);
    }
}
