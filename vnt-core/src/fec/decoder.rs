use crate::fec::encoder::FecPacket;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use anyhow::{Result, bail};
use prost::Message;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const GROUP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_GROUPS: usize = 1000;
const MAX_NUM: usize = 50;

#[derive(Clone)]
pub struct FecDecoder {
    inner: Arc<parking_lot::Mutex<FecDecoderInner>>,
}

struct FecDecoderInner {
    groups: HashMap<(Ipv4Addr, u64), FecGroup>,
    last_cleanup: Instant,
}

struct FecGroup {
    data_shards: usize,
    parity_shards: usize,
    received_original_count: usize,
    received_shards: Vec<Option<Vec<u8>>>,
    last_update: Instant,
}
impl FecGroup {
    fn is_done(&self) -> bool {
        self.data_shards != 0 && self.received_original_count == self.data_shards
    }
    fn done(&mut self) {
        self.received_original_count = self.data_shards;
        self.received_shards = vec![];
    }
}
impl Default for FecGroup {
    fn default() -> Self {
        Self {
            data_shards: 0,
            parity_shards: 0,
            received_original_count: 0,
            received_shards: Vec::with_capacity(16),
            last_update: Instant::now(),
        }
    }
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(FecDecoderInner {
                groups: HashMap::new(),
                last_cleanup: Instant::now(),
            })),
        }
    }

    /// 接收FEC包并尝试恢复丢失的包
    pub fn receive(
        &self,
        net_packet: NetPacket<TransmissionBytes>,
    ) -> Result<Option<Vec<NetPacket<TransmissionBytes>>>> {
        let mut inner = self.inner.lock();
        let src_ip = Ipv4Addr::from(net_packet.src_id());
        let fec_packet = FecPacket::decode(net_packet.payload())?;

        let group_id = fec_packet.group_id;
        let packet_index = fec_packet.packet_index as usize;
        let payload = fec_packet.payload;

        if packet_index > MAX_NUM {
            log::warn!(
                "packet_index overflow, src={src_ip},group_id={group_id}, packet_index={packet_index}",
            );
            bail!("packet_index overflow {src_ip}");
        }
        let mut packet = None;
        let group = inner.groups.entry((src_ip, group_id)).or_default();
        if group.is_done() {
            return Ok(None);
        }
        if group
            .received_shards
            .get(packet_index)
            .is_some_and(|v| v.is_some())
        {
            return Ok(None);
        }
        if let Some(parity_data) = fec_packet.parity_data {
            let data_shards = parity_data.data_shards as usize;
            let parity_shards = parity_data.parity_shards as usize;
            if data_shards > MAX_NUM {
                bail!("data_shards overflow {src_ip}");
            }
            if parity_shards > MAX_NUM {
                bail!("parity_shards overflow {src_ip}");
            }

            if data_shards + parity_shards <= packet_index {
                log::warn!(
                    "packet_index overflow in parity, src={},group_id={}, packet_index={}, total_shards={}",
                    src_ip,
                    group_id,
                    packet_index,
                    data_shards + parity_shards
                );
                bail!("packet_index overflow {src_ip}");
            }
            if group.data_shards != 0 && group.data_shards != data_shards {
                bail!("group data_shards!=data_shards {src_ip}");
            }
            if group.parity_shards != 0 && group.parity_shards != parity_shards {
                bail!("group parity_shards!=parity_shards {src_ip}");
            }
            group.data_shards = data_shards;
            group.parity_shards = parity_shards;
            if group.received_shards.len() < data_shards + parity_shards {
                group
                    .received_shards
                    .resize(data_shards + parity_shards, None);
            }

            group.received_shards[packet_index] = Some(payload);
        } else {
            let buffer = TransmissionBytes::zeroed(HEAD_LENGTH + payload.len());
            let mut result_packet = NetPacket::new(buffer)?;
            result_packet.head_mut().copy_from_slice(net_packet.head());
            result_packet.set_fec_flag(false);
            result_packet.set_payload(&payload)?;
            packet = Some(result_packet);

            if group.received_shards.len() <= packet_index {
                group.received_shards.resize(packet_index + 1, None);
            }

            // 保存FEC数据: [type_byte, flags_byte, payload_len(u16), payload...]
            let type_byte = net_packet.head()[0];
            let flags_byte = net_packet.head()[2];
            let mut batch_data = vec![0u8; 4 + payload.len()];
            batch_data[0] = type_byte;
            batch_data[1] = flags_byte;
            batch_data[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            batch_data[4..].copy_from_slice(&payload);
            group.received_shards[packet_index] = Some(batch_data);
            group.received_original_count += 1;
        }
        group.last_update = Instant::now();

        if group.is_done() {
            group.done();
            if inner.last_cleanup.elapsed() > Duration::from_secs(1) {
                Self::cleanup_old_groups(&mut inner.groups);
                inner.last_cleanup = Instant::now();
            }
            return Ok(packet.map(|v| vec![v]));
        }

        let result = Self::try_decode(group, (src_ip, group_id), &net_packet)?;

        if inner.last_cleanup.elapsed() > Duration::from_secs(1) {
            Self::cleanup_old_groups(&mut inner.groups);
            inner.last_cleanup = Instant::now();
        }
        match (packet, result) {
            (Some(packet), Some(mut result)) => {
                result.push(packet);
                Ok(Some(result))
            }
            (Some(packet), None) => Ok(Some(vec![packet])),
            (None, Some(result)) => Ok(Some(result)),
            (None, None) => Ok(None),
        }
    }

    /// 检查是否可以恢复丢失的包
    fn try_decode(
        group: &mut FecGroup,
        key: (Ipv4Addr, u64),
        net_packet: &NetPacket<TransmissionBytes>,
    ) -> Result<Option<Vec<NetPacket<TransmissionBytes>>>> {
        if group.data_shards == 0 {
            return Ok(None);
        }
        if group.received_original_count == group.data_shards {
            return Ok(None);
        }
        let received_count = group.received_shards.iter().filter(|s| s.is_some()).count();

        if received_count < group.data_shards {
            return Ok(None);
        }

        Self::decode_with_rs(group, key, net_packet)
    }

    /// Reed-Solomon解码恢复丢失的包
    fn decode_with_rs(
        group: &mut FecGroup,
        key: (Ipv4Addr, u64),
        net_packet: &NetPacket<TransmissionBytes>,
    ) -> Result<Option<Vec<NetPacket<TransmissionBytes>>>> {
        let (src_ip, group_id) = key;

        if group.received_shards.len() != group.data_shards + group.parity_shards {
            bail!(
                "received_shards.len()({}) != data_shards({})+parity_shards({}) src_ip={src_ip},group_id={group_id}",
                group.received_shards.len(),
                group.data_shards,
                group.parity_shards,
            )
        }

        let mut delivered_packets = vec![false; group.data_shards];
        for (index, x) in group.received_shards[..group.data_shards]
            .iter()
            .enumerate()
        {
            if x.is_some() {
                delivered_packets[index] = true;
            }
        }

        let rs = ReedSolomon::new(group.data_shards, group.parity_shards)?;
        rs.reconstruct(&mut group.received_shards)?;

        let mut result = Vec::new();
        for (i, shard) in group
            .received_shards
            .iter()
            .enumerate()
            .take(group.data_shards)
        {
            if let Some(shard) = shard {
                if delivered_packets[i] {
                    continue;
                }

                let net_packet = Self::rebuild_net_packet(net_packet, shard)?;
                result.push(net_packet);
            }
        }

        group.done();

        Ok(Some(result))
    }

    /// 从恢复的数据重建NetPacket
    fn rebuild_net_packet(
        current_packet: &NetPacket<TransmissionBytes>,
        recovered_data: &[u8],
    ) -> Result<NetPacket<TransmissionBytes>> {
        if recovered_data.len() < 4 {
            bail!("recovered_data too short");
        }

        let type_byte = recovered_data[0];
        let flags_byte = recovered_data[1];
        let payload_len = u16::from_be_bytes([recovered_data[2], recovered_data[3]]) as usize;

        if payload_len + 4 > recovered_data.len() {
            bail!("invalid payload_len in recovered_data");
        }

        let payload = &recovered_data[4..4 + payload_len];

        let buffer = TransmissionBytes::zeroed(HEAD_LENGTH + payload.len());
        let mut net_packet = NetPacket::new(buffer)?;

        net_packet.head_mut()[0] = type_byte;
        net_packet.head_mut()[2] = flags_byte;
        net_packet.set_src_id(current_packet.src_id());
        net_packet.set_dest_id(current_packet.dest_id());
        net_packet.set_ttl(current_packet.ttl());
        net_packet.set_fec_flag(false);
        net_packet.set_payload(payload)?;

        Ok(net_packet)
    }

    fn cleanup_old_groups(groups: &mut HashMap<(Ipv4Addr, u64), FecGroup>) {
        let now = Instant::now();

        groups.retain(|_, group| now.duration_since(group.last_update) < GROUP_TIMEOUT);

        if groups.len() > MAX_GROUPS {
            let mut group_ids: Vec<_> = groups.iter().map(|(id, g)| (*id, g.last_update)).collect();
            group_ids.sort_by_key(|(_, last_update)| *last_update);

            let to_remove = group_ids.len() - MAX_GROUPS;
            for (group_id, _) in group_ids.iter().take(to_remove) {
                groups.remove(group_id);
            }
        }
    }
}
