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
    /// shard 统一长度（校验包到达后才能确定，等于编码端填充后的 max_len）
    shard_size: usize,
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
            shard_size: 0,
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
            // 校验包索引必须落在 [data_shards, data_shards+parity_shards) 区间，
            // 否则会覆盖数据区 shard，污染整个 group
            if packet_index < data_shards {
                log::warn!(
                    "parity packet_index in data region, src={src_ip},group_id={group_id}, packet_index={packet_index}, data_shards={data_shards}"
                );
                return Ok(None);
            }
            if group.data_shards != 0 && group.data_shards != data_shards {
                bail!("group data_shards!=data_shards {src_ip}");
            }
            if group.parity_shards != 0 && group.parity_shards != parity_shards {
                bail!("group parity_shards!=parity_shards {src_ip}");
            }
            // 尺寸未知时到达的越界数据包可能已把 received_shards 撑大，
            // 该 group 已无法解码，直接放弃（等超时 GC）
            if group.received_shards.len() > data_shards + parity_shards {
                log::warn!(
                    "fec group polluted by out-of-range packet_index, src={src_ip},group_id={group_id}, received_shards={}, total={}",
                    group.received_shards.len(),
                    data_shards + parity_shards
                );
                bail!("fec group polluted {src_ip}");
            }
            group.data_shards = data_shards;
            group.parity_shards = parity_shards;
            // 校验包在线上即编码端填充后的 shard 统一长度
            group.shard_size = payload.len();
            if group.received_shards.len() < data_shards + parity_shards {
                group
                    .received_shards
                    .resize(data_shards + parity_shards, None);
            }

            // RS 要求所有 shard 等长：把先到的数据 shard 补齐到 shard_size
            // （编码端发送前把所有数据 shard 填充到 max_len）
            for shard in group.received_shards[..data_shards].iter_mut().flatten() {
                if shard.len() < group.shard_size {
                    shard.resize(group.shard_size, 0);
                }
            }
            group.received_shards[packet_index] = Some(payload);
        } else {
            // group 尺寸已知时，数据包索引必须落在数据区，
            // 否则会把 received_shards 撑出 data_shards+parity_shards，污染整个 group
            if group.data_shards != 0 && packet_index >= group.data_shards {
                log::warn!(
                    "data packet_index overflow, src={src_ip},group_id={group_id}, packet_index={packet_index}, data_shards={}",
                    group.data_shards
                );
                return Ok(None);
            }
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
            // 长度字段为 u16，超限必须拒绝而非静默截断（实际 payload 远小于此值，
            // 这里是防御性检查）
            let payload_len = u16::try_from(payload.len())
                .map_err(|_| anyhow::anyhow!("fec payload too large: {}", payload.len()))?;
            let mut batch_data = vec![0u8; 4 + payload.len()];
            batch_data[0] = type_byte;
            batch_data[1] = flags_byte;
            batch_data[2..4].copy_from_slice(&payload_len.to_be_bytes());
            batch_data[4..].copy_from_slice(&payload);
            // 校验包先到时 shard 尺寸已知，补齐保持所有 shard 等长
            if group.shard_size != 0 && batch_data.len() < group.shard_size {
                batch_data.resize(group.shard_size, 0);
            }
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

        // 解码失败（如对端构造的异常 group）只放弃该 group，
        // 不能向上传播错误——否则当前完好接收的包会被连带丢弃
        let decode_failed;
        let result = match Self::try_decode(group, (src_ip, group_id), &net_packet) {
            Ok(result) => {
                decode_failed = false;
                result
            }
            Err(e) => {
                log::warn!(
                    "fec decode failed, drop group, src={src_ip},group_id={group_id}: {e:?}"
                );
                decode_failed = true;
                None
            }
        };
        if decode_failed {
            // 移除坏 group，后续该 group 的完好数据包按新 group 正常透传
            inner.groups.remove(&(src_ip, group_id));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::encoder::ParityData;

    const SRC: u32 = 0x0A000001;
    const DST: u32 = 0x0A000002;

    /// 构造线上的 FEC 数据包（payload 为 prost 编码的 FecPacket）
    fn build_data_packet(
        group_id: u64,
        packet_index: u32,
        type_byte: u8,
        flags_byte: u8,
        payload: &[u8],
    ) -> NetPacket<TransmissionBytes> {
        let fec = FecPacket {
            group_id,
            packet_index,
            payload: payload.to_vec(),
            parity_data: None,
        };
        build_packet(fec, type_byte, flags_byte)
    }

    fn build_parity_packet(
        group_id: u64,
        packet_index: u32,
        payload: Vec<u8>,
        data_shards: u32,
        parity_shards: u32,
    ) -> NetPacket<TransmissionBytes> {
        let fec = FecPacket {
            group_id,
            packet_index,
            payload,
            parity_data: Some(ParityData {
                data_shards,
                parity_shards,
            }),
        };
        // 校验包头部的 type/flags 不参与数据重建，固定取值
        build_packet(fec, 0x81, 0)
    }

    fn build_packet(fec: FecPacket, type_byte: u8, flags_byte: u8) -> NetPacket<TransmissionBytes> {
        let fec_payload = fec.encode_to_vec();
        let buffer = TransmissionBytes::zeroed(HEAD_LENGTH + fec_payload.len());
        let mut pkt = NetPacket::new(buffer).unwrap();
        pkt.head_mut()[0] = type_byte;
        pkt.head_mut()[2] = flags_byte;
        pkt.set_src_id(SRC);
        pkt.set_dest_id(DST);
        pkt.set_ttl(5);
        pkt.set_fec_flag(true);
        pkt.set_payload(&fec_payload).unwrap();
        pkt
    }

    /// 按编码端格式组装 shard：[type_byte, flags_byte, len(u16), payload...]，填充到 max_len
    fn make_shard(type_byte: u8, flags_byte: u8, payload: &[u8], max_len: usize) -> Vec<u8> {
        let mut shard = vec![0u8; max_len];
        shard[0] = type_byte;
        shard[1] = flags_byte;
        shard[2..4].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        shard[4..4 + payload.len()].copy_from_slice(payload);
        shard
    }

    #[test]
    fn test_original_fec_packet_preserves_ethernet_flag() {
        let decoder = FecDecoder::new();
        let packets = decoder
            .receive(build_data_packet(99, 0, 0x81, 0x10, &[1, 2, 3]))
            .unwrap()
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert!(packets[0].is_ethernet());
        assert!(!packets[0].is_fec());
    }

    /// 变长批次：丢一个数据包，靠校验包必须能恢复（修复前必报 IncorrectShardSize）
    #[test]
    fn test_reconstruct_variable_length_batch() {
        let decoder = FecDecoder::new();
        let group_id = 1u64;

        let payloads: [&[u8]; 3] = [&[0xAA; 10], &[0xBB; 30], &[0xCC; 20]];
        let type_bytes = [0x81u8, 0x82, 0x83];
        let max_len = 4 + 30; // 编码端按最长 shard 填充

        // 编码端：3 数据 + 1 校验
        let mut shards: Vec<Vec<u8>> = payloads
            .iter()
            .zip(type_bytes)
            .map(|(p, t)| make_shard(t, 0, p, max_len))
            .collect();
        shards.push(vec![0u8; max_len]);
        let rs = ReedSolomon::new(3, 1).unwrap();
        {
            let mut refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut()).collect();
            rs.encode(&mut refs).unwrap();
        }
        let parity = shards[3].clone();

        // 收到 pkt0、pkt1，pkt2 丢失，随后收到校验包
        assert!(
            decoder
                .receive(build_data_packet(
                    group_id,
                    0,
                    type_bytes[0],
                    0,
                    payloads[0]
                ))
                .unwrap()
                .is_some()
        );
        assert!(
            decoder
                .receive(build_data_packet(
                    group_id,
                    1,
                    type_bytes[1],
                    0,
                    payloads[1]
                ))
                .unwrap()
                .is_some()
        );
        let recovered = decoder
            .receive(build_parity_packet(group_id, 3, parity, 3, 1))
            .unwrap()
            .expect("should reconstruct the lost packet");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].payload(), payloads[2]);
        assert_eq!(recovered[0].head()[0], type_bytes[2]);
        assert_eq!(recovered[0].src_id(), SRC);
        assert_eq!(recovered[0].dest_id(), DST);
        assert!(!recovered[0].is_fec());
    }

    /// 校验包先到时，后到的数据 shard 也要补齐（等长）后能恢复
    #[test]
    fn test_reconstruct_when_parity_arrives_first() {
        let decoder = FecDecoder::new();
        let group_id = 2u64;

        let payloads: [&[u8]; 2] = [&[0x11; 8], &[0x22; 24]];
        let max_len = 4 + 24;

        let mut shards = [
            make_shard(0x81, 0, payloads[0], max_len),
            make_shard(0x82, 0, payloads[1], max_len),
            vec![0u8; max_len],
        ];
        let rs = ReedSolomon::new(2, 1).unwrap();
        {
            let mut refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut()).collect();
            rs.encode(&mut refs).unwrap();
        }
        let parity = shards[2].clone();

        // 校验包先到（此时丢失 pkt0 还未知），再收到 pkt1
        assert!(
            decoder
                .receive(build_parity_packet(group_id, 2, parity, 2, 1))
                .unwrap()
                .is_none()
        );
        let recovered = decoder
            .receive(build_data_packet(group_id, 1, 0x82, 0, payloads[1]))
            .unwrap()
            .expect("should reconstruct pkt0 after parity-first");

        // 校验包先到时 pkt1 会透传，恢复的 pkt0 也应在返回列表中
        let recovered_pkt0 = recovered
            .iter()
            .find(|p| p.payload() == payloads[0])
            .expect("recovered pkt0 missing");
        assert_eq!(recovered_pkt0.head()[0], 0x81);
    }

    /// 异常 group（校验 shard 比数据 shard 短）导致重建失败时：
    /// 当前包不被连带丢弃，坏 group 被移除，后续数据包正常透传
    #[test]
    fn test_decode_failure_does_not_swallow_good_packets() {
        let decoder = FecDecoder::new();
        let group_id = 3u64;

        // 先到一个较大的数据包
        assert!(
            decoder
                .receive(build_data_packet(group_id, 0, 0x81, 0, &[0xAA; 40]))
                .unwrap()
                .is_some()
        );
        // 异常校验包：shard 只有 4 字节，比已存数据 shard 短，reconstruct 必失败
        assert!(
            decoder
                .receive(build_parity_packet(group_id, 2, vec![0u8; 4], 2, 1))
                .unwrap()
                .is_none()
        );
        // 坏 group 已被移除，后续数据包按新 group 正常透传
        let passed = decoder
            .receive(build_data_packet(group_id, 1, 0x82, 0, &[0xBB; 8]))
            .unwrap()
            .expect("good packet must not be swallowed");
        assert_eq!(passed.len(), 1);
        assert_eq!(passed[0].payload(), &[0xBB; 8][..]);
    }

    /// 越界数据包不污染 group：尺寸已知后到达的越界 packet_index 必须被丢弃，
    /// 不能把 received_shards 撑出 data_shards+parity_shards 导致整组解码失败
    #[test]
    fn test_out_of_range_data_index_does_not_poison_group() {
        let decoder = FecDecoder::new();
        let group_id = 1u64;
        let shard = make_shard(0x81, 0, &[0xAA; 10], 14);
        // 校验包先到：data_shards=2, parity_shards=1，索引 2
        let parity = build_parity_packet(group_id, 2, shard, 2, 1);
        decoder.receive(parity).unwrap();

        // 越界数据包（index 5 >= data_shards 2）：必须被丢弃
        let evil = build_data_packet(group_id, 5, 0x81, 0, &[0xEE; 10]);
        assert!(decoder.receive(evil).unwrap().is_none());

        // 合法数据包 p0：received_shards 未被撑大，正常触发重构，
        // 返回 p0 和恢复出的 p1 共 2 个包（修复前 group 已被污染，解码失败只返回 p0）
        let p0 = build_data_packet(group_id, 0, 0x81, 0, &[0xAA; 10]);
        let out = decoder.receive(p0).unwrap().expect("packet 0 delivered");
        assert_eq!(out.len(), 2, "should deliver p0 and recovered p1");
        // group 已完成，p1 重传被忽略
        let p1 = build_data_packet(group_id, 1, 0x81, 0, &[0xBB; 10]);
        assert!(decoder.receive(p1).unwrap().is_none());
    }

    /// 落在数据区的校验包索引必须被拒绝，且不能破坏 group
    #[test]
    fn test_parity_index_in_data_region_rejected() {
        let decoder = FecDecoder::new();
        let group_id = 1u64;
        let shard = make_shard(0x81, 0, &[0xAA; 10], 14);
        // 索引 0 < data_shards=2 的"校验包"：必须拒绝
        let bad_parity = build_parity_packet(group_id, 0, shard.clone(), 2, 1);
        assert!(decoder.receive(bad_parity).unwrap().is_none());

        // group 仍可用：合法校验包 + 数据包正常处理
        let parity = build_parity_packet(group_id, 2, shard, 2, 1);
        decoder.receive(parity).unwrap();
        let p0 = build_data_packet(group_id, 0, 0x81, 0, &[0xAA; 10]);
        assert!(decoder.receive(p0).unwrap().is_some());
    }
}
