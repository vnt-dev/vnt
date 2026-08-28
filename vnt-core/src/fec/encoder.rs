use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::BasicOutbound;
use anyhow::Result;
use parking_lot::Mutex;
use prost::Message;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

mod fec_proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.fec.rs"));
}
use crate::utils::task_control::TaskGroup;
pub use fec_proto::FecPacket;
#[cfg(test)]
pub use fec_proto::ParityData;

const BATCH_SIZE: usize = 10;
const REDUNDANCY_RATE: f32 = 0.2;
const BATCH_TIMEOUT_MS: u64 = 20;
const MIN_PARITY: usize = 1;
const BATCH_CHANNEL_SIZE: usize = 1024;
const PACKET_LENGTH_SIZE: usize = size_of::<u16>();

#[derive(Clone)]
pub struct FecEncoder {
    batch_states: Arc<Mutex<HashMap<Ipv4Addr, DestBatchState>>>,
    batch_tx: mpsc::Sender<(Ipv4Addr, Ipv4Addr, u64, Vec<TransmissionBytes>)>,
}

struct DestBatchState {
    group_id: u64,
    current_batch: Vec<TransmissionBytes>,
    deadline: Instant,
    src_ip: Ipv4Addr,
}

impl FecEncoder {
    pub fn new(task_group: &TaskGroup, basic_outbound: BasicOutbound) -> Self {
        let (batch_tx, batch_rx) = mpsc::channel(BATCH_CHANNEL_SIZE);
        let batch_states = Arc::new(Mutex::new(HashMap::new()));
        let encoder = Self {
            batch_states: batch_states.clone(),
            batch_tx,
        };

        task_group.spawn(fec_encoder_worker(batch_rx, basic_outbound, batch_states));

        encoder
    }

    /// 将数据包加入FEC批次并返回包装后的包
    pub fn encode(
        &self,
        mut packet: NetPacket<TransmissionBytes>,
    ) -> Result<NetPacket<TransmissionBytes>> {
        let src_ip = Ipv4Addr::from(packet.src_id());
        let dest = Ipv4Addr::from(packet.dest_id());
        // FEC 编码完整的原始 NetPacket。长度前缀用于去除 RS 等长 shard 的尾部填充。
        let original_packet = packet.buffer().to_vec();
        let original_packet_len = u16::try_from(original_packet.len())
            .map_err(|_| anyhow::anyhow!("Packet too big: {}", original_packet.len()))?;
        let batch_len = PACKET_LENGTH_SIZE
            .checked_add(original_packet.len())
            .ok_or_else(|| anyhow::anyhow!("FEC packet length overflow"))?;
        let mut batch_buffer = TransmissionBytes::zeroed(batch_len);
        batch_buffer[..PACKET_LENGTH_SIZE].copy_from_slice(&original_packet_len.to_be_bytes());
        batch_buffer[PACKET_LENGTH_SIZE..].copy_from_slice(&original_packet);

        let (group_id, packet_index) = {
            let mut states = self.batch_states.lock();
            let state = states.entry(dest).or_insert_with(|| DestBatchState {
                group_id: 0,
                current_batch: Vec::with_capacity(BATCH_SIZE),
                deadline: Instant::now() + Duration::from_millis(BATCH_TIMEOUT_MS),
                src_ip,
            });

            let group_id = state.group_id;
            let packet_index = state.current_batch.len();

            state.current_batch.push(batch_buffer);

            if state.current_batch.len() >= BATCH_SIZE {
                let batch = std::mem::take(&mut state.current_batch);
                state.group_id += 1;
                state.deadline = Instant::now() + Duration::from_millis(BATCH_TIMEOUT_MS);

                if self
                    .batch_tx
                    .try_send((src_ip, dest, group_id, batch))
                    .is_err()
                {
                    log::warn!(
                        "failed to send batch to worker (channel full), dest={}, group_id={}",
                        dest,
                        group_id
                    );
                }
            }

            (group_id, packet_index)
        };

        let fec_packet = FecPacket {
            group_id,
            packet_index: packet_index as u32,
            payload: original_packet,
            parity_data: None,
        };

        let fec_payload = fec_packet.encode_to_vec();
        packet
            .source_buf_mut()
            .resize(HEAD_LENGTH + fec_payload.len(), 0);
        packet.set_payload(&fec_payload)?;
        packet.set_fec_flag(true);

        Ok(packet)
    }
}

/// 后台worker，处理满批次和超时批次
async fn fec_encoder_worker(
    mut batch_rx: mpsc::Receiver<(Ipv4Addr, Ipv4Addr, u64, Vec<TransmissionBytes>)>,
    basic_outbound: BasicOutbound,
    batch_states: Arc<Mutex<HashMap<Ipv4Addr, DestBatchState>>>,
) {
    let mut timer = tokio::time::interval(Duration::from_millis(5));

    loop {
        tokio::select! {
            Some((src,dest, group_id, mut items)) = batch_rx.recv() => {
                if let Err(e) = encode_and_send_parity(src,dest, group_id, &mut items, &basic_outbound).await {
                    log::warn!("encode_and_send_parity error for {} group {}: {:?}", dest, group_id, e);
                }
            }

            _ = timer.tick() => {
                let now = Instant::now();

                let timeout_batches = {
                    let mut states = batch_states.lock();
                    let mut batches = Vec::new();
                    for (dest, state) in states.iter_mut() {
                        if !state.current_batch.is_empty() && now >= state.deadline {
                            let items = std::mem::take(&mut state.current_batch);
                            let group_id = state.group_id;
                            state.group_id += 1;
                            state.deadline = Instant::now() + Duration::from_millis(BATCH_TIMEOUT_MS);
                            batches.push((state.src_ip,*dest, group_id, items));
                        }
                    }
                    batches
                };

                for (src,dest, group_id, mut items) in timeout_batches {
                    if let Err(e) = encode_and_send_parity(src, dest, group_id, &mut items, &basic_outbound).await {
                        log::warn!("encode_and_send_parity timeout error for {} group {}: {:?}", dest, group_id, e);
                    }
                }
            }
        }
    }
}

/// Reed-Solomon编码并发送冗余包
async fn encode_and_send_parity(
    src: Ipv4Addr,
    dest: Ipv4Addr,
    group_id: u64,
    items: &mut Vec<TransmissionBytes>,
    basic_outbound: &BasicOutbound,
) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }

    let data_shards = items.len();
    let parity_shards = (data_shards as f32 * REDUNDANCY_RATE).ceil() as usize;
    let parity_shards = parity_shards.max(MIN_PARITY);

    let max_len = items.iter().map(|buf| buf.len()).max().unwrap_or(0);

    if max_len == 0 {
        log::warn!("max_len is 0, dest={}, group_id={}", dest, group_id);
        return Ok(());
    }

    for buf in items.iter_mut() {
        if buf.len() < max_len {
            let padding = max_len - buf.len();
            buf.extend_end(padding);
        }
    }

    for _ in 0..parity_shards {
        items.push(TransmissionBytes::zeroed(max_len));
    }

    let rs = ReedSolomon::new(data_shards, parity_shards)?;
    let mut shard_refs: Vec<&mut [u8]> = items.iter_mut().map(|buf| buf.as_mut()).collect();
    rs.encode(&mut shard_refs)?;

    for (i, parity_buf) in items[data_shards..].iter().enumerate() {
        let packet_index = (data_shards + i) as u32;
        let fec_packet = FecPacket {
            group_id,
            packet_index,
            payload: parity_buf.as_ref().to_vec(),
            parity_data: Some(fec_proto::ParityData {
                data_shards: data_shards as u32,
                parity_shards: parity_shards as u32,
            }),
        };

        let fec_payload = fec_packet.encode_to_vec();

        let buffer = TransmissionBytes::zeroed(HEAD_LENGTH + fec_payload.len());
        let mut net_packet = NetPacket::new(buffer)?;
        net_packet.set_msg_type(MsgType::Turn);
        net_packet.set_src_id(src.into());
        net_packet.set_dest_id(dest.into());
        net_packet.set_ttl(5);
        net_packet.set_payload(&fec_payload)?;
        net_packet.set_fec_flag(true);

        if let Err(e) = basic_outbound.send_encrypted_packet(dest, net_packet).await {
            log::warn!(
                "failed to send parity packet {}: {:?}, dest={}, group_id={}",
                packet_index,
                e,
                dest,
                group_id
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_fec_payload_and_shard_contain_complete_packet() {
        let (batch_tx, _batch_rx) = mpsc::channel(BATCH_CHANNEL_SIZE);
        let encoder = FecEncoder {
            batch_states: Arc::new(Mutex::new(HashMap::new())),
            batch_tx,
        };

        let buffer = TransmissionBytes::zeroed(HEAD_LENGTH + 5);
        let mut packet = NetPacket::new(buffer).unwrap();
        packet.set_msg_type(MsgType::Quic);
        packet.set_ttl(3);
        packet.set_seq(0x1234_5678);
        packet.set_src_id(0x0A00_0001);
        packet.set_dest_id(0x0A00_0002);
        packet.set_ethernet_flag(true);
        packet.head_mut()[3] = 0xA5;
        packet.set_payload(&[1, 2, 3, 4, 5]).unwrap();
        let original = packet.buffer().to_vec();

        let encoded = encoder.encode(packet).unwrap();
        let fec_packet = FecPacket::decode(encoded.payload()).unwrap();
        assert_eq!(fec_packet.payload, original);

        let states = encoder.batch_states.lock();
        let state = states.get(&Ipv4Addr::from(0x0A00_0002u32)).unwrap();
        let shard = state.current_batch.first().unwrap();
        let packet_len = u16::from_be_bytes(shard[..PACKET_LENGTH_SIZE].try_into().unwrap());
        assert_eq!(packet_len as usize, original.len());
        assert_eq!(&shard[PACKET_LENGTH_SIZE..], original.as_slice());
    }

    #[test]
    fn rejects_complete_packet_larger_than_u16() {
        let (batch_tx, _batch_rx) = mpsc::channel(BATCH_CHANNEL_SIZE);
        let encoder = FecEncoder {
            batch_states: Arc::new(Mutex::new(HashMap::new())),
            batch_tx,
        };
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(u16::MAX as usize + 1)).unwrap();
        packet.set_src_id(0x0A00_0001);
        packet.set_dest_id(0x0A00_0002);

        let err = match encoder.encode(packet) {
            Err(err) => err,
            Ok(_) => panic!("oversized complete packet must be rejected"),
        };
        assert!(err.to_string().contains("Packet too big"));
    }
}
