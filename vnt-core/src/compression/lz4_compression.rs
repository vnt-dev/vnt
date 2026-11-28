use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use std::cell::RefCell;
use std::io;

/// Compressed payloads start with the uncompressed size, a little-endian u32.
const SIZE_PREFIX: usize = 4;

thread_local! {
    /// Reused across packets, so a packet does not set up a hash table.
    static COMPRESSOR: RefCell<lz4rip::block::Compressor> =
        RefCell::new(lz4rip::block::Compressor::new());
}

#[derive(Clone)]
pub struct LZ4Compression {
    min_size: usize, // 只压缩大于此大小的数据包
}

impl LZ4Compression {
    pub fn new() -> Self {
        Self::with_min_size(256)
    }
    pub fn with_min_size(min_size: usize) -> Self {
        Self { min_size }
    }

    /// 压缩数据包，返回新的压缩后的数据包
    /// reserve: 尾部预留空间（用于后续加密等操作）
    pub fn compress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
        reserve: usize,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        let payload = pkt.payload();
        if payload.len() < self.min_size {
            return Ok(pkt);
        }
        let block_start = HEAD_LENGTH + SIZE_PREFIX;
        let max_len = block_start + lz4rip::block::get_maximum_output_size(payload.len());
        let mut buf = TransmissionBytes::zeroed_size(max_len, reserve);
        let block_len = COMPRESSOR
            .with_borrow_mut(|compressor| {
                compressor.compress_into(payload, &mut buf[block_start..])
            })
            .map_err(|e| io::Error::other(format!("compress failed: {}", e)))?;
        if SIZE_PREFIX + block_len >= payload.len() {
            return Ok(pkt);
        }
        let total_len = block_start + block_len;
        buf.set_len(total_len)?;

        buf[..HEAD_LENGTH].copy_from_slice(&pkt.buffer()[..HEAD_LENGTH]);
        buf[HEAD_LENGTH..block_start].copy_from_slice(&(payload.len() as u32).to_le_bytes());

        let mut packet = NetPacket::new(buf)?;
        packet.set_compressed_flag(true);
        Ok(packet)
    }

    /// 解压缩数据包，返回新的解压后的数据包
    /// reserve: 尾部预留空间（用于后续加密等操作）
    pub fn decompress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        if !pkt.is_compressed() {
            return Ok(pkt);
        }
        let payload = pkt.payload();

        let invalid = |msg: String| io::Error::new(io::ErrorKind::InvalidData, msg);
        let Some((size, block)) = payload.split_first_chunk::<SIZE_PREFIX>() else {
            return Err(invalid("decompress failed: missing size".into()));
        };
        let size = u32::from_le_bytes(*size) as usize;
        // An LZ4 block expands at most 255 times: refuse a larger size before
        // allocating for it.
        if size > block.len().saturating_mul(255) {
            return Err(invalid(format!(
                "decompress failed: size {} too large",
                size
            )));
        }

        let total_len = HEAD_LENGTH + size;
        let mut buf = TransmissionBytes::zeroed(total_len);
        let decompressed_len = lz4rip::block::decompress_into(block, &mut buf[HEAD_LENGTH..])
            .map_err(|e| invalid(format!("decompress failed: {}", e)))?;
        if decompressed_len != size {
            return Err(invalid(format!(
                "decompress failed: {} bytes, expected {}",
                decompressed_len, size
            )));
        }

        buf[..HEAD_LENGTH].copy_from_slice(&pkt.buffer()[..HEAD_LENGTH]);

        let mut packet = NetPacket::new(buf)?;
        packet.set_compressed_flag(false);
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
    use crate::protocol::transmission::TransmissionBytes;

    fn make_packet(data: &[u8]) -> NetPacket<TransmissionBytes> {
        let mut buf = TransmissionBytes::zeroed(HEAD_LENGTH + data.len());
        buf[HEAD_LENGTH..HEAD_LENGTH + data.len()].copy_from_slice(data);
        NetPacket::new(buf).unwrap()
    }

    #[test]
    fn test_lz4_compress_and_decompress() {
        let lz = LZ4Compression::with_min_size(10);

        // --- 构造原始包 ---
        let payload = vec![1u8; 200];
        let mut original = make_packet(&payload);
        original.set_ethernet_flag(true);

        // --- 压缩 ---
        let compressed = lz.compress(original, 0).unwrap();
        assert!(compressed.is_compressed());
        assert!(compressed.is_ethernet());

        // 压缩后的 payload 应变小
        assert!(
            compressed.payload().len() < payload.len(),
            "压缩后 payload 应该更小"
        );

        // --- 解压 ---
        let decompressed = lz.decompress(compressed).unwrap();

        // 标志应清除
        assert!(!decompressed.is_compressed());
        assert!(decompressed.is_ethernet());

        // HEAD 不变
        let mut expected_head = [0u8; HEAD_LENGTH];
        expected_head[2] = 0x10;
        assert_eq!(
            &decompressed.buffer()[..HEAD_LENGTH],
            &expected_head,
            "HEAD 必须保持不变"
        );

        // payload 必须等于原始 payload
        assert_eq!(decompressed.payload(), &payload[..]);
    }

    #[test]
    fn test_no_compress_when_small() {
        let lz = LZ4Compression::with_min_size(100);

        let pkt = make_packet(&[7; 20]);
        let compressed = lz.compress(pkt, 0).unwrap();

        assert!(!compressed.is_compressed(), "小包不应该被压缩");

        assert_eq!(compressed.payload(), &[7; 20][..]);
    }

    const REQUEST: &[u8] =
        b"GET /api/v1/peers HTTP/1.1\r\nHost: 10.26.0.1\r\nAccept: application/json\r\n\r\n";

    /// `REQUEST` four times, as earlier versions compressed it with lz4_flex.
    const LZ4_FLEX_PAYLOAD: &[u8] = &[
        0x24, 0x01, 0x00, 0x00, 0xf0, 0x1a, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x61, 0x70, 0x69, 0x2f,
        0x76, 0x31, 0x2f, 0x70, 0x65, 0x65, 0x72, 0x73, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x31, 0x30, 0x2e, 0x32, 0x36,
        0x2e, 0x30, 0x11, 0x00, 0xff, 0x0d, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x61,
        0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e,
        0x0d, 0x0a, 0x0d, 0x0a, 0x49, 0x00, 0xc2, 0x60, 0x6f, 0x6e, 0x0d, 0x0a, 0x0d, 0x0a,
    ];

    fn make_compressed_packet(payload: &[u8]) -> NetPacket<TransmissionBytes> {
        let mut packet = make_packet(payload);
        packet.set_compressed_flag(true);
        packet
    }

    #[test]
    fn test_decompress_packet_from_earlier_version() {
        let lz = LZ4Compression::new();

        let decompressed = lz
            .decompress(make_compressed_packet(LZ4_FLEX_PAYLOAD))
            .unwrap();

        assert!(!decompressed.is_compressed());
        assert_eq!(decompressed.payload(), &REQUEST.repeat(4)[..]);
    }

    #[test]
    fn test_reject_wrong_decompressed_size() {
        let lz = LZ4Compression::new();

        let mut larger = LZ4_FLEX_PAYLOAD.to_vec();
        larger[0] += 1;
        assert!(lz.decompress(make_compressed_packet(&larger)).is_err());

        let mut huge = LZ4_FLEX_PAYLOAD.to_vec();
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(lz.decompress(make_compressed_packet(&huge)).is_err());
    }

    #[test]
    fn test_send_incompressible_payload_raw() {
        let lz = LZ4Compression::new();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let payload: Vec<u8> = (0..1340)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();

        let compressed = lz.compress(make_packet(&payload), 0).unwrap();

        assert!(!compressed.is_compressed());
        assert_eq!(compressed.payload(), &payload[..]);
    }
}
