use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use std::io;

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
        let compressed = lz4_flex::compress_prepend_size(payload);
        if compressed.len() >= payload.len() {
            return Ok(pkt);
        }
        let total_len = HEAD_LENGTH + compressed.len();
        let mut buf = TransmissionBytes::zeroed_size(total_len, reserve);

        buf[..HEAD_LENGTH].copy_from_slice(&pkt.buffer()[..HEAD_LENGTH]);
        buf[HEAD_LENGTH..total_len].copy_from_slice(&compressed);

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

        let decompressed = lz4_flex::decompress_size_prepended(payload).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("decompress failed: {}", e),
            )
        })?;

        let total_len = HEAD_LENGTH + decompressed.len();
        let mut buf = TransmissionBytes::zeroed(total_len);

        buf[..HEAD_LENGTH].copy_from_slice(&pkt.buffer()[..HEAD_LENGTH]);
        buf[HEAD_LENGTH..total_len].copy_from_slice(&decompressed);

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
        let original = make_packet(&payload);

        // --- 压缩 ---
        let compressed = lz.compress(original, 0).unwrap();
        assert!(compressed.is_compressed());

        // 压缩后的 payload 应变小
        assert!(
            compressed.payload().len() < payload.len(),
            "压缩后 payload 应该更小"
        );

        // --- 解压 ---
        let decompressed = lz.decompress(compressed).unwrap();

        // 标志应清除
        assert!(!decompressed.is_compressed());

        // HEAD 不变
        assert_eq!(
            &decompressed.buffer()[..HEAD_LENGTH],
            &[0u8; HEAD_LENGTH][..],
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
}
