use crate::protocol::NetPacket;
use anyhow::anyhow;
use zstd::zstd_safe::CompressionLevel;

#[derive(Clone)]
pub struct ZstdCompressor;

impl ZstdCompressor {
    pub fn compress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        compression_level: CompressionLevel,
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        out.set_data_len_max();
        let len = match zstd::zstd_safe::compress(
            out.payload_mut(),
            in_net_packet.payload(),
            compression_level,
        ) {
            Ok(len) => len,
            Err(e) => Err(anyhow!("zstd compress {}", e))?,
        };
        out.set_payload_len(len)?;
        Ok(())
    }
    pub fn decompress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        out.set_data_len_max();
        let len = match zstd::zstd_safe::decompress(out.payload_mut(), in_net_packet.payload()) {
            Ok(len) => len,
            Err(e) => Err(anyhow!("zstd decompress {}", e))?,
        };
        out.set_payload_len(len)?;
        Ok(())
    }
}
