use anyhow::anyhow;

use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct Lz4Compressor;

impl Lz4Compressor {
    pub fn compress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        out.set_data_len_max();
        let len = match lz4_flex::compress_into(in_net_packet.payload(), out.payload_mut()) {
            Ok(len) => len,
            Err(e) => Err(anyhow!("Lz4 compress {}", e))?,
        };
        out.set_payload_len(len)?;
        Ok(())
    }
    pub fn decompress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        out.set_data_len_max();
        let len = match lz4_flex::decompress_into(in_net_packet.payload(), out.payload_mut()) {
            Ok(len) => len,
            Err(e) => Err(anyhow!("Lz4 decompress {}", e))?,
        };
        out.set_payload_len(len)?;
        Ok(())
    }
}
