use crate::compression::Compressor;
use crate::protocol::extension::ExtensionTailPacket;
use crate::protocol::NetPacket;
use anyhow::anyhow;

pub fn handle_extension_tail<I: AsRef<[u8]> + AsMut<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
    in_net_packet: &mut NetPacket<I>,
    out: &mut NetPacket<O>,
) -> anyhow::Result<bool> {
    if in_net_packet.is_extension() {
        let tail_packet = in_net_packet.split_tail_packet()?;
        match tail_packet {
            ExtensionTailPacket::Compression(extension) => {
                let compression_algorithm = extension.algorithm();
                Compressor::decompress(compression_algorithm, &in_net_packet, out)?;
                out.head_mut().copy_from_slice(in_net_packet.head());
                Ok(true)
            }
            ExtensionTailPacket::Unknown => Err(anyhow!("Unknown decompress")),
        }
    } else {
        Ok(false)
    }
}
