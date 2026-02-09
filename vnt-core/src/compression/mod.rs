use crate::compression::lz4_compression::LZ4Compression;
use crate::protocol::ip_packet_protocol::NetPacket;
use crate::protocol::transmission::TransmissionBytes;
use std::io;

mod lz4_compression;

#[derive(Clone)]
pub(crate) struct PacketCompression {
    compression: Option<LZ4Compression>,
}

impl PacketCompression {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            compression: if enabled {
                Some(LZ4Compression::new())
            } else {
                None
            },
        }
    }

    pub(crate) fn compress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
        reserve: usize,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        if let Some(compression) = self.compression.as_ref() {
            return compression.compress(pkt, reserve);
        }

        Ok(pkt)
    }

    pub(crate) fn decompress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        if let Some(compression) = self.compression.as_ref() {
            return compression.decompress(pkt);
        }
        Ok(pkt)
    }
}
