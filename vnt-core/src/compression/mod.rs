use crate::compression::lz4_compression::LZ4Compression;
use crate::protocol::ip_packet_protocol::NetPacket;
use crate::protocol::transmission::TransmissionBytes;
use std::io;

mod lz4_compression;

#[derive(Clone)]
pub(crate) struct PacketCompression {
    compression: LZ4Compression,
    enabled: bool,
}

impl PacketCompression {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            compression: LZ4Compression::new(),
            enabled,
        }
    }

    pub(crate) fn compress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
        reserve: usize,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        if self.enabled {
            return self.compression.compress(pkt, reserve);
        }

        Ok(pkt)
    }

    pub(crate) fn decompress(
        &self,
        pkt: NetPacket<TransmissionBytes>,
    ) -> io::Result<NetPacket<TransmissionBytes>> {
        // Decoding is capability based, not configuration based: a peer may
        // still have compressed packets in flight when compression is turned
        // off locally.
        self.compression.decompress(pkt)
    }
}
