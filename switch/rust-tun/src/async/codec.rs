//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::io;

use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// A packet protocol IP version
#[derive(Debug)]
enum PacketProtocol {
    IPv4,
    IPv6,
    Other(u8),
}

// Note: the protocol in the packet information header is platform dependent.
impl PacketProtocol {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn into_pi_field(&self) -> Result<u16, io::Error> {
        match self {
            PacketProtocol::IPv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::IPv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "neither an IPv4 or IPv6 packet",
            )),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn into_pi_field(&self) -> Result<u16, io::Error> {
        match self {
            PacketProtocol::IPv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::IPv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "neither an IPv4 or IPv6 packet",
            )),
        }
    }
}

/// A Tun Packet to be sent or received on the TUN interface.
#[derive(Debug)]
pub struct TunPacket(PacketProtocol, Bytes);

/// Infer the protocol based on the first nibble in the packet buffer.
fn infer_proto(buf: &[u8]) -> PacketProtocol {
    match buf[0] >> 4 {
        4 => PacketProtocol::IPv4,
        6 => PacketProtocol::IPv6,
        p => PacketProtocol::Other(p),
    }
}

impl TunPacket {
    /// Create a new `TunPacket` based on a byte slice.
    pub fn new(bytes: Vec<u8>) -> TunPacket {
        let proto = infer_proto(&bytes);
        TunPacket(proto, Bytes::from(bytes))
    }

    /// Return this packet's bytes.
    pub fn get_bytes(&self) -> &[u8] {
        &self.1
    }

    pub fn into_bytes(self) -> Bytes {
        self.1
    }
}

/// A TunPacket Encoder/Decoder.
pub struct TunPacketCodec(bool, i32);

impl TunPacketCodec {
    /// Create a new `TunPacketCodec` specifying whether the underlying
    ///  tunnel Device has enabled the packet information header.
    pub fn new(pi: bool, mtu: i32) -> TunPacketCodec {
        TunPacketCodec(pi, mtu)
    }
}

impl Decoder for TunPacketCodec {
    type Item = TunPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut pkt = buf.split_to(buf.len());

        // reserve enough space for the next packet
        if self.0 {
            buf.reserve(self.1 as usize + 4);
        } else {
            buf.reserve(self.1 as usize);
        }

        // if the packet information is enabled we have to ignore the first 4 bytes
        if self.0 {
            let _ = pkt.split_to(4);
        }

        let proto = infer_proto(pkt.as_ref());
        Ok(Some(TunPacket(proto, pkt.freeze())))
    }
}

impl Encoder<TunPacket> for TunPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TunPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.get_bytes().len() + 4);
        match item {
            TunPacket(proto, bytes) if self.0 => {
                // build the packet information header comprising of 2 u16
                // fields: flags and protocol.
                let mut buf = Vec::<u8>::with_capacity(4);

                // flags is always 0
                buf.write_u16::<NativeEndian>(0).unwrap();
                // write the protocol as network byte order
                buf.write_u16::<NetworkEndian>(proto.into_pi_field()?)
                    .unwrap();

                dst.put_slice(&buf);
                dst.put(bytes);
            }
            TunPacket(_, bytes) => dst.put(bytes),
        }
        Ok(())
    }
}
