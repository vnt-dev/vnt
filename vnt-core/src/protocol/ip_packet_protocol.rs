/*
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | 1 |    msg_type(7)  |max ttl(4) |curr ttl(4)| C | G | F | E |        reserve(12)             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                            seq(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         src ID(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         dest ID(32)                                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         payload(n)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#![allow(dead_code)]
use crate::protocol::transmission::TransmissionBytes;
use bytes::{Bytes, BytesMut};
use std::io;
use zerocopy::byteorder::{NetworkEndian, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

#[derive(Debug, FromBytes, IntoBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C)]
pub struct NetHeader {
    /// Byte 0: bit7 = 1, bit0..6 = msg_type
    pub type_byte: u8,
    /// Byte 1: high 4 = max ttl, low 4 = curr ttl
    pub ttl_byte: u8,
    /// Byte 2: C(0x80) | G(0x40) | F(0x20) | ETHERNET(0x10) | reserve
    pub flags_byte: u8,
    /// Byte 3: reserve
    pub _reserved: u8,

    pub seq: U32<NetworkEndian>,
    pub src_id: U32<NetworkEndian>,
    pub dest_id: U32<NetworkEndian>,
}
const COMPRESSED: u8 = 0x80;
const GATEWAY: u8 = 0x40;
const FEC: u8 = 0x20;
const ETHERNET: u8 = 0x10;
impl NetHeader {
    #[inline]
    pub fn msg_type(&self) -> u8 {
        self.type_byte & 0x7F
    }

    #[inline]
    pub fn set_msg_type(&mut self, msg_type: u8) {
        self.type_byte = (msg_type & 0x7F) | 0x80;
    }

    #[inline]
    pub fn max_ttl(&self) -> u8 {
        self.ttl_byte >> 4
    }

    #[inline]
    pub fn curr_ttl(&self) -> u8 {
        self.ttl_byte & 0x0F
    }

    #[inline]
    pub fn set_ttl(&mut self, max: u8, curr: u8) {
        self.ttl_byte = (max << 4) | (curr & 0x0F);
    }

    #[inline]
    pub fn decr_ttl(&mut self) {
        let curr = self.curr_ttl();
        if curr == 0 {
            return;
        }
        self.ttl_byte = (self.ttl_byte & 0xF0) | (curr - 1);
    }

    fn set_flag(&mut self, mask: u8, val: bool) {
        if val {
            self.flags_byte |= mask;
        } else {
            self.flags_byte &= !mask;
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MsgType {
    Turn = 1,
    Broadcast = 2,
    ExcludeBroadcast = 3,
    TargetBroadcast = 4,

    Ping = 5,
    Pong = 6,
    PingTurn = 7,
    PongTurn = 8,

    PunchStart1 = 9,
    PunchStart2 = 10,
    PunchReq = 11,
    PunchRes = 12,

    PushClientIps = 13,

    RpcReq = 14,
    RpcRes = 15,

    Quic = 17,
    RelayProbe = 18,
    RelayProbeReply = 19,
}
impl From<MsgType> for u8 {
    fn from(val: MsgType) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for MsgType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let val = match value {
            1 => MsgType::Turn,
            2 => MsgType::Broadcast,
            3 => MsgType::ExcludeBroadcast,
            4 => MsgType::TargetBroadcast,

            5 => MsgType::Ping,
            6 => MsgType::Pong,
            7 => MsgType::PingTurn,
            8 => MsgType::PongTurn,

            9 => MsgType::PunchStart1,
            10 => MsgType::PunchStart2,
            11 => MsgType::PunchReq,
            12 => MsgType::PunchRes,

            13 => MsgType::PushClientIps,

            14 => MsgType::RpcReq,
            15 => MsgType::RpcRes,

            17 => MsgType::Quic,
            18 => MsgType::RelayProbe,
            19 => MsgType::RelayProbeReply,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid msg type:{value}"),
                ));
            }
        };
        Ok(val)
    }
}

pub const HEAD_LENGTH: usize = std::mem::size_of::<NetHeader>();

pub struct NetPacket<B> {
    buffer: B,
}
impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn new(buffer: B) -> io::Result<NetPacket<B>> {
        if buffer.as_ref().len() < HEAD_LENGTH {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(NetPacket { buffer })
    }
    fn header(&self) -> Ref<&[u8], NetHeader> {
        // Safe: NetHeader is Unaligned and length is validated in new()
        let (header, _) = Ref::<&[u8], NetHeader>::from_prefix(self.buffer.as_ref()).unwrap();
        header
    }
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    pub fn into_buffer(self) -> B {
        self.buffer
    }
    pub fn source_buf(&self) -> &B {
        &self.buffer
    }
    pub fn msg_type(&self) -> io::Result<MsgType> {
        self.header().msg_type().try_into()
    }
    pub fn max_ttl(&self) -> u8 {
        self.header().max_ttl()
    }
    pub fn ttl(&self) -> u8 {
        self.header().curr_ttl()
    }

    pub fn seq(&self) -> u32 {
        self.header().seq.get()
    }

    pub fn src_id(&self) -> u32 {
        self.header().src_id.get()
    }

    pub fn dest_id(&self) -> u32 {
        self.header().dest_id.get()
    }
    pub fn is_compressed(&self) -> bool {
        (self.header().flags_byte & COMPRESSED) != 0
    }
    pub fn is_gateway(&self) -> bool {
        (self.header().flags_byte & GATEWAY) != 0
    }
    pub fn is_fec(&self) -> bool {
        (self.header().flags_byte & FEC) != 0
    }
    pub fn is_ethernet(&self) -> bool {
        (self.header().flags_byte & ETHERNET) != 0
    }
    pub fn head(&self) -> &[u8] {
        &self.buffer.as_ref()[..HEAD_LENGTH]
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[HEAD_LENGTH..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> NetPacket<B> {
    fn header_mut(&mut self) -> Ref<&mut [u8], NetHeader> {
        // Safe: NetHeader is Unaligned and length is validated in new()
        let (header, _) = Ref::<&mut [u8], NetHeader>::from_prefix(self.buffer.as_mut()).unwrap();
        header
    }

    pub fn set_msg_type(&mut self, msg_type: MsgType) {
        self.header_mut().set_msg_type(msg_type.into());
    }

    pub fn decr_ttl(&mut self) {
        self.header_mut().decr_ttl()
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.header_mut().set_ttl(ttl, ttl);
    }

    pub fn set_seq(&mut self, seq: u32) {
        self.header_mut().seq.set(seq);
    }

    pub fn set_src_id(&mut self, id: u32) {
        self.header_mut().src_id.set(id);
    }

    pub fn set_dest_id(&mut self, id: u32) {
        self.header_mut().dest_id.set(id);
    }

    pub fn set_compressed_flag(&mut self, compressed: bool) {
        self.header_mut().set_flag(COMPRESSED, compressed);
    }
    pub fn set_gateway_flag(&mut self, gateway: bool) {
        self.header_mut().set_flag(GATEWAY, gateway);
    }
    pub fn set_fec_flag(&mut self, fec: bool) {
        self.header_mut().set_flag(FEC, fec);
    }
    pub fn set_ethernet_flag(&mut self, ethernet: bool) {
        self.header_mut().set_flag(ETHERNET, ethernet);
    }

    pub fn set_payload(&mut self, data: &[u8]) -> io::Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < HEAD_LENGTH + data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid message length",
            ));
        }
        buf[HEAD_LENGTH..HEAD_LENGTH + data.len()].copy_from_slice(data);
        Ok(())
    }
    pub fn head_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..HEAD_LENGTH]
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[HEAD_LENGTH..]
    }
    pub fn source_buf_mut(&mut self) -> &mut B {
        &mut self.buffer
    }
}

impl Clone for NetPacket<Bytes> {
    fn clone(&self) -> Self {
        NetPacket {
            buffer: self.buffer.clone(),
        }
    }
}

impl NetPacket<BytesMut> {
    pub fn into_bytes(self) -> NetPacket<Bytes> {
        NetPacket {
            buffer: self.buffer.freeze(),
        }
    }
}

impl NetPacket<TransmissionBytes> {
    pub fn into_bytes(self) -> NetPacket<Bytes> {
        NetPacket {
            buffer: self.buffer.into_bytes().freeze(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_round_trip() {
        let all = [
            MsgType::Turn,
            MsgType::Broadcast,
            MsgType::ExcludeBroadcast,
            MsgType::TargetBroadcast,
            MsgType::Ping,
            MsgType::Pong,
            MsgType::PingTurn,
            MsgType::PongTurn,
            MsgType::PunchStart1,
            MsgType::PunchStart2,
            MsgType::PunchReq,
            MsgType::PunchRes,
            MsgType::PushClientIps,
            MsgType::RpcReq,
            MsgType::RpcRes,
            MsgType::Quic,
            MsgType::RelayProbe,
            MsgType::RelayProbeReply,
        ];
        for msg_type in all {
            let byte = u8::from(msg_type);
            assert_eq!(
                MsgType::try_from(byte).unwrap(),
                msg_type,
                "round trip failed for {msg_type:?} ({byte})"
            );
        }
        // 未分配的取值必须报错
        assert!(MsgType::try_from(0u8).is_err());
        assert!(MsgType::try_from(16u8).is_err());
        assert!(MsgType::try_from(20u8).is_err());
    }

    #[test]
    fn ethernet_flag_round_trip() {
        let mut packet = NetPacket::new(BytesMut::from(&[0u8; HEAD_LENGTH][..])).unwrap();
        assert!(!packet.is_ethernet());
        packet.set_ethernet_flag(true);
        assert!(packet.is_ethernet());
        packet.set_fec_flag(true);
        assert!(packet.is_ethernet());
        packet.set_ethernet_flag(false);
        assert!(!packet.is_ethernet());
        assert!(packet.is_fec());
    }

    /// 中继转发语义：包每经过一跳 curr_ttl 减 1，curr_ttl >= 1 时才继续转发，
    /// 接收方以 metric = max_ttl - curr_ttl 计算路由距离。
    #[test]
    fn relay_reply_survives_one_hop() {
        let mut packet = NetPacket::new(BytesMut::from(&[0u8; HEAD_LENGTH][..])).unwrap();
        packet.set_msg_type(MsgType::RelayProbeReply);
        // 目标方回复时 TTL 必须允许一次中继
        packet.set_ttl(2);

        // 中继节点：decr 后 curr_ttl == 1，满足转发条件 ttl >= 1
        packet.decr_ttl();
        assert_eq!(packet.ttl(), 1);
        assert!(packet.ttl() >= 1, "relay node would drop this packet");

        // 发起方：decr 后 curr_ttl == 0，metric = 2（经由一个中继）
        packet.decr_ttl();
        assert_eq!(packet.ttl(), 0);
        assert_eq!(packet.max_ttl() - packet.ttl(), 2);
    }
}
