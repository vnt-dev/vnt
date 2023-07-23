use std::{fmt, io};
use crate::ethernet::protocol::Protocol;

/// 以太网帧协议
/// https://www.ietf.org/rfc/rfc894.txt
/*
   0                      6                      12    14 (字节)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        目的地址         |         源地址         | 类型 |
 */
pub struct EthernetPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> EthernetPacket<B> {
    pub fn unchecked(buffer: B) -> EthernetPacket<B> {
        EthernetPacket { buffer }
    }

    pub fn new(buffer: B) -> io::Result<EthernetPacket<B>> {
        let packet = EthernetPacket::unchecked(buffer);
        //头部固定14位
        if packet.buffer.as_ref().len() < 14 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }

        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> EthernetPacket<B> {
    /// 目的MAC地址
    pub fn destination(&self) -> &[u8] {
        &self.buffer.as_ref()[0..6]
    }
    /// 源MAC地址
    pub fn source(&self) -> &[u8] {
        &self.buffer.as_ref()[6..12]
    }
    /// 3层协议
    pub fn protocol(&self) -> Protocol {
        u16::from_be_bytes(self.buffer.as_ref()[12..14].try_into().unwrap()).into()
    }
    /// 载荷
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[14..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> EthernetPacket<B> {
    pub fn set_destination(&mut self, value: &[u8]) {
        self.buffer.as_mut()[0..6].copy_from_slice(value);
    }

    pub fn set_source(&mut self, value: &[u8]) {
        self.buffer.as_mut()[6..12].copy_from_slice(value);
    }

    pub fn set_protocol(&mut self, value: Protocol) {
        let p: u16 = value.into();
        self.buffer.as_mut()[12..14].copy_from_slice(&p.to_be_bytes())
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[14..]
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for EthernetPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthernetPacket")
            .field("destination", &self.destination())
            .field("source", &self.source())
            .field("protocol", &self.protocol())
            .field("payload", &self.payload())
            .finish()
    }
}