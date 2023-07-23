use std::{fmt, io};
use byteorder::{BigEndian, ReadBytesExt};
use crate::cal_checksum;
use crate::icmp::{Code, Kind};
use crate::ip::ipv4::packet::IpV4Packet;

/// icmp 协议
/*  https://www.rfc-editor.org/rfc/rfc792
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |     Code      |          Checksum             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      不同Type和Code有不同含义                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 数据体 不同Type和Code有不同含义                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

pub struct IcmpPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IcmpPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let packet = Self::unchecked(buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IcmpPacket<B> {
    pub fn set_kind(&mut self, kind: Kind) {
        self.buffer.as_mut()[0] = kind.into();
    }
    pub fn update_checksum(&mut self) {
        self.buffer.as_mut()[2..4].copy_from_slice(&[0, 0]);
        let checksum = cal_checksum(self.buffer.as_ref());
        self.buffer.as_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
}

impl<B: AsRef<[u8]>> IcmpPacket<B> {
    pub fn kind(&self) -> Kind {
        Kind::from(self.buffer.as_ref()[0])
    }
    pub fn code(&self) -> Code {
        Code::from(self.kind(), self.buffer.as_ref()[1])
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || cal_checksum(self.buffer.as_ref()) == 0
    }
    pub fn header_other(&self) -> HeaderOther {
        match self.kind() {
            Kind::EchoReply
            | Kind::EchoRequest
            | Kind::TimestampRequest
            | Kind::TimestampReply
            | Kind::InformationRequest
            | Kind::InformationReply => {
                let ide =u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap());
                let seq = u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap());
                HeaderOther::Identifier(ide, seq)
            }
            Kind::DestinationUnreachable | Kind::TimeExceeded | Kind::SourceQuench => {
                let bytes = self.buffer.as_ref();
                HeaderOther::Unused(bytes[4], bytes[5], bytes[6], bytes[7])
            }
            Kind::Redirect => {
                let bytes = self.buffer.as_ref();
                HeaderOther::Address(bytes[4], bytes[5], bytes[6], bytes[7])
            }
            Kind::ParameterProblem => HeaderOther::Pointer(self.buffer.as_ref()[4]),
            _ => {
                let bytes = self.buffer.as_ref();
                HeaderOther::UnKnown(bytes[4], bytes[5], bytes[6], bytes[7])
            }
        }
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[8..]
    }
    pub fn description(&self) -> Description<&[u8]> {
        use std::io::Cursor;
        match self.kind() {
            Kind::DestinationUnreachable
            | Kind::TimeExceeded
            | Kind::ParameterProblem
            | Kind::SourceQuench
            | Kind::Redirect => match IpV4Packet::new(self.payload()) {
                Ok(d) => Description::Ip(d),
                Err(_) => Description::Other(self.payload()),
            },
            Kind::TimestampRequest | Kind::TimestampReply => {
                let mut buffer = Cursor::new(self.payload());

                Description::Timestamp(
                    buffer.read_u32::<BigEndian>().unwrap(),
                    buffer.read_u32::<BigEndian>().unwrap(),
                    buffer.read_u32::<BigEndian>().unwrap(),
                )
            }
            _ => Description::Other(self.payload()),
        }
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IcmpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(if self.is_valid() {
            "icmp::Packet"
        } else {
            "icmp::Packet!"
        })
            .field("kind", &self.kind())
            .field("code", &self.code())
            .field("checksum", &self.checksum())
            .field("payload", &self.payload())
            .finish()
    }
}

#[derive(Debug)]
pub enum HeaderOther {
    /// 全零
    Unused(u8, u8, u8, u8),
    /// If code = 0, identifies the octet where an error was detected.
    Pointer(u8),
    /// Address of the gateway to which traffic for the network specified
    ///       in the internet destination network field of the original
    ///       datagram's data should be sent.
    Address(u8, u8, u8, u8),
    ///      Identifier          |        Sequence Number
    Identifier(u16, u16),
    UnKnown(u8, u8, u8, u8),
}

pub enum Description<B> {
    Ip(IpV4Packet<B>),
    ///时间戳  Originate Timestamp,Receive Timestamp,Transmit Timestamp
    Timestamp(u32, u32, u32),
    Other(B),
}

impl<B: AsRef<[u8]> + std::fmt::Debug> fmt::Debug for Description<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Description::Ip(packet) => f.debug_struct(&format!("{:?}", packet)).finish(),
            Description::Timestamp(originate, receive, transmit) => f
                .debug_struct("")
                .field("originate", originate)
                .field("receive", receive)
                .field("transmit", transmit)
                .finish(),
            Description::Other(bytes) => f.debug_struct(&format!("{:?}", bytes)).finish(),
        }
    }
}
