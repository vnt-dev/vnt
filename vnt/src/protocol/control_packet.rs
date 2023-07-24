use std::{fmt, io};
use std::net::Ipv4Addr;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// ping请求
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              time             |             echo              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    Ping,
    /// 维持连接，内容同ping
    Pong,
    /// 打洞请求
    PunchRequest,
    /// 打洞响应
    PunchResponse,
    ///获取对端看到的地址
    AddrRequest,
    AddrResponse,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Ping,
            2 => Protocol::Pong,
            3 => Protocol::PunchRequest,
            4 => Protocol::PunchResponse,
            5 => Protocol::AddrRequest,
            6 => Protocol::AddrResponse,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Ping => 1,
            Protocol::Pong => 2,
            Protocol::PunchRequest => 3,
            Protocol::PunchResponse => 4,
            Protocol::AddrRequest => 5,
            Protocol::AddrResponse => 6,
            Protocol::Unknown(val) => val,
        }
    }
}

pub enum ControlPacket<B> {
    PingPacket(PingPacket<B>),
    PongPacket(PongPacket<B>),
    PunchRequest,
    PunchResponse,
    AddrRequest,
    AddrResponse(AddrPacket<B>),
}

impl<B: AsRef<[u8]>> ControlPacket<B> {
    pub fn new(protocol: u8, buffer: B) -> io::Result<ControlPacket<B>> {
        match Protocol::from(protocol) {
            Protocol::Ping => Ok(ControlPacket::PingPacket(PingPacket::new(buffer)?)),
            Protocol::Pong => Ok(ControlPacket::PongPacket(PongPacket::new(buffer)?)),
            Protocol::PunchRequest => Ok(ControlPacket::PunchRequest),
            Protocol::PunchResponse => Ok(ControlPacket::PunchResponse),
            Protocol::AddrRequest => Ok(ControlPacket::AddrRequest),
            Protocol::AddrResponse => Ok(ControlPacket::AddrResponse(AddrPacket::new(buffer)?)),
            Protocol::Unknown(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported")),
        }
    }
}

/// 网络探针
pub struct PingPacket<B> {
    buffer: B,
}

pub type PongPacket<B> = PingPacket<B>;

impl<B: AsRef<[u8]>> PingPacket<B> {
    pub fn new(buffer: B) -> io::Result<PingPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "len != 4"));
        }
        Ok(PingPacket { buffer })
    }
}

impl<B: AsRef<[u8]>> PingPacket<B> {
    pub fn time(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[..2].try_into().unwrap())
    }
    pub fn epoch(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PingPacket<B> {
    pub fn set_time(&mut self, time: u16) {
        self.buffer.as_mut()[..2].copy_from_slice(&time.to_be_bytes())
    }
    pub fn set_epoch(&mut self, epoch: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&epoch.to_be_bytes())
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for PingPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PingPacket")
            .field("time", &self.time())
            .field("epoch", &self.epoch())
            .finish()
    }
}

pub struct AddrPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> AddrPacket<B> {
    pub fn new(buffer: B) -> io::Result<AddrPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 6 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "len != 6"));
        }
        Ok(AddrPacket { buffer })
    }
    pub fn ipv4(&self) -> Ipv4Addr {
        let buf = self.buffer.as_ref();
        Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])
    }
    pub fn port(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap())
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AddrPacket<B> {
    pub fn set_ipv4(&mut self, ip: Ipv4Addr) {
        self.buffer.as_mut()[..4].copy_from_slice(&ip.octets())
    }
    pub fn set_port(&mut self, port: u16) {
        self.buffer.as_mut()[4..6].copy_from_slice(&port.to_be_bytes())
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for AddrPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddrPacket")
            .field("ipv4", &self.ipv4())
            .field("port", &self.port())
            .finish()
    }
}
