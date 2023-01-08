use std::fmt;

use crate::error::*;

pub mod control_packet;
pub mod error_packet;
pub mod service_packet;
pub mod turn_packet;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Version {
    V1,
    UnKnow(u8),
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            1 => Version::V1,
            val => Version::UnKnow(val),
        }
    }
}

impl Into<u8> for Version {
    fn into(self) -> u8 {
        match self {
            Version::V1 => 1,
            Version::UnKnow(val) => val,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 服务包 用于和服务端交互
    Service,
    /// 响应异常
    Error,
    /// 控制协议
    Control,
    /// 转发ipv4数据
    Ipv4Turn,
    OtherTurn,
    UnKnow(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Service,
            2 => Protocol::Error,
            3 => Protocol::Control,
            4 => Protocol::Ipv4Turn,
            5 => Protocol::OtherTurn,
            val => Protocol::UnKnow(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Service => 1,
            Protocol::Error => 2,
            Protocol::Control => 3,
            Protocol::Ipv4Turn => 4,
            Protocol::OtherTurn => 5,
            Protocol::UnKnow(val) => val,
        }
    }
}

#[derive(Copy, Clone)]
pub struct NetPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn new(buffer: B) -> Result<NetPacket<B>> {
        let len = buffer.as_ref().len();
        // 不能大于udp最大载荷长度
        if len < 4 || len > 65535 - 20 - 8 {
            return Err(Error::InvalidPacket);
        }
        Ok(NetPacket { buffer })
    }
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    pub fn into_buffer(self) -> B {
        self.buffer
    }
}

impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn version(&self) -> Version {
        Version::from(self.buffer.as_ref()[0])
    }
    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.buffer.as_ref()[1])
    }
    pub fn transport_protocol(&self) -> u8 {
        self.buffer.as_ref()[2]
    }
    pub fn ttl(&self) -> u8 {
        self.buffer.as_ref()[3]
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[4..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> NetPacket<B> {
    pub fn set_version(&mut self, version: Version) {
        self.buffer.as_mut()[0] = version.into();
    }
    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.buffer.as_mut()[1] = protocol.into();
    }
    pub fn set_transport_protocol(&mut self, transport_protocol: u8) {
        self.buffer.as_mut()[2] = transport_protocol;
    }
    pub fn set_ttl(&mut self, ttl: u8) {
        self.buffer.as_mut()[3] = ttl;
    }
    pub fn set_payload(&mut self, payload: &[u8]) {
        self.buffer.as_mut()[4..payload.len() + 4].copy_from_slice(payload);
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[4..]
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for NetPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPacket")
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("transport_protocol", &self.transport_protocol())
            .field("ttl", &self.ttl())
            .field("payload", &self.payload())
            .finish()
    }
}
