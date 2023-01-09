use std::fmt;
use std::net::Ipv4Addr;

use crate::error::*;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    Ping,
    Pong,
    PunchRequest,
    PunchResponse,
    UnKnow(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Ping,
            2 => Protocol::Pong,
            3 => Protocol::PunchRequest,
            4 => Protocol::PunchResponse,
            val => Protocol::UnKnow(val),
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
            Protocol::UnKnow(val) => val,
        }
    }
}

pub enum ControlPacket<B> {
    PingPacket(PingPacket<B>),
    PongPacket(PongPacket<B>),
    PunchRequest(PunchRequestPacket<B>),
    PunchResponse(PunchResponsePacket<B>),
}

impl<B: AsRef<[u8]>> ControlPacket<B> {
    pub fn new(protocol: u8, buffer: B) -> Result<ControlPacket<B>> {
        match Protocol::from(protocol) {
            Protocol::Ping => Ok(ControlPacket::PingPacket(PingPacket::new(buffer)?)),
            Protocol::Pong => Ok(ControlPacket::PongPacket(PongPacket::new(buffer)?)),
            Protocol::PunchRequest => Ok(ControlPacket::PunchRequest(PunchRequestPacket::new(
                buffer,
            )?)),
            Protocol::PunchResponse => Ok(ControlPacket::PunchResponse(PunchResponsePacket::new(
                buffer,
            )?)),
            Protocol::UnKnow(_) => Err(Error::NotSupport),
        }
    }
}

/// 网络探针
#[derive(Copy, Clone)]
pub struct PingPacket<B> {
    buffer: B,
}

#[derive(Copy, Clone)]
pub struct PongPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> PingPacket<B> {
    pub fn new(buffer: B) -> Result<PingPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 8 + 4 {
            return Err(Error::InvalidPacket);
        }
        Ok(PingPacket { buffer })
    }
}

impl<B: AsRef<[u8]>> PingPacket<B> {
    pub fn time(&self) -> i64 {
        i64::from_be_bytes(self.buffer.as_ref()[..8].try_into().unwrap())
    }
    pub fn epoch(&self) -> u32 {
        u32::from_be_bytes(self.buffer.as_ref()[8..12].try_into().unwrap())
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PingPacket<B> {
    pub fn set_time(&mut self, time: i64) {
        self.buffer.as_mut()[..8].copy_from_slice(&time.to_be_bytes())
    }
    pub fn set_epoch(&mut self, epoch: u32) {
        self.buffer.as_mut()[8..12].copy_from_slice(&epoch.to_be_bytes())
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

impl<B: AsRef<[u8]>> PongPacket<B> {
    pub fn new(buffer: B) -> Result<PongPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 8 {
            return Err(Error::InvalidPacket);
        }
        Ok(PongPacket { buffer })
    }
}

impl<B: AsRef<[u8]>> PongPacket<B> {
    pub fn time(&self) -> i64 {
        i64::from_be_bytes(self.buffer.as_ref()[..8].try_into().unwrap())
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PongPacket<B> {
    pub fn set_time(&mut self, time: i64) {
        self.buffer.as_mut()[..8].copy_from_slice(&time.to_be_bytes())
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for PongPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PongPacket")
            .field("time", &self.time())
            .finish()
    }
}

pub type TurnPongPacket<B> = TurnPingPacket<B>;

/// 探测目标延迟
#[derive(Copy, Clone)]
pub struct TurnPingPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> TurnPingPacket<B> {
    pub fn new(buffer: B) -> Result<TurnPingPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 16 {
            return Err(Error::InvalidPacket);
        }
        Ok(TurnPingPacket { buffer })
    }
}

impl<B: AsRef<[u8]>> TurnPingPacket<B> {
    // pub fn source(&self) -> Ipv4Addr {
    //     let tmp:[u8;4] = self.buffer.as_ref()[..4].try_into().unwrap();
    //     Ipv4Addr::from(tmp)
    // }
    // pub fn destination(&self) -> Ipv4Addr {
    //     let tmp:[u8;4] = self.buffer.as_ref()[4..8].try_into().unwrap();
    //     Ipv4Addr::from(tmp)
    // }
    pub fn time(&self) -> i64 {
        i64::from_be_bytes(self.buffer.as_ref()[8..].try_into().unwrap())
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> TurnPingPacket<B> {
    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.buffer.as_mut()[..4].copy_from_slice(&source.octets());
    }
    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.buffer.as_mut()[4..8].copy_from_slice(&destination.octets());
    }
    pub fn set_time(&mut self, time: i64) {
        self.buffer.as_mut()[8..].copy_from_slice(&time.to_be_bytes())
    }
}

pub type PunchResponsePacket<B> = PunchPacket<B>;
pub type PunchRequestPacket<B> = PunchPacket<B>;

/// nat穿透
#[derive(Clone)]
pub struct PunchPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> PunchPacket<B> {
    pub fn new(buffer: B) -> Result<PunchPacket<B>> {
        let len = buffer.as_ref().len();
        if len != 8 {
            return Err(Error::InvalidPacket);
        }
        Ok(Self { buffer })
    }
}

impl<B: AsRef<[u8]>> PunchPacket<B> {
    pub fn source(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[..4].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PunchPacket<B> {
    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.buffer.as_mut()[..4].copy_from_slice(&source.octets());
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for PunchPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PunchPacket")
            .field("source", &self.source())
            .finish()
    }
}
