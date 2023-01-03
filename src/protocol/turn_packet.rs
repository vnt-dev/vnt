use std::fmt;
use std::net::Ipv4Addr;

use crate::error::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Protocol {
    Punch,
    UnKnow(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Punch,
            val => Protocol::UnKnow(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Punch => 1,
            Protocol::UnKnow(val) => val,
        }
    }
}

pub struct TurnPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> TurnPacket<B> {
    pub fn new(buffer: B) -> Result<TurnPacket<B>> {
        let len = buffer.as_ref().len();
        if len <= 8 {
            return Err(Error::InvalidPacket);
        }
        Ok(Self { buffer })
    }
}

impl<B: AsRef<[u8]>> TurnPacket<B> {
    pub fn source(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[..4].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
    pub fn destination(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[4..8].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[8..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> TurnPacket<B> {
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[8..]
    }
    pub fn set_source(&mut self, source: Ipv4Addr) {
        self.buffer.as_mut()[..4].copy_from_slice(&source.octets());
    }
    pub fn set_destination(&mut self, destination: Ipv4Addr) {
        self.buffer.as_mut()[4..8].copy_from_slice(&destination.octets());
    }
    pub fn set_payload(&mut self, payload: &[u8]) {
        self.buffer.as_mut()[8..payload.len() + 8].copy_from_slice(payload)
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for TurnPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnPacket")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("payload", &self.payload())
            .finish()
    }
}
