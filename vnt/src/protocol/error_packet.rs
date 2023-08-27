use crate::error::*;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    TokenError,
    Disconnect,
    AddressExhausted,
    IpAlreadyExists,
    InvalidIp,
    NoKey,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::TokenError,
            2 => Self::Disconnect,
            3 => Self::AddressExhausted,
            4 => Self::IpAlreadyExists,
            5 => Self::InvalidIp,
            6 => Self::NoKey,
            val => Self::Other(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::TokenError => 1,
            Protocol::Disconnect => 2,
            Protocol::AddressExhausted => 3,
            Protocol::IpAlreadyExists => 4,
            Protocol::InvalidIp => 5,
            Protocol::NoKey => 6,
            Protocol::Other(val) => val,
        }
    }
}

pub enum InErrorPacket<B> {
    TokenError,
    Disconnect,
    AddressExhausted,
    IpAlreadyExists,
    InvalidIp,
    NoKey,
    OtherError(ErrorPacket<B>),
}

impl<B: AsRef<[u8]>> InErrorPacket<B> {
    pub fn new(protocol: u8, buffer: B) -> Result<InErrorPacket<B>> {
        match Protocol::from(protocol) {
            Protocol::TokenError => Ok(InErrorPacket::TokenError),
            Protocol::Disconnect => Ok(InErrorPacket::Disconnect),
            Protocol::AddressExhausted => Ok(InErrorPacket::AddressExhausted),
            Protocol::IpAlreadyExists => Ok(InErrorPacket::IpAlreadyExists),
            Protocol::InvalidIp => Ok(InErrorPacket::InvalidIp),
            Protocol::NoKey => Ok(InErrorPacket::NoKey),
            Protocol::Other(_) => Ok(InErrorPacket::OtherError(ErrorPacket::new(buffer)?)),
        }
    }
}

pub struct ErrorPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> ErrorPacket<B> {
    pub fn new(buffer: B) -> Result<ErrorPacket<B>> {
        Ok(Self { buffer })
    }
}

impl<B: AsRef<[u8]>> ErrorPacket<B> {
    pub fn message(&self) -> Result<String> {
        match String::from_utf8(self.buffer.as_ref().to_vec()) {
            Ok(str) => Ok(str),
            Err(_) => Err(Error::InvalidPacket),
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> ErrorPacket<B> {
    pub fn set_message(&mut self, message: &str) {
        self.buffer.as_mut().copy_from_slice(message.as_bytes())
    }
}
