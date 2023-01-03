use std::io;

use crossbeam::channel::RecvError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("packet error")]
    PacketError(#[from] packet::error::Error),
    #[error("Io error")]
    Io(#[from] io::Error),
    #[error("Channel error")]
    Channel(#[from] RecvError),
    #[error("Protobuf error")]
    Protobuf(#[from] protobuf::Error),
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Not support")]
    NotSupport,
    #[error("Stop")]
    Stop(String),
}

pub type Result<T> = std::result::Result<T, Error>;
