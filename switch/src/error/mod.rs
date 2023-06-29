use std::io;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Io error")]
    Io(#[from] io::Error),
    #[error("Protobuf error")]
    Protobuf(#[from] protobuf::Error),
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Not support")]
    NotSupport,
    #[error("Stop")]
    Stop(String),
    #[error("Warn")]
    Warn(String),
}

pub type Result<T> = std::result::Result<T, Error>;
