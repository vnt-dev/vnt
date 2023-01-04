//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::{ffi, io, num};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid configuration")]
    InvalidConfig,

    #[error("not implementated")]
    NotImplemented,

    #[error("device name too long")]
    NameTooLong,

    #[error("invalid device name")]
    InvalidName,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid file descriptor")]
    InvalidDescriptor,

    #[error("unsuported network layer of operation")]
    UnsupportedLayer,

    #[error("invalid queues number")]
    InvalidQueuesNumber,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Nul(#[from] ffi::NulError),

    #[error(transparent)]
    ParseNum(#[from] num::ParseIntError),
}

pub type Result<T> = ::std::result::Result<T, Error>;
