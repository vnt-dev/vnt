use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("the buffer is too small")]
    SmallBuffer,

    #[error("the packet is invalid")]
    InvalidPacket,
    #[error("Unimplemented")]
    Unimplemented,
    // #[error("the vaue is invalid for the field")]
    // InvalidValue,
    //
    // #[error("the value has already been defined")]
    // AlreadyDefined,
    //
    // #[error(transparent)]
    // Io(#[from] io::Error),
    //
    // #[error(transparent)]
    // Nul(#[from] ffi::NulError),
}

pub type Result<T> = ::std::result::Result<T, Error>;
