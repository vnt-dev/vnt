#[cfg(feature = "ring-cipher")]
mod ring_aes_gcm_cipher;
#[cfg(feature = "ring-cipher")]
pub use ring_aes_gcm_cipher::*;

#[cfg(not(feature = "ring-cipher"))]
mod aes_gcm_cipher;
#[cfg(not(feature = "ring-cipher"))]
pub use aes_gcm_cipher::*;
