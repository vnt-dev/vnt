#[cfg(feature = "ring-cipher")]
mod ring_cipher;
#[cfg(feature = "ring-cipher")]
pub use ring_cipher::Cipher;
#[cfg(not(feature = "ring-cipher"))]
mod aes_gcm_cipher;
#[cfg(not(feature = "ring-cipher"))]
pub use aes_gcm_cipher::Cipher;