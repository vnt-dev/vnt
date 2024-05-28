#[cfg(not(any(feature = "openssl-vendored", feature = "openssl")))]
mod rs_aes_ecb;
#[cfg(not(any(feature = "openssl-vendored", feature = "openssl")))]
pub use rs_aes_ecb::*;

#[cfg(any(feature = "openssl-vendored", feature = "openssl"))]
mod openssl_aes_ecb;
#[cfg(any(feature = "openssl-vendored", feature = "openssl"))]
pub use openssl_aes_ecb::*;
