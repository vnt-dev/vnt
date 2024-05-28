#[cfg(feature = "ring-cipher")]
mod ring_chacha20_poly1305;
#[cfg(feature = "ring-cipher")]
pub use ring_chacha20_poly1305::*;

#[cfg(not(feature = "ring-cipher"))]
mod rs_chacha20_poly1305;
#[cfg(not(feature = "ring-cipher"))]
pub use rs_chacha20_poly1305::*;
