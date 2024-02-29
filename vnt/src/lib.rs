pub const VNT_VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub mod channel;
pub mod cipher;
pub mod core;
pub mod external_route;
pub mod handle;
#[cfg(feature = "ip_proxy")]
pub mod ip_proxy;
pub mod nat;
pub mod proto;
pub mod protocol;
pub mod tun_tap_device;
pub mod util;

pub use handle::callback::{DeviceInfo, ErrorInfo, HandshakeInfo, RegisterInfo, VntCallback};
