use crate::error::Error;
pub const VNT_VERSION:&'static str = "1.2.1";
pub type Result<T> = std::result::Result<T, Error>;

pub mod error;
pub mod handle;
pub mod nat;
pub mod proto;
pub mod protocol;
pub mod ip_proxy;
pub mod external_route;
pub mod igmp_server;
pub mod tun_tap_device;
pub mod core;
pub mod channel;
pub mod util;
pub mod cipher;
