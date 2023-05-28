use crate::error::Error;

pub use p2p_channel::channel::{Route, RouteKey};

pub type Result<T> = std::result::Result<T, Error>;

pub mod error;
pub mod handle;
pub mod nat;
pub mod proto;
pub mod protocol;
pub mod tun_device;
pub mod tap_device;
pub mod ip_proxy;
pub mod external_route;
pub mod core;
