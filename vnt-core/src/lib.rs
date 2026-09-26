pub(crate) mod compression;
pub mod context;
pub mod core;
pub mod crypto;
pub(crate) mod ethernet;
pub(crate) mod event_script;
pub(crate) mod fec;
pub mod log_manager;
pub mod managed_config;
pub mod nat;
pub mod network_info;
pub mod protocol;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
mod system_subnet_routes;
pub mod tls;
pub(crate) mod tun;
pub mod tunnel_core;
pub mod utils;

pub mod api;
pub(crate) mod enhanced_tunnel;
pub mod port_mapping;
pub(crate) mod runtime_config;

#[cfg(feature = "internal-bench")]
#[doc(hidden)]
pub mod internal_bench {
    pub use crate::tunnel_core::p2p::route_table::{Route, RouteTable};
}
