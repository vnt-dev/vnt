pub const VNT_VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub mod channel;
pub mod cipher;
pub mod core;
mod external_route;
pub mod handle;
#[cfg(feature = "ip_proxy")]
mod ip_proxy;
pub mod nat;
#[cfg(feature = "port_mapping")]
mod port_mapping;
mod proto;
pub mod protocol;
mod tun_tap_device;
pub use tun_tap_device::*;
pub mod util;

pub use handle::callback::*;

pub mod compression;
pub use packet;

pub(crate) fn ignore_io_interrupted(e: std::io::Error) -> std::io::Result<()> {
    if e.kind() == std::io::ErrorKind::Interrupted {
        log::warn!("ignore_io_interrupted");
        Ok(())
    } else {
        Err(e)
    }
}
