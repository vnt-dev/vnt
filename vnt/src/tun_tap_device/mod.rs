#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[cfg(feature = "inner_tun")]
pub use create_device::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[cfg(feature = "inner_tun")]
mod create_device;
#[cfg(feature = "inner_tun")]
pub mod tun_create_helper;

pub mod vnt_device;
