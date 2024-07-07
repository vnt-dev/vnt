#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[cfg(feature = "integrated_tun")]
pub use create_device::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[cfg(feature = "integrated_tun")]
mod create_device;
#[cfg(feature = "integrated_tun")]
pub mod tun_create_helper;

pub mod vnt_device;
