#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub use create_device::create_device;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod create_device;
pub mod tun_create_helper;
