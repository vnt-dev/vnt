#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(any(unix))]
pub mod unix;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::create_device;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::delete_device;
#[cfg(any(unix))]
pub use unix::{DeviceWriter, DeviceReader};

#[cfg(target_os = "macos")]
pub use mac::create_device;
#[cfg(target_os = "macos")]
pub use mac::delete_device;

#[cfg(target_os = "windows")]
pub use windows::create_device;
#[cfg(target_os = "windows")]
pub use windows::delete_device;
#[cfg(target_os = "windows")]
pub use windows::{DeviceWriter, DeviceReader};

pub enum DeviceType {
    Tun,
    Tap,
}