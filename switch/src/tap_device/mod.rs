#[cfg(target_os = "windows")]
mod windows;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
pub use mac::{TapWriter, TapReader};
#[cfg(target_os = "macos")]
pub use mac::create_tap;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::{TapWriter, TapReader};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::create_tap;
#[cfg(target_os = "windows")]
pub use windows::create_tap;
#[cfg(target_os = "windows")]
pub use windows::delete_tap;
#[cfg(target_os = "windows")]
pub use windows::{TapReader, TapWriter};