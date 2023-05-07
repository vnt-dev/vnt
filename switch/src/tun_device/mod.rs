#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::create_tun;
#[cfg(target_os = "macos")]
pub use mac::create_tun;
#[cfg(any(unix))]
pub use unix::{TunReader, TunWriter};
#[cfg(target_os = "windows")]
pub use windows::create_tun;
#[cfg(target_os = "windows")]
pub use windows::delete_tun;
#[cfg(target_os = "windows")]
pub use windows::{TunReader, TunWriter};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod mac;
#[cfg(any(unix))]
pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows;
