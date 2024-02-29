/// 参考
/// https://github.com/meh/rust-tun
/// https://github.com/Tazdevil971/tap-windows
/// https://github.com/nulldotblack/wintun
pub mod device;
mod packet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Device;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::Device;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Device;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Fd;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::Device;
