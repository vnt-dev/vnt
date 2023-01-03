
#[cfg(any(unix))]
pub use unix::create_tun;
#[cfg(any(unix))]
pub use unix::{TunReader, TunWriter};

#[cfg(any(unix))]
pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::create_tun;
#[cfg(target_os = "windows")]
pub use windows::{TunReader, TunWriter};
