#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::is_app_elevated;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::is_app_elevated;