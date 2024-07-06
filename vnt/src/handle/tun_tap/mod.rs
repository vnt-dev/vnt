pub mod tun_handler;

#[cfg(unix)]
mod unix;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::sync::Arc;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub(crate) use windows::*;

/// 仅仅是停止tun，不停止vnt
#[derive(Clone, Default)]
pub struct DeviceStop {
    f: Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>,
    stopped: Arc<AtomicCell<bool>>,
}

impl DeviceStop {
    pub fn set_stop_fn<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.f.lock().replace(Box::new(f));
    }
    pub fn stop(&self) {
        if let Some(f) = self.f.lock().take() {
            f()
        }
    }
    pub fn stopped(&self) {
        self.stopped.store(true);
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped.load()
    }
}
