pub mod tun_handler;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::sync::Arc;
mod platform;

pub(crate) use platform::*;

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
