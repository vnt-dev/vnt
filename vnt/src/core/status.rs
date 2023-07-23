use std::sync::Arc;
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};
use crate::util::wait::WaitGroup;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum VntStatus {
    Starting,
    Stopping,
}

pub struct VntWorker {
    _name: String,
    wg: WaitGroup,
    status_s: Arc<Sender<VntStatus>>,
    status_r: Receiver<VntStatus>,
}

impl VntWorker {
    pub fn worker(&self, name: &str) -> Self {
        self.wg.add();
        VntWorker {
            _name: name.to_string(),
            wg: self.wg.clone(),
            status_s: self.status_s.clone(),
            status_r: self.status_r.clone(),
        }
    }
}

impl Drop for VntWorker {
    fn drop(&mut self) {
        self.wg.done();
    }
}

impl VntWorker {
    pub fn stop_all(&self) {
        let _ = self.status_s.send(VntStatus::Stopping);
    }
    pub async fn stop_wait(&mut self) {
        loop {
            if *self.status_r.borrow() == VntStatus::Stopping {
                return;
            }
            match self.status_r.changed().await {
                Ok(_) => {
                    if *self.status_r.borrow() == VntStatus::Stopping {
                        return;
                    }
                }
                Err(_) => { return; }
            }
        }
    }
}

#[derive(Clone)]
pub struct VntStatusManger {
    wg: WaitGroup,
    status_s: Arc<Sender<VntStatus>>,
    status_r: Receiver<VntStatus>,
}

impl VntStatusManger {
    pub fn new() -> Self {
        let (status_s, status_r) = watch::channel(VntStatus::Starting);
        Self {
            wg: WaitGroup::new(),
            status_s: Arc::new(status_s),
            status_r,
        }
    }
    pub fn stop_all(&self) {
        let _ = self.status_s.send(VntStatus::Stopping);
    }
    pub async fn wait(&mut self) {
        self.wg.wait().await
    }
    pub fn worker(&self, name: &str) -> VntWorker {
        self.wg.add();
        VntWorker {
            _name: name.to_string(),
            wg: self.wg.clone(),
            status_s: self.status_s.clone(),
            status_r: self.status_r.clone(),
        }
    }
}
