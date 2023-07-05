use std::sync::Arc;
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};
use crate::util::wait::WaitGroup;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SwitchStatus {
    Starting,
    Stopping,
}

pub struct SwitchWorker {
    wg: WaitGroup,
    status_s: Arc<Sender<SwitchStatus>>,
    status_r: Receiver<SwitchStatus>,
}

impl Clone for SwitchWorker {
    fn clone(&self) -> Self {
        self.wg.add();
        SwitchWorker {
            wg: self.wg.clone(),
            status_s: self.status_s.clone(),
            status_r: self.status_r.clone(),
        }
    }
}

impl Drop for SwitchWorker {
    fn drop(&mut self) {
        self.wg.done();
    }
}

impl SwitchWorker {
    pub fn stop_all(&self) {
        let _ = self.status_s.send(SwitchStatus::Stopping);
    }
    pub async fn stop_wait(&mut self) {
        loop {
            if *self.status_r.borrow() == SwitchStatus::Stopping {
                return;
            }
            match self.status_r.changed().await {
                Ok(_) => {
                    if *self.status_r.borrow() == SwitchStatus::Stopping {
                        return;
                    }
                }
                Err(_) => { return; }
            }
        }
    }
}

pub struct SwitchStatusManger {
    wg: WaitGroup,
    status_s: Arc<Sender<SwitchStatus>>,
    status_r: Receiver<SwitchStatus>,
}

impl SwitchStatusManger {
    pub fn new() -> Self {
        let (status_s, status_r) = watch::channel(SwitchStatus::Starting);
        Self {
            wg: WaitGroup::new(),
            status_s: Arc::new(status_s),
            status_r,
        }
    }
    pub fn stop_all(&self) {
        let _ = self.status_s.send(SwitchStatus::Stopping);
    }
    pub async fn wait(&mut self) {
        self.wg.wait().await
    }
    pub fn worker(&self) -> SwitchWorker {
        self.wg.add();
        SwitchWorker {
            wg: self.wg.clone(),
            status_s: self.status_s.clone(),
            status_r: self.status_r.clone(),
        }
    }
}
