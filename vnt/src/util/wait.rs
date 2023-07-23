use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
use tokio::sync::watch::{channel, Receiver, Sender};

#[derive(Clone)]
pub struct WaitGroup {
    count: Arc<AtomicIsize>,
    receiver: Receiver<usize>,
    sender: Arc<Sender<usize>>,
}

impl WaitGroup {
    pub fn new() -> Self {
        let (sender, receiver) = channel(1);
        Self {
            count: Arc::new(Default::default()),
            receiver,
            sender: Arc::new(sender),
        }
    }
    pub fn add(&self) {
        let _ = self.count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn done(&self) {
        let i = self.count.fetch_sub(1, Ordering::Relaxed);
        if i == 1 {
            let _ = self.sender.send(0);
        }
    }
    pub async fn wait(&mut self) {
        loop {
            if 0 == *self.receiver.borrow() {
                return;
            }
            if self.receiver.changed().await.is_ok() {
                if 0 == *self.receiver.borrow() {
                    return;
                }
            } else {
                return;
            }
        }
    }
}