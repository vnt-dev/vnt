use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;

#[derive(Clone, Default)]
pub struct U64Adder {
    count: Arc<AtomicCell<u64>>,
}

impl U64Adder {
    pub fn add(&self, num: u64) {
        self.count.fetch_add(num);
    }
    pub fn get(&self) -> u64 {
        self.count.load()
    }
    pub fn watch(&self) -> WatchU64Adder {
        WatchU64Adder {
            count: self.count.clone(),
        }
    }
}

#[derive(Clone)]
pub struct WatchU64Adder {
    count: Arc<AtomicCell<u64>>,
}

impl WatchU64Adder {
    pub fn get(&self) -> u64 {
        self.count.load()
    }
}
