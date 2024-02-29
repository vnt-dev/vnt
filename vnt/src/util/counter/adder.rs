use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 并发计数器，销毁计数器并不会释放计数槽，这不适用计数器会多次创建销毁的场景
pub struct U64Adder {
    inner: Arc<U64AdderInner>,
    index: Option<usize>,
}

struct U64AdderInner {
    global: AtomicU64,
    base: Vec<AtomicU64>,
}

impl U64AdderInner {
    pub fn get(&self) -> u64 {
        let mut count = self.global.load(Ordering::Relaxed);
        for counter in self.base.iter() {
            let num = counter.load(Ordering::Relaxed);
            if num > 1 {
                count = count + num - 1;
            }
        }
        count
    }
}

impl U64Adder {
    /// 计数槽容量
    pub fn with_capacity(capacity: usize) -> Self {
        let mut base = Vec::with_capacity(capacity);
        base.push(AtomicU64::new(1));
        for _ in 1..capacity {
            base.push(AtomicU64::new(0))
        }
        let inner = Arc::new(U64AdderInner {
            global: AtomicU64::new(0),
            base,
        });
        U64Adder {
            inner,
            index: Some(0),
        }
    }
    pub fn add(&mut self, num: u64) {
        if let Some(index) = self.index {
            let counter = &self.inner.base[index];
            let i = counter.load(Ordering::Relaxed);
            counter.store(i + num, Ordering::Relaxed);
        } else {
            self.inner.global.fetch_add(num, Ordering::Relaxed);
        }
    }
    pub fn get(&self) -> u64 {
        self.inner.get()
    }
    pub fn watch(&self) -> WatchU64Adder {
        WatchU64Adder {
            inner: self.inner.clone(),
        }
    }
}

impl Clone for U64Adder {
    fn clone(&self) -> Self {
        let mut index: Option<usize> = None;
        for (i, counter) in self.inner.base.iter().enumerate() {
            //占用一个空闲的计数槽
            if counter.load(Ordering::Acquire) == 0 {
                if counter
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    index = Some(i);
                    break;
                }
            }
        }

        Self {
            inner: self.inner.clone(),
            index,
        }
    }
}

#[derive(Clone)]
pub struct WatchU64Adder {
    inner: Arc<U64AdderInner>,
}

impl WatchU64Adder {
    pub fn get(&self) -> u64 {
        self.inner.get()
    }
}
