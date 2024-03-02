use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 不安全的并发计数器，谨慎使用

pub struct U64Adder {
    global_index: Arc<AtomicUsize>,
    inner: Arc<U64AdderInner>,
    index: usize,
}
pub struct SingleU64Adder {
    inner: Arc<SingleU64AdderInner>,
}
impl SingleU64Adder {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SingleU64AdderInner::new()),
        }
    }
    pub fn add(&mut self, num: u64) {
        self.inner.add(num);
    }
    pub fn get(&self) -> u64 {
        self.inner.get()
    }
    pub fn watch(&self) -> WatchSingleU64Adder {
        WatchSingleU64Adder {
            inner: self.inner.clone(),
        }
    }
}

struct SingleU64AdderInner {
    ptr: *mut u64,
}

impl SingleU64AdderInner {
    fn new() -> Self {
        Self {
            ptr: Box::into_raw(Box::new(0)),
        }
    }
    #[inline(always)]
    fn add(&self, num: u64) {
        unsafe { *self.ptr += num }
    }

    fn get(&self) -> u64 {
        unsafe { *self.ptr }
    }
}
impl Drop for SingleU64AdderInner {
    fn drop(&mut self) {
        unsafe {
            let _ = Box::from_raw(self.ptr);
        }
    }
}

unsafe impl Send for SingleU64AdderInner {}

unsafe impl Sync for SingleU64AdderInner {}

struct U64AdderInner {
    base: Vec<SingleU64AdderInner>,
}

impl U64AdderInner {
    pub fn get(&self) -> u64 {
        let mut count = 0;
        for counter in self.base.iter() {
            count += counter.get()
        }
        count
    }
}

impl U64Adder {
    /// 计数槽容量
    pub fn with_capacity(capacity: usize) -> Self {
        let mut base = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            base.push(SingleU64AdderInner::new())
        }
        let inner = Arc::new(U64AdderInner { base });
        U64Adder {
            global_index: Arc::new(AtomicUsize::new(1)),
            inner,
            index: 0,
        }
    }
    pub fn add(&mut self, num: u64) {
        self.inner.base[self.index].add(num);
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
        let index = self.global_index.fetch_add(1, Ordering::AcqRel);
        if index > self.inner.base.len() {
            panic!()
        }

        Self {
            global_index: self.global_index.clone(),
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
#[derive(Clone)]
pub struct WatchSingleU64Adder {
    inner: Arc<SingleU64AdderInner>,
}
impl WatchSingleU64Adder {
    pub fn get(&self) -> u64 {
        self.inner.get()
    }
}
