use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::Thread;
use std::time::Duration;

use anyhow::anyhow;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct StopManager {
    inner: Arc<StopManagerInner>,
}

impl StopManager {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            inner: Arc::new(StopManagerInner::new(f)),
        }
    }
    pub fn add_listener<F>(&self, name: String, f: F) -> anyhow::Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        self.inner.add_listener(name, f)
    }
    pub fn stop(&self) {
        self.inner.stop();
    }
    pub fn wait(&self) {
        self.inner.wait();
    }
    pub fn wait_timeout(&self, dur: Duration) -> bool {
        self.inner.wait_timeout(dur)
    }
    pub fn is_stopped(&self) -> bool {
        self.inner.is_stopped()
    }
}

struct StopManagerInner {
    listeners: Mutex<(bool, Vec<(String, Box<dyn FnOnce() + Send>)>)>,
    park_threads: Mutex<Vec<Thread>>,
    worker_num: AtomicUsize,
    state: AtomicBool,
    stop_call: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl StopManagerInner {
    fn new<F>(f: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            listeners: Mutex::new((false, Vec::with_capacity(32))),
            park_threads: Mutex::new(Vec::with_capacity(4)),
            worker_num: AtomicUsize::new(0),
            state: AtomicBool::new(false),
            stop_call: Mutex::new(Some(Box::new(f))),
        }
    }
    fn add_listener<F>(self: &Arc<Self>, name: String, f: F) -> anyhow::Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        if name.is_empty() {
            return Err(anyhow!("name cannot be empty"));
        }
        let mut guard = self.listeners.lock();
        if guard.0 {
            return Err(anyhow!("stopped"));
        }
        for (n, _) in &guard.1 {
            if &name == n {
                return Err(anyhow!("stop add_listener {:?} name already exists", name));
            }
        }
        guard.1.push((name.clone(), Box::new(f)));
        Ok(Worker::new(name, self.clone()))
    }
    fn stop(&self) {
        self.state.store(true, Ordering::Release);
        let mut guard = self.listeners.lock();
        guard.0 = true;
        for (_name, listener) in guard.1.drain(..) {
            listener();
        }
    }
    pub fn is_stopped(&self) -> bool {
        self.worker_num.load(Ordering::Acquire) == 0
    }
    fn wait(&self) {
        {
            let mut guard = self.park_threads.lock();
            guard.push(thread::current());
            drop(guard);
        }
        loop {
            if self.worker_num.load(Ordering::Acquire) == 0 {
                return;
            }
            thread::park()
        }
    }
    fn wait_timeout(&self, dur: Duration) -> bool {
        {
            let mut guard = self.park_threads.lock();
            guard.push(thread::current());
            drop(guard);
        }
        if self.worker_num.load(Ordering::Acquire) == 0 {
            return true;
        }
        thread::park_timeout(dur);
        self.worker_num.load(Ordering::Acquire) == 0
    }
    fn stop_call(&self) {
        self.stop();
        if let Some(call) = self.stop_call.lock().take() {
            call();
        }
    }
}

pub struct Worker {
    name: String,
    inner: Arc<StopManagerInner>,
}

impl Worker {
    fn new(name: String, inner: Arc<StopManagerInner>) -> Self {
        let _ = inner.worker_num.fetch_add(1, Ordering::AcqRel);
        Self { name, inner }
    }
    fn release0(&self) {
        let inner = &self.inner;
        let worker_name = &self.name;
        {
            let mut mutex_guard = inner.listeners.lock();
            if let Some(pos) = mutex_guard
                .1
                .iter()
                .position(|(name, _)| name == worker_name)
            {
                let (_, listener) = mutex_guard.1.remove(pos);
                listener();
            }
        }

        let count = inner.worker_num.fetch_sub(1, Ordering::AcqRel);
        if count == 1 {
            for x in inner.park_threads.lock().drain(..) {
                x.unpark();
            }
            self.inner.stop_call();
        }
    }
    pub fn stop_all(self) {
        self.inner.stop()
    }
    pub fn stop_self(self) {
        drop(self)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.release0();
        log::info!("stop {}", self.name);
    }
}
