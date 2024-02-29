use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::Thread;
use std::{io, thread};

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
    pub fn add_listener<F>(&self, name: String, f: F) -> io::Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        self.inner.add_listener(name, f)
    }
    pub fn stop(&self) {
        self.inner.stop("");
    }
    pub fn wait(&self) {
        self.inner.wait();
    }
    pub fn is_stop(&self) -> bool {
        self.inner.state.load(Ordering::Acquire)
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
    fn add_listener<F>(self: &Arc<Self>, name: String, f: F) -> io::Result<Worker>
    where
        F: FnOnce() + Send + 'static,
    {
        if name.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "name cannot be empty"));
        }
        let mut guard = self.listeners.lock();
        if guard.0 {
            return Err(io::Error::new(io::ErrorKind::Other, "stopped"));
        }
        for (n, _) in &guard.1 {
            if &name == n {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("stop add_listener {:?} name already exists", name),
                ));
            }
        }
        guard.1.push((name.clone(), Box::new(f)));
        Ok(Worker::new(name, self.clone()))
    }
    fn stop(&self, skip_name: &str) {
        self.state.store(true, Ordering::Release);
        let mut guard = self.listeners.lock();
        guard.0 = true;
        for (name, listener) in guard.1.drain(..) {
            if &name == skip_name {
                continue;
            }
            listener();
        }
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
    fn stop_call(&self) {
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
        let count = inner.worker_num.fetch_sub(1, Ordering::AcqRel);
        if count == 1 {
            for x in inner.park_threads.lock().drain(..) {
                x.unpark();
            }
            self.inner.stop_call();
        }
    }
    pub fn stop_all(self) {
        self.inner.stop(&self.name)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.release0();
        log::info!("stop {}", self.name);
    }
}
