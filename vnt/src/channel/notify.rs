use mio::{Token, Waker};
use parking_lot::Mutex;
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct WritableNotify {
    inner: Arc<WritableNotifyInner>,
}

impl WritableNotify {
    pub fn new(waker: Waker) -> Self {
        Self {
            inner: Arc::new(WritableNotifyInner {
                waker,
                state: AtomicUsize::new(0),
                tokens: Mutex::new(Vec::with_capacity(8)),
            }),
        }
    }
}

impl Deref for WritableNotify {
    type Target = WritableNotifyInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct WritableNotifyInner {
    waker: Waker,
    state: AtomicUsize,
    tokens: Mutex<Vec<(Token, bool)>>,
}

impl WritableNotifyInner {
    pub fn notify(&self, token: Token, state: bool) -> io::Result<()> {
        {
            let mut guard = self.tokens.lock();
            if guard.is_empty() || !guard.contains(&(token, state)) {
                guard.push((token, state));
            }
            drop(guard);
        }
        self.need_write()
    }

    pub fn stop(&self) -> io::Result<()> {
        self.state.store(0b001, Ordering::Release);
        self.waker.wake()
    }
    pub fn need_write(&self) -> io::Result<()> {
        self.state.fetch_or(0b010, Ordering::AcqRel);
        self.waker.wake()
    }
    pub fn add_socket(&self) -> io::Result<()> {
        self.state.fetch_or(0b100, Ordering::AcqRel);
        self.waker.wake()
    }
    pub fn take_all(&self) -> Option<Vec<(Token, bool)>> {
        let mut guard = self.tokens.lock();
        if guard.is_empty() {
            None
        } else {
            Some(guard.drain(..).collect())
        }
    }
    pub fn is_stop(&self) -> bool {
        self.state.load(Ordering::Acquire) & 0b001 == 0b001
    }
    pub fn is_need_write(&self) -> bool {
        self.state.fetch_and(!0b010, Ordering::AcqRel) & 0b010 == 0b010
    }
    pub fn is_add_socket(&self) -> bool {
        self.state.fetch_and(!0b100, Ordering::AcqRel) & 0b100 == 0b100
    }
}

#[derive(Clone)]
pub struct AcceptNotify {
    inner: Arc<AcceptNotifyInner>,
}

impl AcceptNotify {
    pub fn new(waker: Waker) -> Self {
        Self {
            inner: Arc::new(AcceptNotifyInner {
                waker,
                state: AtomicUsize::new(0),
            }),
        }
    }
}

impl Deref for AcceptNotify {
    type Target = AcceptNotifyInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct AcceptNotifyInner {
    waker: Waker,
    state: AtomicUsize,
}

impl AcceptNotifyInner {
    pub fn is_stop(&self) -> bool {
        self.state.load(Ordering::Acquire) & 0b001 == 0b001
    }
    pub fn is_add_socket(&self) -> bool {
        self.state.fetch_and(!0b100, Ordering::AcqRel) & 0b100 == 0b100
    }
    pub fn stop(&self) -> io::Result<()> {
        self.state.store(0b001, Ordering::Release);
        self.waker.wake()
    }
    pub fn add_socket(&self) -> io::Result<()> {
        self.state.fetch_or(0b100, Ordering::AcqRel);
        self.waker.wake()
    }
}
