use std::io;
use std::ops::Deref;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

use mio::Token;

use crate::channel::context::Context;
use crate::channel::notify::{AcceptNotify, WritableNotify};

#[derive(Clone)]
pub struct ChannelSender {
    context: Context,
}

impl ChannelSender {
    pub fn new(context: Context) -> Self {
        Self { context }
    }
}

impl Deref for ChannelSender {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}
pub struct AcceptSocketSender<T> {
    sender: SyncSender<T>,
    notify: AcceptNotify,
}

impl<T> Clone for AcceptSocketSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            notify: self.notify.clone(),
        }
    }
}
impl<T> AcceptSocketSender<T> {
    pub fn new(notify: AcceptNotify, sender: SyncSender<T>) -> Self {
        Self { sender, notify }
    }
    pub fn try_add_socket(&self, t: T) -> io::Result<()> {
        match self.sender.try_send(t) {
            Ok(_) => self.notify.add_socket(),
            Err(e) => match e {
                TrySendError::Full(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                TrySendError::Disconnected(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            },
        }
    }
}

#[derive(Clone)]
pub struct PacketSender {
    inner: Arc<PacketSenderInner>,
}

impl PacketSender {
    pub fn new(notify: WritableNotify, buffer: SyncSender<Vec<u8>>, token: Token) -> Self {
        Self {
            inner: Arc::new(PacketSenderInner {
                token,
                notify,
                buffer,
            }),
        }
    }
    #[inline]
    pub fn try_send(&self, buf: &[u8]) -> io::Result<()> {
        self.inner.try_send(buf)
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown()
    }
}

pub struct PacketSenderInner {
    token: Token,
    notify: WritableNotify,
    buffer: SyncSender<Vec<u8>>,
}

impl PacketSenderInner {
    #[inline]
    fn try_send(&self, buf: &[u8]) -> io::Result<()> {
        let len = buf.len();
        let mut buf_vec = Vec::with_capacity(buf.len() + 4);
        buf_vec.extend_from_slice(&[0, 0, (len >> 8) as u8, (len & 0xFF) as u8]);
        buf_vec.extend_from_slice(buf);
        match self.buffer.try_send(buf_vec) {
            Ok(_) => self.notify.notify(self.token, true),
            Err(e) => match e {
                TrySendError::Disconnected(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
                TrySendError::Full(_) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            },
        }
    }
    fn shutdown(&self) -> io::Result<()> {
        self.notify.notify(self.token, false)
    }
}
