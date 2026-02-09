use bytes::{Buf, Bytes, BytesMut};
use std::borrow::{Borrow, BorrowMut};
use std::io;
use std::ops::{Deref, DerefMut};

const DEFAULT_BUF_SIZE: usize = 2048;
#[derive(Clone)]
pub struct TransmissionBytes {
    buf: BytesMut,
    start: usize,
    end: usize,
}
impl From<BytesMut> for TransmissionBytes {
    fn from(buf: BytesMut) -> TransmissionBytes {
        let end = buf.len();
        Self { buf, start: 0, end }
    }
}
impl From<Bytes> for TransmissionBytes {
    fn from(buf: Bytes) -> TransmissionBytes {
        let end = buf.len();
        Self {
            buf: BytesMut::from(buf),
            start: 0,
            end,
        }
    }
}
impl From<&[u8]> for TransmissionBytes {
    fn from(buf: &[u8]) -> TransmissionBytes {
        let end = buf.len();
        Self {
            buf: BytesMut::from(buf),
            start: 0,
            end,
        }
    }
}

impl TransmissionBytes {
    pub fn new_offset(start: usize) -> Self {
        TransmissionBytes {
            buf: BytesMut::zeroed(DEFAULT_BUF_SIZE),
            start,
            end: start,
        }
    }
    pub fn new_offset_zeroed(start: usize) -> Self {
        TransmissionBytes {
            buf: BytesMut::zeroed(DEFAULT_BUF_SIZE),
            start,
            end: DEFAULT_BUF_SIZE,
        }
    }
    pub fn zeroed(cap: usize) -> Self {
        TransmissionBytes {
            buf: BytesMut::zeroed(cap),
            start: 0,
            end: cap,
        }
    }
    pub fn zeroed_size(size: usize, reserve: usize) -> Self {
        TransmissionBytes {
            buf: BytesMut::zeroed(size + reserve),
            start: 0,
            end: size,
        }
    }
    #[allow(dead_code)]
    pub fn with_capacity(head_room: usize, capacity: usize) -> Self {
        TransmissionBytes {
            buf: BytesMut::zeroed(capacity),
            start: head_room,
            end: head_room,
        }
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[allow(dead_code)]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }
    /// 头部可用空间（可向前扩展的字节数）
    #[inline]
    pub fn head_room(&self) -> usize {
        self.start
    }

    /// 尾部可用空间（可向后扩展的字节数）
    #[inline]
    #[allow(dead_code)]
    pub fn tail_room(&self) -> usize {
        self.buf.capacity() - self.end
    }
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    #[inline]
    fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }
    pub fn put(&mut self, data: &[u8]) -> io::Result<()> {
        let need = data.len();
        let free = self.buf.capacity() - self.end;

        if need > free {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("data too large:need={need},free={free}"),
            ));
        }

        self.buf[self.end..self.end + need].copy_from_slice(data);
        self.end += need;
        Ok(())
    }
    pub fn retreat_head(&mut self, len: usize) -> io::Result<()> {
        if len > self.head_room() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "retreat_head beyond start: len={len}, head_room={}",
                    self.head_room()
                ),
            ));
        }
        self.start -= len;
        Ok(())
    }
    pub fn advance_head(&mut self, len: usize) -> io::Result<()> {
        if len > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "advance_head beyond end: len={len}, data_len={}",
                    self.len()
                ),
            ));
        }
        self.start += len;
        Ok(())
    }
    pub fn set_len(&mut self, new_len: usize) -> io::Result<()> {
        let new_end = self.start + new_len;
        if new_end > self.buf.capacity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "set_len exceeds capacity: new_len={new_len}, max={}",
                    self.buf.capacity() - self.start
                ),
            ));
        }
        self.end = new_end;
        Ok(())
    }
    pub fn resize(&mut self, new_len: usize, value: u8) {
        let new_end = self.start + new_len;
        self.buf.resize(new_end, value);
        self.end = new_end;
    }
    pub fn extend_end(&mut self, n: usize) {
        if self.end + n > self.buf.len() {
            self.buf.resize(self.end + n, 0);
        }
        self.end += n;
    }
    pub fn shrink_end(&mut self, n: usize) {
        if n >= self.end - self.start {
            self.end = self.start;
        } else {
            self.end -= n;
        }
    }
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
    }
    pub fn into_bytes(mut self) -> BytesMut {
        self.buf.truncate(self.end);
        if self.start > 0 {
            self.buf.advance(self.start);
        }
        self.buf
    }
}

impl AsRef<[u8]> for TransmissionBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Deref for TransmissionBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsMut<[u8]> for TransmissionBytes {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl DerefMut for TransmissionBytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl Borrow<[u8]> for TransmissionBytes {
    fn borrow(&self) -> &[u8] {
        self.as_ref()
    }
}

impl BorrowMut<[u8]> for TransmissionBytes {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

pub trait ShrinkEnd {
    fn shrink_end(&mut self, n: usize);
}
pub trait ExtendEnd {
    fn extend_end(&mut self, n: usize);
}

impl ShrinkEnd for TransmissionBytes {
    fn shrink_end(&mut self, n: usize) {
        self.shrink_end(n);
    }
}

impl ExtendEnd for TransmissionBytes {
    fn extend_end(&mut self, n: usize) {
        self.extend_end(n);
    }
}

impl ShrinkEnd for &mut TransmissionBytes {
    fn shrink_end(&mut self, n: usize) {
        TransmissionBytes::shrink_end(self, n);
    }
}

impl ExtendEnd for &mut TransmissionBytes {
    fn extend_end(&mut self, n: usize) {
        TransmissionBytes::extend_end(self, n);
    }
}
