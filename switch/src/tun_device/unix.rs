use std::io;
use std::io::{Read, Write};

use bytes::BufMut;
use tun::platform::posix::{Reader, Writer};

pub struct TunReader(pub(crate) Reader, pub(crate) bool);

impl TunReader {
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<&mut [u8]> {
        let len = self.0.read(buf)?;
        if self.1 {
            Ok(&mut buf[4..len])
        } else {
            Ok(&mut buf[..len])
        }
    }
}

pub struct TunWriter(pub(crate) Writer, pub(crate) bool);

impl TunWriter {
    pub fn write(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.1 {
            let mut buf = Vec::<u8>::with_capacity(4 + packet.len());
            buf.put_u16(0);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            buf.put_u16(libc::PF_INET as u16);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            buf.put_u16(libc::ETH_P_IP as u16);
            buf.extend_from_slice(packet);
            self.0.write_all(&buf)
        } else {
            self.0.write_all(packet)
        }
    }
}
