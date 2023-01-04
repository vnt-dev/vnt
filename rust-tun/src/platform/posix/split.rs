//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use crate::platform::posix::Fd;
use libc;

/// Read-only end for a file descriptor.
pub struct Reader(pub(crate) Arc<Fd>);

/// Write-only end for a file descriptor.
pub struct Writer(pub(crate) Arc<Fd>);

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let amount = libc::read(self.0.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len());

            if amount < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(amount as usize)
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            // msg.msg_name: NULL
            // msg.msg_namelen: 0
            msg.msg_iov = bufs.as_mut_ptr().cast();
            msg.msg_iovlen = bufs.len().min(libc::c_int::MAX as usize) as _;

            let n = libc::recvmsg(self.0.as_raw_fd(), &mut msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(n as usize)
        }
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let amount = libc::write(self.0.as_raw_fd(), buf.as_ptr() as *const _, buf.len());

            if amount < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(amount as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        unsafe {
            let mut msg: libc::msghdr = mem::zeroed();
            // msg.msg_name = NULL
            // msg.msg_namelen = 0
            msg.msg_iov = bufs.as_ptr() as *mut _;
            msg.msg_iovlen = bufs.len().min(libc::c_int::MAX as usize) as _;

            let n = libc::sendmsg(self.0.as_raw_fd(), &msg, 0);
            if n < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(n as usize)
        }
    }
}

impl AsRawFd for Reader {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsRawFd for Writer {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
