use std::io;
use std::os::unix::io::RawFd;

#[derive(Clone)]
pub struct DeviceWriter(RawFd);

pub struct DeviceReader(RawFd);

impl DeviceWriter {
    pub fn write_ipv4_tun(&self, buf: &[u8]) -> io::Result<()> {
        unsafe {
            let amount = libc::write(self.0, buf.as_ptr() as *const _, buf.len());
            if amount < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    ///写入ipv4数据，为了兼容其他代码，头部空了14个字节
    pub fn write_ipv4(&self, buf: &[u8]) -> io::Result<()> {
        let buf = &buf[14..];
        self.write_ipv4_tun(buf)
    }
    pub fn close(&self) -> io::Result<()> {
        // unsafe {
        //     libc::close(self.0);
        // }
        Ok(())
    }
}

impl DeviceReader {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let amount = libc::read(self.0, buf.as_mut_ptr() as *mut _, buf.len());

            if amount < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(amount as usize)
        }
    }
}

pub fn create(fd: i32) -> (DeviceWriter, DeviceReader) {
    (DeviceWriter(fd as _), DeviceReader(fd as _))
}