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
#![allow(unused_variables)]

use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::sync::Arc;

use libc;
use libc::{AF_INET, c_char, c_uint, c_void, SOCK_DGRAM, sockaddr, socklen_t};

use crate::configuration::{Configuration, Layer};
use crate::device::Device as D;
use crate::error::*;
use crate::platform::macos::sys::*;
use crate::platform::posix::{self, Fd, SockAddr};

/// A TUN device using the TUN macOS driver.
pub struct Device {
    name: String,
    queue: Queue,
    ctl: Fd,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let id = if let Some(name) = config.name.as_ref() {
            if name.len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }

            if !name.starts_with("utun") {
                return Err(Error::InvalidName);
            }

            name[4..].parse()?
        } else {
            0
        };

        if config.layer.filter(|l| *l != Layer::L3).is_some() {
            return Err(Error::UnsupportedLayer);
        }

        let queues_number = config.queues.unwrap_or(1);
        if queues_number != 1 {
            return Err(Error::InvalidQueuesNumber);
        }

        let mut device = unsafe {
            let tun = Fd::new(libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL))
                .map_err(|_| io::Error::last_os_error())?;

            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            if ctliocginfo(tun.0, &mut info as *mut _ as *mut _) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            let addr = sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            if libc::connect(
                tun.0,
                &addr as *const sockaddr_ctl as *const sockaddr,
                mem::size_of_val(&addr) as socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error().into());
            }

            let mut name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            if libc::getsockopt(
                tun.0,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut name as *mut _ as *mut c_void,
                &mut name_len as *mut socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error().into());
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))
                .map_err(|_| io::Error::last_os_error())?;

            Device {
                name: CStr::from_ptr(name.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into(),
                queue: Queue { tun: Arc::new(tun) },
                ctl: ctl,
            }
        };

        device.configure(&config)?;

        Ok(device)
    }

    /// Prepare a new request.
    pub unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            self.name.as_ptr() as *const c_char,
            req.ifrn.name.as_mut_ptr(),
            self.name.len(),
        );

        req
    }

    /// Set the IPv4 alias of the device.
    pub fn set_alias(&mut self, addr: Ipv4Addr, broadaddr: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req: ifaliasreq = mem::zeroed();
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                req.ifran.as_mut_ptr(),
                self.name.len(),
            );

            req.addr = SockAddr::from(addr).into();
            req.broadaddr = SockAddr::from(broadaddr).into();
            req.mask = SockAddr::from(mask).into();

            if siocaifaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    // /// Split the interface into a `Reader` and `Writer`.
    // pub fn split(self) -> (posix::Reader, posix::Writer) {
    //     let fd = Arc::new(self.queue.tun);
    //     (posix::Reader(fd.clone()), posix::Writer(fd.clone()))
    // }

    /// Return whether the device has packet information
    pub fn has_packet_information(&self) -> bool {
        self.queue.has_packet_information()
    }

    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.queue.set_nonblock()
    }
}

// impl Read for Device {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         self.queue.tun.read(buf)
//     }
//
//     fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
//         self.queue.tun.read_vectored(bufs)
//     }
// }
//
// impl Write for Device {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         self.queue.tun.write(buf)
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         self.queue.tun.flush()
//     }
//
//     fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
//         self.queue.tun.write_vectored(bufs)
//     }
// }

impl D for Device {
    type Queue = Queue;

    fn name(&self) -> &str {
        &self.name
    }

    // XXX: Cannot set interface name on Darwin.
    fn set_name(&mut self, value: &str) -> Result<()> {
        Err(Error::InvalidName)
    }

    fn enabled(&mut self, value: bool) -> Result<()> {
        unsafe {
            let mut req = self.request();

            if siocgifflags(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            if value {
                req.ifru.flags |= IFF_UP | IFF_RUNNING;
            } else {
                req.ifru.flags &= !IFF_UP;
            }

            if siocsifflags(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn address(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifru.addr).map(Into::into)
        }
    }

    fn set_address(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

            if siocsifaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn destination(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifdstaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifru.dstaddr).map(Into::into)
        }
    }

    fn set_destination(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.dstaddr = SockAddr::from(value).into();

            if siocsifdstaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn broadcast(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifbrdaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifru.broadaddr).map(Into::into)
        }
    }

    fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.broadaddr = SockAddr::from(value).into();

            if siocsifbrdaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn netmask(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifnetmask(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::unchecked(&req.ifru.addr).map(Into::into)
        }
    }

    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

            if siocsifnetmask(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn mtu(&self) -> Result<i32> {
        unsafe {
            let mut req = self.request();

            if siocgifmtu(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(req.ifru.mtu)
        }
    }

    fn set_mtu(&mut self, value: i32) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.mtu = value;

            if siocsifmtu(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn queue(&self, index: usize) -> Option<&Self::Queue> {
        if index > 0 {
            return None;
        }

        Some(&self.queue)
    }
}

// impl AsRawFd for Device {
//     fn as_raw_fd(&self) -> RawFd {
//         self.queue.as_raw_fd()
//     }
// }
//
// impl IntoRawFd for Device {
//     fn into_raw_fd(self) -> RawFd {
//         self.queue.into_raw_fd()
//     }
// }

pub struct Queue {
    tun: Arc<Fd>,
}

impl Queue {
    pub fn has_packet_information(&self) -> bool {
        // on macos this is always the case
        true
    }

    pub fn set_nonblock(&self) -> io::Result<()> {
        self.tun.set_nonblock()
    }

    pub fn reader(&self) -> posix::Reader {
        posix::Reader(self.tun.clone())
    }
    pub fn writer(&self) -> posix::Writer {
        posix::Writer(self.tun.clone())
    }
}

// impl AsRawFd for Queue {
//     fn as_raw_fd(&self) -> RawFd {
//         self.tun.as_raw_fd()
//     }
// }
//
// impl IntoRawFd for Queue {
//     fn into_raw_fd(self) -> RawFd {
//         self.tun.into_raw_fd()
//     }
// }

// impl Read for Queue {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         self.tun.read(buf)
//     }
//
//     fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
//         self.tun.read_vectored(bufs)
//     }
// }
//
// impl Write for Queue {
//     fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
//         self.tun.write(buf)
//     }
//
//     fn flush(&mut self) -> io::Result<()> {
//         self.tun.flush()
//     }
//
//     fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
//         self.tun.write_vectored(bufs)
//     }
// }
