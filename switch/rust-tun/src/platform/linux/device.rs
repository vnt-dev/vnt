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

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::sync::Arc;
use std::vec::Vec;

use libc;
use libc::{c_char, c_short};
use libc::{AF_INET, O_RDWR, SOCK_DGRAM};

use crate::configuration::{Configuration, Layer};
use crate::device::Device as D;
use crate::error::*;
use crate::platform::linux::sys::*;
use crate::platform::posix::{self, Fd, SockAddr};

/// A TUN device using the TUN/TAP Linux driver.
pub struct Device {
    name: String,
    queues: Vec<Queue>,
    ctl: Fd,
}

impl Device {
    /// Create a new `Device` for the given `Configuration`.
    pub fn new(config: &Configuration) -> Result<Self> {
        let mut device = unsafe {
            let dev = match config.name.as_ref() {
                Some(name) => {
                    let name = CString::new(name.clone())?;

                    if name.as_bytes_with_nul().len() > IFNAMSIZ {
                        return Err(Error::NameTooLong);
                    }

                    Some(name)
                }

                None => None,
            };

            let mut queues = Vec::new();

            let mut req: ifreq = mem::zeroed();

            if let Some(dev) = dev.as_ref() {
                ptr::copy_nonoverlapping(
                    dev.as_ptr() as *const c_char,
                    req.ifrn.name.as_mut_ptr(),
                    dev.as_bytes().len(),
                );
            }

            let device_type: c_short = config.layer.unwrap_or(Layer::L3).into();

            let queues_num = config.queues.unwrap_or(1);
            if queues_num < 1 {
                return Err(Error::InvalidQueuesNumber);
            }

            req.ifru.flags = device_type
                | if config.platform.packet_information {
                0
            } else {
                IFF_NO_PI
            }
                | if queues_num > 1 { IFF_MULTI_QUEUE } else { 0 };

            for _ in 0..queues_num {
                let tun = Fd::new(libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR))
                    .map_err(|_| io::Error::last_os_error())?;

                if tunsetiff(tun.0, &mut req as *mut _ as *mut _) < 0 {
                    return Err(io::Error::last_os_error().into());
                }

                queues.push(Queue {
                    tun: Arc::new(tun),
                    pi_enabled: config.platform.packet_information,
                });
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))
                .map_err(|_| io::Error::last_os_error())?;

            Device {
                name: CStr::from_ptr(req.ifrn.name.as_ptr())
                    .to_string_lossy()
                    .into(),
                queues,
                ctl,
            }
        };

        device.configure(config)?;

        Ok(device)
    }

    /// Prepare a new request.
    unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            self.name.as_ptr() as *const c_char,
            req.ifrn.name.as_mut_ptr(),
            self.name.len(),
        );

        req
    }

    // /// Make the device persistent.
    // pub fn persist(&mut self) -> Result<()> {
    //     unsafe {
    //         if tunsetpersist(self.as_raw_fd(), &1) < 0 {
    //             Err(io::Error::last_os_error().into())
    //         } else {
    //             Ok(())
    //         }
    //     }
    // }

    // /// Set the owner of the device.
    // pub fn user(&mut self, value: i32) -> Result<()> {
    //     unsafe {
    //         if tunsetowner(self.as_raw_fd(), &value) < 0 {
    //             Err(io::Error::last_os_error().into())
    //         } else {
    //             Ok(())
    //         }
    //     }
    // }
    //
    // /// Set the group of the device.
    // pub fn group(&mut self, value: i32) -> Result<()> {
    //     unsafe {
    //         if tunsetgroup(self.as_raw_fd(), &value) < 0 {
    //             Err(io::Error::last_os_error().into())
    //         } else {
    //             Ok(())
    //         }
    //     }
    // }
    /// Return whether the device has packet information
    pub fn has_packet_information(&self) -> bool {
        self.queues[0].has_packet_information()
    }

    /// Set non-blocking mode
    pub fn set_nonblock(&self) -> io::Result<()> {
        self.queues[0].set_nonblock()
    }
}

impl D for Device {
    type Queue = Queue;

    fn name(&self) -> &str {
        &self.name
    }

    fn set_name(&mut self, value: &str) -> Result<()> {
        unsafe {
            let name = CString::new(value)?;

            if name.as_bytes_with_nul().len() > IFNAMSIZ {
                return Err(Error::NameTooLong);
            }

            let mut req = self.request();
            ptr::copy_nonoverlapping(
                name.as_ptr() as *const c_char,
                req.ifru.newname.as_mut_ptr(),
                value.len(),
            );

            if siocsifname(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            self.name = value.into();

            Ok(())
        }
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

            SockAddr::new(&req.ifru.netmask).map(Into::into)
        }
    }

    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.netmask = SockAddr::from(value).into();

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
        self.queues.get(index)
    }
}

pub struct Queue {
    tun: Arc<Fd>,
    pi_enabled: bool,
}

impl Queue {
    pub fn has_packet_information(&self) -> bool {
        self.pi_enabled
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

impl From<Layer> for c_short {
    fn from(layer: Layer) -> Self {
        match layer {
            Layer::L2 => IFF_TAP,
            Layer::L3 => IFF_TUN,
        }
    }
}
