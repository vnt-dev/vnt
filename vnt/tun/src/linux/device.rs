#![allow(dead_code)]
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::{io, mem, ptr};

use libc::{
    c_char, c_short, ifreq, AF_INET, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_RUNNING, IFF_TUN, IFF_UP,
    IFNAMSIZ, O_RDWR, SOCK_DGRAM,
};

use crate::device::IFace;
use crate::linux::route;
use crate::linux::sys::*;
use crate::unix::{exe_cmd, Fd, SockAddr};

pub struct Device {
    name: String,
    ctl: Fd,
    tun: Fd,
}

impl Device {
    pub fn new(name: Option<String>) -> io::Result<Self> {
        let device = unsafe {
            let dev = match name {
                Some(name) => {
                    let name =
                        CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                    if name.as_bytes_with_nul().len() > IFNAMSIZ {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
                    }

                    Some(name)
                }

                None => None,
            };

            let mut req: ifreq = mem::zeroed();

            if let Some(dev) = dev.as_ref() {
                ptr::copy_nonoverlapping(
                    dev.as_ptr() as *const c_char,
                    req.ifr_name.as_mut_ptr(),
                    dev.as_bytes().len(),
                );
            }

            let device_type: c_short = IFF_TUN as c_short; //if tap { IFF_TAP } else { IFF_TUN } as c_short;

            let queues_num = 1;

            let iff_no_pi = IFF_NO_PI as c_short;
            let iff_multi_queue = IFF_MULTI_QUEUE as c_short;
            let packet_information = false;
            req.ifr_ifru.ifru_flags = device_type
                | if packet_information { 0 } else { iff_no_pi }
                | if queues_num > 1 { iff_multi_queue } else { 0 };

            let tun = Fd::new(libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR))
                .map_err(|_| io::Error::last_os_error())?;

            if tunsetiff(tun.0, &mut req as *mut _ as *mut _) < 0 {
                return Err(io::Error::last_os_error());
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))?;

            let name = CStr::from_ptr(req.ifr_name.as_ptr())
                .to_string_lossy()
                .to_string();
            let set_txqueuelen = format!("ifconfig {} txqueuelen 1000", name);
            if let Err(e) = exe_cmd(&set_txqueuelen) {
                log::warn!("{:?}", e);
            }
            Device { name, tun, ctl }
        };
        device.enabled(true)?;
        Ok(device)
    }
}

impl Device {
    fn enabled(&self, value: bool) -> io::Result<()> {
        unsafe {
            let mut req = self.request();

            if siocgifflags(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            if value {
                req.ifr_ifru.ifru_flags |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifr_ifru.ifru_flags &= !(IFF_UP as c_short);
            }

            if siocsifflags(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }
    unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(
            self.name.as_ptr() as *const c_char,
            req.ifr_name.as_mut_ptr(),
            self.name.len(),
        );
        req
    }
    fn address(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifr_ifru.ifru_addr).map(Into::into)
        }
    }

    fn set_address(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_addr = SockAddr::from(value).into();

            if siocsifaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    fn destination(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifdstaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifr_ifru.ifru_dstaddr).map(Into::into)
        }
    }

    fn set_destination(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_dstaddr = SockAddr::from(value).into();

            if siocsifdstaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    fn broadcast(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifbrdaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifr_ifru.ifru_broadaddr).map(Into::into)
        }
    }

    fn set_broadcast(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_broadaddr = SockAddr::from(value).into();

            if siocsifbrdaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    fn netmask(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifnetmask(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifr_ifru.ifru_netmask).map(Into::into)
        }
    }

    fn set_netmask(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_netmask = SockAddr::from(value).into();

            if siocsifnetmask(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }
}

impl Device {
    pub fn as_tun_fd(&self) -> &Fd {
        &self.tun
    }
}

impl IFace for Device {
    fn version(&self) -> io::Result<String> {
        Ok(String::new())
    }

    fn name(&self) -> io::Result<String> {
        Ok(self.name.clone())
    }

    fn shutdown(&self) -> io::Result<()> {
        exe_cmd(&format!("ip link delete {}", self.name))?;
        Ok(())
    }
    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        self.set_address(address)?;
        self.set_netmask(mask)
    }

    fn mtu(&self) -> io::Result<u32> {
        unsafe {
            let mut req = self.request();

            if siocgifmtu(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(req.ifr_ifru.ifru_mtu as u32)
        }
    }

    fn set_mtu(&self, value: u32) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_mtu = value as _;

            if siocsifmtu(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, _metric: u16) -> io::Result<()> {
        route::add_route(&self.name, dest, netmask)
    }

    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        route::del_route(&self.name, dest, netmask)
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.read(buf)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.write(buf)
    }
}
