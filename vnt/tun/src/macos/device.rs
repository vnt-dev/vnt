use std::ffi::{c_void, CStr};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::{io, mem, ptr};

use libc::{
    c_char, c_short, c_uint, sockaddr, socklen_t, AF_INET, AF_SYSTEM, AF_SYS_CONTROL, IFF_RUNNING,
    IFF_UP, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};

use crate::device::IFace;
use crate::macos::route;
use crate::macos::sys::*;
use crate::unix::{Fd, SockAddr};

pub struct Device {
    name: String,
    ctl: Fd,
    tun: Fd,
}

impl Device {
    pub fn new(name: Option<String>) -> io::Result<Self> {
        let id = if let Some(name) = name {
            if name.len() > IFNAMSIZ {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
            }

            if !name.starts_with("utun") {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid name"));
            }

            name[4..]
                .parse::<u32>()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                + 1u32
        } else {
            0u32
        };
        let device = unsafe {
            let tun = Fd::new(libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL))?;

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
                return Err(io::Error::last_os_error());
            }

            let addr = sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            let address = &addr as *const sockaddr_ctl as *const sockaddr;
            if libc::connect(tun.0, address, mem::size_of_val(&addr) as socklen_t) < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            let optval = &mut name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(tun.0, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(io::Error::last_os_error());
            }

            let ctl = Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))?;

            Device {
                name: CStr::from_ptr(name.as_ptr() as *const c_char)
                    .to_string_lossy()
                    .into(),
                tun,
                ctl,
            }
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
                req.ifru.flags |= (IFF_UP | IFF_RUNNING) as c_short;
            } else {
                req.ifru.flags &= !(IFF_UP as c_short);
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
            req.ifrn.name.as_mut_ptr(),
            self.name.len(),
        );
        req
    }
    fn address(&self) -> io::Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.addr).map(Into::into)
        }
    }

    fn set_address(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

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

            SockAddr::new(&req.ifru.dstaddr).map(Into::into)
        }
    }

    fn set_destination(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.dstaddr = SockAddr::from(value).into();

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

            SockAddr::new(&req.ifru.broadaddr).map(Into::into)
        }
    }

    fn set_broadcast(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.broadaddr = SockAddr::from(value).into();

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

            SockAddr::unchecked(&req.ifru.addr).map(Into::into)
        }
    }

    fn set_netmask(&self, value: Ipv4Addr) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.addr = SockAddr::from(value).into();

            if siocsifnetmask(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
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
        self.enabled(false)
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

            Ok(req.ifru.mtu as _)
        }
    }

    fn set_mtu(&self, value: u32) -> io::Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifru.mtu = value as _;

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
