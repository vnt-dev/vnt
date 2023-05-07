use std::{io, net, time};
use std::net::Ipv4Addr;

use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::*;
use winapi::um::winioctl::*;
use winapi::um::winnt::HANDLE;

use crate::{decode_utf16, encode_utf16, ffi, IFace, netsh, route};

mod iface;

pub struct TapDevice {
    luid: NET_LUID,
    handle: HANDLE,

}
unsafe impl Send for TapDevice{}
unsafe impl Sync for TapDevice{}

impl TapDevice {
    /// Retieve the mac of the interface
    pub fn get_mac(&self) -> io::Result<[u8; 6]> {
        let mut mac = [0; 6];

        ffi::device_io_control(
            self.handle,
            CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS),
            &(),
            &mut mac,
        )
            .map(|_| mac)
    }

    /// Retrieve the version of the driver
    pub fn get_version(&self) -> io::Result<[u32; 3]> {
        let mut version = [0; 3];

        ffi::device_io_control(
            self.handle,
            CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS),
            &(),
            &mut version,
        )
            .map(|_| version)
    }

    /// Retieve the mtu of the interface
    pub fn get_mtu(&self) -> io::Result<u32> {
        let mut mtu = 0;

        ffi::device_io_control(
            self.handle,
            CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS),
            &(),
            &mut mtu,
        )
            .map(|_| mtu)
    }


    /// Set the status of the interface, true for connected,
    /// false for disconnected.
    pub fn set_status(&self, status: bool) -> io::Result<()> {
        let status: u32 = if status { 1 } else { 0 };
        ffi::device_io_control(
            self.handle,
            CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS),
            &status,
            &mut (),
        )
    }
}

impl TapDevice {
    pub fn create() -> io::Result<Self> {
        let luid = iface::create_interface()?;
        // Even after retrieving the luid, we might need to wait
        let start = time::Instant::now();
        let handle = loop {
            // If we surpassed 2 seconds just return
            let now = time::Instant::now();
            if now - start > time::Duration::from_secs(3) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Interface timed out",
                ));
            }

            match iface::open_interface(&luid) {
                Err(_) => {
                    std::thread::yield_now();
                    continue;
                }
                Ok(handle) => break handle,
            };
        };
        Ok(Self { luid, handle })
    }

    pub fn open(name: &str) -> io::Result<Self> {
        let name = encode_utf16(name);

        let luid = ffi::alias_to_luid(&name)?;
        iface::check_interface(&luid)?;

        let handle = iface::open_interface(&luid)?;
        Ok(Self { luid, handle })
    }

    pub fn delete(self) -> io::Result<()> {
        iface::delete_interface(&self.luid)
    }
}

impl IFace for TapDevice {
    fn shutdown(&self) -> io::Result<()> {
        self.set_status(false)
    }

    fn get_index(&self) -> io::Result<u32> {
        ffi::luid_to_index(&self.luid).map(|index| index as u32)
    }

    fn get_name(&self) -> io::Result<String> {
        ffi::luid_to_alias(&self.luid).map(|name| decode_utf16(&name))
    }

    fn set_name(&self, new_name: &str) -> io::Result<()> {
        let name = self.get_name()?;
        netsh::set_interface_name(&name, new_name)
    }

    fn set_ip<IP>(&self, address: IP, mask: IP) -> io::Result<()> where IP: Into<Ipv4Addr> {
        let index = self.get_index()?;
        netsh::set_interface_ip(index, &address.into(), &mask.into())
    }

    fn add_route<IP>(&self, dest: IP, netmask: IP, gateway: IP) -> io::Result<()> where IP: Into<Ipv4Addr> {
        let index = self.get_index()?;
        route::add_route(index, dest.into(), netmask.into(), gateway.into())
    }

    fn delete_route<IP>(&self, dest: IP, netmask: IP, gateway: IP) -> io::Result<()> where IP: Into<Ipv4Addr> {
        let index = self.get_index()?;
        route::delete_route(index, dest.into(), netmask.into(), gateway.into())
    }

    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let index = self.get_index()?;
        netsh::set_interface_mtu(index, mtu)
    }
}


impl TapDevice {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        ffi::read_file(self.handle, buf).map(|res| res as _)
    }
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        ffi::write_file(self.handle, buf).map(|res| res as _)
    }
}

impl Drop for TapDevice {
    fn drop(&mut self) {
        let _ = ffi::close_handle(self.handle);
        let _ = iface::delete_interface(&self.luid);
    }
}



