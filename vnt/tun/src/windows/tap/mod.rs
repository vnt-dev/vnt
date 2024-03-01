use std::io;
use std::net::Ipv4Addr;
use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::OPEN_EXISTING;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winioctl::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE, HANDLE,
};

use crate::device::IFace;
use crate::packet;
use crate::packet::ethernet::protocol::Protocol;
use crate::packet::{arp, ethernet};
use crate::windows::{ctl_code, decode_utf16, encode_utf16, ffi, netsh, route};

/* Present in 8.1 */
const TAP_WIN_IOCTL_GET_MAC: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_GET_VERSION: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_GET_MTU: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_GET_INFO: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_SET_MEDIA_STATUS: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_CONFIG_DHCP_MASQ: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_GET_LOG_LINE: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
const TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
/* Added in 8.2 */
/* obsoletes TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT */
const TAP_WIN_IOCTL_CONFIG_TUN: DWORD =
    ctl_code(FILE_DEVICE_UNKNOWN, 10, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub struct Device {
    handle: HANDLE,
    index: u32,
    luid: NET_LUID,
    mac: [u8; 6],
}

unsafe impl Send for Device {}

unsafe impl Sync for Device {}

impl Device {
    /// 打开设备，设置为TUN模式，激活网卡
    pub fn new(name: String) -> io::Result<Self> {
        let luid = ffi::alias_to_luid(&encode_utf16(&name)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("alias_to_luid name={},err={:?}", name, e),
            )
        })?;
        let guid = ffi::luid_to_guid(&luid)
            .and_then(|guid| ffi::string_from_guid(&guid))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("luid_to_guid name={},err={:?}", name, e),
                )
            })?;
        let path = format!(r"\\.\Global\{}.tap", decode_utf16(&guid));
        let handle = ffi::create_file(
            &encode_utf16(&path),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("tap name={},err={:?}", name, e)))?;

        // ep保存tun网卡的IP地址和掩码
        // let mut ep = [0;3];
        // ep[0] = Ipv4Addr::new(10,26,0,11).into();
        // ep[2] = Ipv4Addr::new(255,255,255,0).into();;
        // ep[1] = ep[0] & ep[2];
        // //tun模式收不到ipv4包，原因未知 https://github.com/OpenVPN/tap-windows6/issues/111
        // ffi::device_io_control(handle, TAP_WIN_IOCTL_CONFIG_TUN, &ep, &mut ()).map_err(
        //     |e| {
        //         io::Error::new(
        //             e.kind(),
        //             format!("TAP_WIN_IOCTL_CONFIG_TUN name={},err={:?}", name_str, e),
        //         )
        //     },
        // )?;
        let mut mac = [0u8; 6];
        ffi::device_io_control(handle, TAP_WIN_IOCTL_GET_MAC, &(), &mut mac)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("TAP_WIN_IOCTL_CONFIG_TUN name={},err={:?}", name, e),
                )
            })
            .map_err(|e| io::Error::new(e.kind(), format!("TAP_WIN_IOCTL_GET_MAC,err={:?}", e)))?;
        let index = ffi::luid_to_index(&luid).map(|index| index as u32)?;
        // 设置网卡跃点
        netsh::set_interface_metric(index, 0)?;
        let device = Self {
            handle,
            index,
            luid,
            mac,
        };
        device.enabled(true)?;
        Ok(device)
    }
    fn write_tap(&self, buf: &[u8]) -> io::Result<usize> {
        ffi::write_file(self.handle, buf).map(|res| res as _)
    }
    fn enabled(&self, value: bool) -> io::Result<()> {
        let status: u32 = if value { 1 } else { 0 };
        ffi::device_io_control(
            self.handle,
            TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status,
            &mut (),
        )
    }
}

const MAC: [u8; 6] = [0xf, 0xf, 0xf, 0xf, 0xe, 0x9];

impl IFace for Device {
    fn version(&self) -> io::Result<String> {
        let mut version = [0u32; 3];
        ffi::device_io_control(self.handle, TAP_WIN_IOCTL_GET_VERSION, &(), &mut version)?;
        Ok(format!("{}.{}.{}", version[0], version[1], version[2]))
    }
    fn name(&self) -> io::Result<String> {
        ffi::luid_to_alias(&self.luid).map(|name| decode_utf16(&name))
    }

    fn shutdown(&self) -> io::Result<()> {
        self.enabled(false)
    }

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        netsh::set_interface_ip(self.index, &address, &mask)
    }

    fn mtu(&self) -> io::Result<u32> {
        let mut mtu = 0;
        ffi::device_io_control(self.handle, TAP_WIN_IOCTL_GET_MTU, &(), &mut mtu).map(|_| mtu)
    }

    fn set_mtu(&self, value: u32) -> io::Result<()> {
        netsh::set_interface_mtu(self.index, value)
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> io::Result<()> {
        route::add_route(self.index, dest, netmask, Ipv4Addr::UNSPECIFIED, metric)?;
        netsh::delete_cache()
    }

    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        route::delete_route(self.index, dest, netmask, Ipv4Addr::UNSPECIFIED)?;
        netsh::delete_cache()
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        packet::read_tap(
            buf,
            |eth_buf| ffi::read_file(self.handle, eth_buf).map(|res| res as usize),
            |eth_buf| ffi::write_file(self.handle, eth_buf).map(|res| res as _),
        )
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        // 封装二层数据
        packet::write_tap(
            buf,
            |eth_buf| ffi::write_file(self.handle, eth_buf).map(|res| res as _),
            &self.mac,
        )
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Err(e) = ffi::close_handle(self.handle) {
            log::warn!("close_handle={:?}", e)
        }
    }
}
