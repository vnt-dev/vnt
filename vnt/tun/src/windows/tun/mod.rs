use libloading::{Error, Library};
use std::io;
use std::net::Ipv4Addr;

use rand::Rng;
use winapi::um::winbase;
use winapi::um::{synchapi, winnt};

use crate::device::IFace;
use crate::windows::decode_utf16;
use crate::windows::{encode_utf16, ffi, netsh, route};

mod packet;
mod wintun_log;
mod wintun_raw;

/// The maximum size of wintun's internal ring buffer (in bytes)
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;

/// The minimum size of wintun's internal ring buffer (in bytes)
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;

/// Maximum pool name length including zero terminator
pub const MAX_POOL: usize = 256;

pub struct Device {
    pub(crate) luid: u64,
    pub(crate) index: u32,
    /// The session handle given to us by WintunStartSession
    pub(crate) session: wintun_raw::WINTUN_SESSION_HANDLE,

    /// Shared dll for required wintun driver functions
    pub(crate) win_tun: wintun_raw::wintun,

    /// Windows event handle that is signaled by the wintun driver when data becomes available to
    /// read
    pub(crate) read_event: winnt::HANDLE,

    /// Windows event handle that is signaled when [`TunSession::shutdown`] is called force blocking
    /// readers to exit
    pub(crate) shutdown_event: winnt::HANDLE,

    /// The adapter that owns this session
    pub(crate) adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
}

unsafe impl Send for Device {}

unsafe impl Sync for Device {}

impl Device {
    pub fn new(name: String) -> io::Result<Self> {
        unsafe {
            let library = match Library::new("wintun.dll") {
                Ok(library) => library,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("wintun.dll not found {:?}", e),
                    ));
                }
            };
            let win_tun = match wintun_raw::wintun::from_library(library) {
                Ok(win_tun) => win_tun,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("library error {:?} ", e),
                    ));
                }
            };
            let name_utf16 = encode_utf16(&name);
            if name_utf16.len() > MAX_POOL {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("too long {}:{:?}", MAX_POOL, name),
                ));
            }
            wintun_log::set_default_logger_if_unset(&win_tun);
            let _ = Self::delete_for_name(&win_tun, &name_utf16);
            let mut guid_bytes: [u8; 16] = [0u8; 16];
            rand::thread_rng().fill(&mut guid_bytes);
            let guid = u128::from_ne_bytes(guid_bytes);
            //SAFETY: guid is a unique integer so transmuting either all zeroes or the user's preferred
            //guid to the winapi guid type is safe and will allow the windows kernel to see our GUID

            let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(guid) };
            let guid_ptr = &guid_struct as *const wintun_raw::GUID;

            //SAFETY: the function is loaded from the wintun dll properly, we are providing valid
            //pointers, and all the strings are correct null terminated UTF-16. This safety rationale
            //applies for all Wintun* functions below
            let adapter =
                win_tun.WintunCreateAdapter(name_utf16.as_ptr(), name_utf16.as_ptr(), guid_ptr);
            if adapter.is_null() {
                log::error!("adapter.is_null {:?}", io::Error::last_os_error());
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to crate adapter",
                ));
            }
            // 开启session
            let session = win_tun.WintunStartSession(adapter, 128 * 1024);
            if session.is_null() {
                log::error!("session.is_null {:?}", io::Error::last_os_error());
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "WintunStartSession failed",
                ));
            }
            //SAFETY: We follow the contract required by CreateEventA. See MSDN
            //(the pointers are allowed to be null, and 0 is okay for the others)
            let shutdown_event =
                synchapi::CreateEventA(std::ptr::null_mut(), 0, 0, std::ptr::null_mut());
            let read_event = win_tun.WintunGetReadWaitEvent(session) as winnt::HANDLE;
            let mut luid: wintun_raw::NET_LUID = std::mem::zeroed();
            win_tun.WintunGetAdapterLUID(adapter, &mut luid as *mut wintun_raw::NET_LUID);
            let index = ffi::luid_to_index(&std::mem::transmute(luid)).map(|index| index as u32)?;
            // 设置网卡跃点
            netsh::set_interface_metric(index, 0)?;
            Ok(Self {
                luid: std::mem::transmute(luid),
                index,
                session,
                win_tun,
                read_event,
                shutdown_event,
                adapter,
            })
        }
    }
    pub unsafe fn delete_for_name(
        win_tun: &wintun_raw::wintun,
        name_utf16: &Vec<u16>,
    ) -> io::Result<()> {
        let adapter = win_tun.WintunOpenAdapter(name_utf16.as_ptr());
        if adapter.is_null() {
            log::error!(
                "delete_for_name adapter.is_null {:?}",
                io::Error::last_os_error()
            );
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to open adapter",
            ));
        }
        win_tun.WintunCloseAdapter(adapter);
        win_tun.WintunDeleteDriver();
        Ok(())
    }
}

impl IFace for Device {
    fn version(&self) -> io::Result<String> {
        let version = unsafe { self.win_tun.WintunGetRunningDriverVersion() };
        if version == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "WintunGetRunningDriverVersion",
            ));
        } else {
            Ok(format!("{}.{}", (version >> 16) & 0xFFFF, version & 0xFFFF))
        }
    }
    fn name(&self) -> io::Result<String> {
        let luid = self.luid;
        ffi::luid_to_alias(&unsafe { std::mem::transmute(luid) }).map(|name| decode_utf16(&name))
    }

    fn shutdown(&self) -> io::Result<()> {
        unsafe {
            if 0 == synchapi::SetEvent(self.shutdown_event) {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        netsh::set_interface_ip(self.index, &address, &mask)
    }

    fn mtu(&self) -> io::Result<u32> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
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
        let packet = self.receive_blocking()?;
        let packet = packet.bytes();
        let len = packet.len();
        if len > buf.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "data too long"));
        }
        buf[..len].copy_from_slice(packet);
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut packet = self.allocate_send_packet(buf.len() as u16)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.send_packet(packet);
        Ok(buf.len())
    }
}

impl Device {
    pub fn try_receive(&self) -> io::Result<Option<packet::TunPacket>> {
        let mut size = 0u32;

        let bytes_ptr = unsafe {
            self.win_tun
                .WintunReceivePacket(self.session, &mut size as *mut u32)
        };

        debug_assert!(size <= u16::MAX as u32);
        if bytes_ptr.is_null() {
            //Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available
            let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if last_error == winapi::shared::winerror::ERROR_NO_MORE_ITEMS {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "try_receive failed"))
            }
        } else {
            Ok(Some(packet::TunPacket {
                kind: packet::Kind::ReceivePacket,
                size: size as usize,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes_ptr,
                tun_device: Some(&self),
            }))
        }
    }
    pub fn receive_blocking(&self) -> io::Result<packet::TunPacket> {
        loop {
            //Try 5 times to receive without blocking so we don't have to issue a syscall to wait
            //for the event if packets are being received at a rapid rate
            for _ in 0..5 {
                match self.try_receive()? {
                    None => {
                        continue;
                    }
                    Some(packet) => {
                        return Ok(packet);
                    }
                }
            }
            //Wait on both the read handle and the shutdown handle so that we stop when requested
            let handles = [self.read_event, self.shutdown_event];
            let result = unsafe {
                //SAFETY: We abide by the requirements of WaitForMultipleObjects, handles is a
                //pointer to valid, aligned, stack memory
                synchapi::WaitForMultipleObjects(
                    2,
                    &handles as *const winnt::HANDLE,
                    0,
                    winbase::INFINITE,
                )
            };
            match result {
                winbase::WAIT_FAILED => {
                    return Err(io::Error::new(io::ErrorKind::Other, "WAIT_FAILED"));
                }
                _ => {
                    if result == winbase::WAIT_OBJECT_0 {
                        //We have data!
                        continue;
                    } else if result == winbase::WAIT_OBJECT_0 + 1 {
                        //Shutdown event triggered
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Shutdown event triggered",
                        ));
                    }
                }
            }
        }
    }
    pub fn allocate_send_packet(&self, size: u16) -> io::Result<packet::TunPacket> {
        let bytes_ptr = unsafe {
            self.win_tun
                .WintunAllocateSendPacket(self.session, size as u32)
        };
        if bytes_ptr.is_null() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "allocate_send_packet failed",
            ))
        } else {
            Ok(packet::TunPacket {
                kind: packet::Kind::SendPacketPending,
                size: size as usize,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes_ptr,
                tun_device: None,
            })
        }
    }
    pub fn send_packet(&self, mut packet: packet::TunPacket) {
        assert!(matches!(packet.kind, packet::Kind::SendPacketPending));

        unsafe {
            self.win_tun
                .WintunSendPacket(self.session, packet.bytes_ptr)
        };
        //Mark the packet at sent
        packet.kind = packet::Kind::SendPacketSent;
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = ffi::close_handle(self.shutdown_event) {
                log::warn!("close shutdown_event={:?}", e)
            }
            self.win_tun.WintunEndSession(self.session);
            self.win_tun.WintunCloseAdapter(self.adapter);
            if 0 != self.win_tun.WintunDeleteDriver() {
                log::warn!("WintunDeleteDriver failed")
            }
        }
    }
}
