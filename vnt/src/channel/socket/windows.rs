use std::mem;
use std::os::windows::io::AsRawSocket;

use windows_sys::core::PCSTR;
use windows_sys::Win32::Networking::WinSock::{
    htonl, setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR,
};

use crate::channel::socket::{LocalInterface, VntSocketTrait};

impl VntSocketTrait for socket2::Socket {
    fn set_ip_unicast_if(&self, interface: &LocalInterface) -> anyhow::Result<()> {
        let index = interface.index;
        if index == 0 {
            return Ok(());
        }
        let raw_socket = self.as_raw_socket();
        let result = unsafe {
            let best_interface = htonl(index);
            setsockopt(
                raw_socket as usize,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &best_interface as *const _ as PCSTR,
                mem::size_of_val(&best_interface) as i32,
            )
        };
        if result == SOCKET_ERROR {
            Err(anyhow::anyhow!(
                "Failed to set IP_UNICAST_IF: {:?} {}",
                std::io::Error::last_os_error(),
                index
            ))?;
        }
        Ok(())
    }
}

// pub fn get_best_interface(dest_ip: Ipv4Addr) -> anyhow::Result<LocalInterface> {
//     // 获取最佳接口
//     let index = unsafe {
//         let mut dest: SOCKADDR_IN = mem::zeroed();
//         dest.sin_family = AF_INET as u16;
//         dest.sin_addr.S_un.S_addr = u32::from_ne_bytes(dest_ip.octets());
//
//         let mut index: u32 = 0;
//         if GetBestInterfaceEx(&dest as *const _ as *mut SOCKADDR, &mut index) != 0 {
//             Err(anyhow::anyhow!(
//                 "Failed to GetBestInterfaceEx: {:?}",
//                 std::io::Error::last_os_error()
//             ))?;
//         }
//         index
//     };
//     Ok(LocalInterface { index })
// }
