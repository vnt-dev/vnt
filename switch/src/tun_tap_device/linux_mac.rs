use std::io;
use std::sync::Arc;

use bytes::BufMut;
use tun::platform::posix::{Reader, Writer};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
#[cfg(any(target_os = "linux"))]
use tun::platform::linux::Device;
#[cfg(any(target_os = "macos"))]
use tun::platform::macos::Device;
use parking_lot::Mutex;
use packet::ethernet;

use packet::ethernet::packet::EthernetPacket;
#[derive(Clone)]
pub enum DeviceW {
    Tun(Writer),
    Tap((Writer, [u8; 6])),
}

impl DeviceW {
    pub fn is_tun(&self) -> bool {
        match self {
            DeviceW::Tun(_) => {
                true
            }
            DeviceW::Tap(_) => {
                false
            }
        }
    }
}

#[derive(Clone)]
pub struct DeviceWriter {
    writer: DeviceW,
    pub lock: Arc<Mutex<Device>>,
    pub in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
    packet_information: bool,
}

impl DeviceWriter {
    pub fn new(writer: DeviceW,lock: Arc<Mutex<Device>>, in_ips: Vec<(Ipv4Addr, Ipv4Addr)>, _ip: Ipv4Addr, packet_information: bool) -> Self {
        Self {
            writer,
            lock,
            in_ips,
            packet_information,
        }
    }
}

impl DeviceWriter {
    pub fn write(packet_information: bool, writer: &Writer, packet: &[u8]) -> io::Result<()> {
        if packet_information {
            let mut buf = Vec::<u8>::with_capacity(4 + packet.len());
            buf.put_u16(0);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            buf.put_u16(libc::PF_INET as u16);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            buf.put_u16(libc::ETH_P_IP as u16);
            buf.extend_from_slice(packet);
            writer.write_all(&buf)
        } else {
            writer.write_all(packet)
        }
    }
    ///tun网卡写入ipv4数据
    pub fn write_ipv4_tun(&self, buf: &[u8]) -> io::Result<()> {
        match &self.writer {
            DeviceW::Tun(writer) => {
                Self::write(self.packet_information, writer, buf)
            }
            DeviceW::Tap(_) => {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
        }
    }
    /// tap网卡写入以太网帧
    pub fn write_ethernet_tap(&self, buf: &[u8]) -> io::Result<()> {
        match &self.writer {
            DeviceW::Tun(_) => {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
            DeviceW::Tap((writer, _)) => {
                Self::write(self.packet_information, writer, buf)
            }
        }
    }
    ///写入ipv4数据，头部必须留14字节，给tap写入以太网帧头
    pub fn write_ipv4(&self, buf: &mut [u8]) -> io::Result<()> {
        match &self.writer {
            DeviceW::Tun(writer) => {
                Self::write(self.packet_information, writer, &buf[14..])
            }
            DeviceW::Tap((writer, mac)) => {
                let source_mac = [buf[14 + 12], buf[14 + 13], buf[14 + 14], buf[14 + 15], !mac[5], 234];
                let mut ethernet_packet = EthernetPacket::unchecked(buf);
                ethernet_packet.set_source(&source_mac);
                ethernet_packet.set_destination(mac);
                ethernet_packet.set_protocol(ethernet::protocol::Protocol::Ipv4);
                Self::write(self.packet_information, writer, &ethernet_packet.buffer)
            }
        }
    }
    pub fn close(&self) -> io::Result<()> {
        unsafe {
            match &self.writer {
                DeviceW::Tun(writer) => {
                    libc::close(writer.as_raw_fd());
                }
                DeviceW::Tap((writer, _)) => {
                    libc::close(writer.as_raw_fd());
                }
            }
        }
        Ok(())
    }
    pub fn is_tun(&self) -> bool {
        self.writer.is_tun()
    }
}

pub struct DeviceReader(Reader);

impl DeviceReader {
    pub fn new(device: Reader) -> Self {
        DeviceReader(device)
    }
}

impl DeviceReader {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
