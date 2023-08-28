use std::{io, thread};
use std::sync::Arc;
use byte_pool::BytePool;

use crossbeam_utils::atomic::AtomicCell;

use packet::icmp::Kind;
use packet::icmp::icmp::IcmpPacket;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::core::status::VntWorker;

use crate::error::*;
use crate::external_route::ExternalRoute;
use crate::handle::CurrentDeviceInfo;
use crate::handle::tun_tap::channel_group::{buf_channel_group, BufSenderGroup};
use crate::igmp_server::IgmpServer;
use crate::ip_proxy::IpProxyMap;
use crate::tun_tap_device::{DeviceReader, DeviceWriter};
lazy_static::lazy_static! {
    static ref POOL:BytePool<Vec<u8>> = BytePool::<Vec<u8>>::new();
}
fn icmp(device_writer: &DeviceWriter, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> Result<()> {
    if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            device_writer.write_ipv4_tun(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

/// 接收tun数据，并且转发到udp上
#[inline]
async fn handle(sender: &ChannelSender, data: &mut [u8], len: usize, device_writer: &DeviceWriter,
                igmp_server: &Option<IgmpServer>, current_device: CurrentDeviceInfo,
                ip_route: &Option<ExternalRoute>, proxy_map: &Option<IpProxyMap>,
                client_cipher: &Cipher, server_cipher: &Cipher) -> Result<()> {
    let ipv4_packet = if let Ok(ipv4_packet) = IpV4Packet::new(&mut data[12..len]) {
        ipv4_packet
    } else {
        return Ok(());
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    if src_ip != current_device.virtual_ip() {
        return Ok(());
    }
    if src_ip == dest_ip {
        return icmp(&device_writer, ipv4_packet);
    }
    return crate::handle::tun_tap::base_handle(sender, data, len, igmp_server,
                                               current_device, ip_route, proxy_map, client_cipher, server_cipher).await;
}

pub async fn start(worker: VntWorker, sender: ChannelSender,
                   device_reader: DeviceReader,
                   device_writer: DeviceWriter,
                   igmp_server: Option<IgmpServer>,
                   current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                   ip_route: Option<ExternalRoute>,
                   ip_proxy_map: Option<IpProxyMap>,
                   client_cipher: Cipher, server_cipher: Cipher, parallel: usize) {
    if parallel == 1 {
        thread::Builder::new().name("tun_handler".into()).spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap()
                .block_on(async move {
                    if let Err(e) = start_simple(sender, device_reader, &device_writer, igmp_server, current_device, ip_route, ip_proxy_map, client_cipher, server_cipher).await {
                        log::warn!("stop:{}",e);
                    }
                    let _ = device_writer.close();
                    worker.stop_all();
                })
        }).unwrap();
    } else {
        let (buf_sender, buf_receiver) = buf_channel_group(parallel);
        for mut buf_receiver in buf_receiver.0 {
            let sender = sender.clone();
            let device_writer = device_writer.clone();
            let igmp_server = igmp_server.clone();
            let current_device = current_device.clone();
            let ip_route = ip_route.clone();
            let ip_proxy_map = ip_proxy_map.clone();
            let client_cipher = client_cipher.clone();
            let server_cipher = server_cipher.clone();
            tokio::spawn(async move {
                while let Some((mut buf, start, len)) = buf_receiver.recv().await {
                    match handle(&sender, &mut buf[start..], len, &device_writer, &igmp_server, current_device.load(),
                                 &ip_route, &ip_proxy_map, &client_cipher, &server_cipher).await {
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("{:?}", e)
                        }
                    }
                }
            });
        }

        thread::Builder::new().name("tun_handler".into()).spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap()
                .block_on(async move {
                    if let Err(e) = start_(sender, device_reader, buf_sender).await {
                        log::warn!("stop:{}",e);
                    }
                    let _ = device_writer.close();
                    worker.stop_all();
                })
        }).unwrap();
    }
}

async fn start_(sender: ChannelSender, device_reader: DeviceReader, mut buf_sender: BufSenderGroup) -> io::Result<()> {
    loop {
        let mut buf = POOL.alloc(4096);
        buf[..12].fill(0);
        if sender.is_close() {
            return Ok(());
        }
        let start = 0;
        let len = device_reader.read(&mut buf[12..])? + 12;
        #[cfg(any(target_os = "macos"))]
            let start = 4;
        if !buf_sender.send((buf, start, len)).await {
            return Err(io::Error::new(io::ErrorKind::Other, "tun buf_sender发送失败"));
        }
    }
}

async fn start_simple(sender: ChannelSender,
                      device_reader: DeviceReader,
                      device_writer: &DeviceWriter,
                      igmp_server: Option<IgmpServer>,
                      current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                      ip_route: Option<ExternalRoute>,
                      ip_proxy_map: Option<IpProxyMap>,
                      client_cipher: Cipher, server_cipher: Cipher) -> io::Result<()> {
    let mut buf = [0; 4096];
    loop {
        if sender.is_close() {
            return Ok(());
        }
        buf[..12].fill(0);
        let len = device_reader.read(&mut buf[12..])? + 12;
        #[cfg(any(target_os = "macos"))]
            let mut buf = &mut buf[4..];
        match handle(&sender, &mut buf, len, device_writer, &igmp_server, current_device.load(), &ip_route, &ip_proxy_map, &client_cipher, &server_cipher).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
    }
}
