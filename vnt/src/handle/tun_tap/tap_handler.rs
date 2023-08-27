use std::{io, thread};
use std::sync::Arc;
use byte_pool::BytePool;

use crossbeam_utils::atomic::AtomicCell;
use lazy_static::lazy_static;

use packet::arp::arp::ArpPacket;
use packet::ethernet;
use packet::ethernet::packet::EthernetPacket;
use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::core::status::VntWorker;
use crate::external_route::ExternalRoute;
use crate::handle::CurrentDeviceInfo;
use crate::handle::tun_tap::channel_group::{buf_channel_group, BufSenderGroup};
use crate::igmp_server::IgmpServer;
use crate::ip_proxy::IpProxyMap;
use crate::tun_tap_device::{DeviceReader, DeviceWriter};
lazy_static! {
    static ref POOL:BytePool<Vec<u8>> = BytePool::<Vec<u8>>::new();
}

pub fn start(worker: VntWorker, sender: ChannelSender,
             device_reader: DeviceReader,
             device_writer: DeviceWriter,
             igmp_server: Option<IgmpServer>,
             current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
             ip_route: Option<ExternalRoute>,
             ip_proxy_map: Option<IpProxyMap>,
             client_cipher: Cipher, server_cipher: Cipher, parallel: usize) {
    if parallel == 1 {
        thread::Builder::new().name("tap_handler".into()).spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap()
                .block_on(async move {
                    if let Err(e) = start_simple(sender, device_reader,
                                                 device_writer, igmp_server,
                                                 current_device, ip_route, ip_proxy_map, client_cipher, server_cipher).await {
                        log::warn!("tap:{:?}",e);
                    }
                    worker.stop_all();
                });
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
                while let Some((mut buf, _, len)) = buf_receiver.recv().await {
                    match handle(&mut buf, len, &igmp_server, &current_device, &device_writer, &sender,
                                 &ip_route, &ip_proxy_map, &client_cipher, &server_cipher).await {
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("{:?}", e)
                        }
                    }
                }
            });
        }
        thread::Builder::new().name("tap_handler".into()).spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all().build().unwrap()
                .block_on(async move {
                    if let Err(e) = start_(sender, device_reader, buf_sender).await {
                        log::warn!("tap:{:?}",e);
                    }
                    worker.stop_all();
                });
        }).unwrap();
    }
}

async fn start_(sender: ChannelSender,
                device_reader: DeviceReader,
                mut buf_sender: BufSenderGroup) -> io::Result<()> {
    loop {
        let mut buf = POOL.alloc(4096);
        if sender.is_close() {
            return Ok(());
        }
        let start = 0;
        let len = device_reader.read(&mut buf)?;
        if !buf_sender.send((buf, start, len)).await {
            return Err(io::Error::new(io::ErrorKind::Other, "tap buf_sender发送失败"));
        }
    }
}

async fn start_simple(sender: ChannelSender,
                      device_reader: DeviceReader,
                      device_writer: DeviceWriter,
                      igmp_server: Option<IgmpServer>,
                      current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                      ip_route: Option<ExternalRoute>,
                      ip_proxy_map: Option<IpProxyMap>,
                      client_cipher: Cipher, server_cipher: Cipher) -> io::Result<()> {
    let mut buf = [0; 4096];
    loop {
        let len = device_reader.read(&mut buf)?;
        if let Err(e) = handle(&mut buf, len, &igmp_server, &current_device, &device_writer, &sender, &ip_route, &ip_proxy_map, &client_cipher, &server_cipher).await {
            log::warn!("tap handle{:?}",e);
        }
    }
}

async fn handle(buf: &mut [u8], len: usize, igmp_server: &Option<IgmpServer>, current_device: &AtomicCell<CurrentDeviceInfo>,
                device_writer: &DeviceWriter, sender: &ChannelSender, ip_route: &Option<ExternalRoute>,
                proxy_map: &Option<IpProxyMap>, client_cipher: &Cipher, server_cipher: &Cipher) -> crate::Result<()> {
    let mut ethernet_packet = EthernetPacket::new(&mut buf[..len])?;
    let current_device = current_device.load();
    match ethernet_packet.protocol() {
        ethernet::protocol::Protocol::Arp => {
            let mut out_ethernet_packet = EthernetPacket::unchecked(ethernet_packet.buffer.to_vec());
            let arp_packet = ArpPacket::unchecked(ethernet_packet.payload());
            let mut out_arp_packet = ArpPacket::unchecked(out_ethernet_packet.payload_mut());
            let sender_h = arp_packet.sender_hardware_addr();
            let sender_p = arp_packet.sender_protocol_addr();
            let target_p = arp_packet.target_protocol_addr();
            if target_p == &[0, 0, 0, 0] || sender_p == &[0, 0, 0, 0] || target_p == sender_p {
                return Ok(());
            }
            //回复一个虚假的MAC地址
            out_arp_packet.set_sender_hardware_addr(&[target_p[0], target_p[1], target_p[2], target_p[3], !sender_h[5], 234]);
            out_arp_packet.set_sender_protocol_addr(target_p);
            out_arp_packet.set_target_hardware_addr(sender_h);
            out_arp_packet.set_target_protocol_addr(sender_p);
            out_arp_packet.set_op_code(2);
            out_ethernet_packet.set_source(&[target_p[0], target_p[1], target_p[2], target_p[3], !sender_h[5], 234]);
            out_ethernet_packet.set_destination(sender_h);
            device_writer.write_ethernet_tap(&out_ethernet_packet.buffer)?;
        }
        ethernet::protocol::Protocol::Ipv4 => {
            let mut ipv4_packet = IpV4Packet::unchecked(ethernet_packet.payload_mut());
            let src_ip = ipv4_packet.source_ip();
            if src_ip != current_device.virtual_ip() {
                return Ok(());
            }
            let dest_ip = ipv4_packet.destination_ip();
            let protocol = ipv4_packet.protocol();
            if src_ip == dest_ip {
                if protocol == ipv4::protocol::Protocol::Icmp {
                    let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
                    if icmp.kind() == Kind::EchoRequest {
                        icmp.set_kind(Kind::EchoReply);
                        icmp.update_checksum();
                        ipv4_packet.set_source_ip(dest_ip);
                        ipv4_packet.set_destination_ip(src_ip);
                        ipv4_packet.update_checksum();
                        let source = ethernet_packet.source().to_vec();
                        let dest = ethernet_packet.destination().to_vec();
                        ethernet_packet.set_source(&dest);
                        ethernet_packet.set_destination(&source);
                        device_writer.write_ethernet_tap(&ethernet_packet.buffer)?;
                    }
                }
                return Ok(());
            }
            // 以太网帧头部14字节，预留12字节
            return crate::handle::tun_tap::base_handle(sender, &mut buf[2..], len - 2, igmp_server, current_device,
                                                       ip_route, proxy_map, client_cipher, server_cipher).await;
        }
        _ => {
            // log::warn!("不支持的二层协议：{:?}",p)
        }
    }
    Ok(())
}

