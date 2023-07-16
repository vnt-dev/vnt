use std::{io, thread};
use std::sync::Arc;
use aes_gcm::Aes256Gcm;

use crossbeam_utils::atomic::AtomicCell;

use packet::icmp::Kind;
use packet::icmp::icmp::IcmpPacket;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use crate::channel::sender::ChannelSender;
use crate::core::status::SwitchWorker;

use crate::error::*;
use crate::external_route::ExternalRoute;
use crate::handle::CurrentDeviceInfo;
use crate::igmp_server::IgmpServer;
use crate::ip_proxy::IpProxyMap;
use crate::tun_tap_device::{DeviceReader, DeviceWriter};

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
async fn handle(sender: &ChannelSender, data: &mut [u8], len: usize, device_writer: &DeviceWriter, igmp_server: &Option<IgmpServer>, current_device: CurrentDeviceInfo,
                ip_route: &Option<ExternalRoute>, proxy_map: &Option<IpProxyMap>, cipher: &Option<Aes256Gcm>) -> Result<()> {
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
    return crate::handle::tun_tap::base_handle(sender, data, len, igmp_server, current_device, ip_route, proxy_map, cipher).await;
}

pub fn start(worker: SwitchWorker, sender: ChannelSender,
             device_reader: DeviceReader,
             device_writer: DeviceWriter,
             igmp_server: Option<IgmpServer>,
             current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
             ip_route: Option<ExternalRoute>,
             ip_proxy_map: Option<IpProxyMap>,
             cipher: Option<Aes256Gcm>) {
    thread::Builder::new().name("tun_handler".into()).spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap()
            .block_on(async move {
                if let Err(e) = start_(sender, device_reader, &device_writer, igmp_server, current_device, ip_route, ip_proxy_map, cipher).await {
                    log::warn!("stop:{}",e);
                }
                let _ = device_writer.close();
                worker.stop_all();
            })
    }).unwrap();
}

async fn start_(sender: ChannelSender,
                device_reader: DeviceReader,
                device_writer: &DeviceWriter,
                igmp_server: Option<IgmpServer>,
                current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                ip_route: Option<ExternalRoute>,
                ip_proxy_map: Option<IpProxyMap>,
                cipher: Option<Aes256Gcm>) -> io::Result<()> {
    let mut buf = [0; 4096];
    loop {
        if sender.is_close() {
            return Ok(());
        }
        let len = device_reader.read(&mut buf[12..])? + 12;
        match handle(&sender, &mut buf, len, device_writer, &igmp_server, current_device.load(), &ip_route, &ip_proxy_map, &cipher).await {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
    }
}
