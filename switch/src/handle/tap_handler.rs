use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};
use crossbeam::atomic::AtomicCell;
use p2p_channel::channel::sender::Sender;
use packet::arp::arp::ArpPacket;
use packet::ethernet;
use packet::ethernet::packet::EthernetPacket;
use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use crate::handle::{check_dest, CurrentDeviceInfo};
use crate::protocol::{MAX_TTL, NetPacket, Protocol, Version};
use crate::tap_device::{TapReader, TapWriter};

pub fn start(sender: Sender<Ipv4Addr>,
             tap_reader: TapReader,
             tap_writer: TapWriter,
             current_device: Arc<AtomicCell<CurrentDeviceInfo>>, ) {
    thread::Builder::new().name("tap-handler".into()).spawn(move || {
        if let Err(e) = start_(sender, tap_reader, tap_writer, current_device) {
            log::warn!("{:?}",e);
        }
    }).unwrap();
}

fn start_(sender: Sender<Ipv4Addr>,
          tap_reader: TapReader,
          tap_writer: TapWriter,
          current_device: Arc<AtomicCell<CurrentDeviceInfo>>, ) -> io::Result<()> {
    let mut net_packet = NetPacket::new(vec![0u8; 4 + 8 + 1500]).unwrap();
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Ipv4Turn);
    net_packet.set_transport_protocol(ipv4::protocol::Protocol::Ipv4.into());
    net_packet.set_ttl(MAX_TTL);
    let mut buf = [0; 2048];
    loop {
        let len = tap_reader.read(&mut buf)?;
        if len == 0 {
            continue;
        }
        let mut ethernet_packet = EthernetPacket::unchecked(&mut buf[..len]);
        if let Err(e) = handle(&mut net_packet, &current_device, &tap_writer, &mut ethernet_packet, &sender) {
            log::error!("tap handle{:?}",e);
        }
    }
}

fn handle(net_packet: &mut NetPacket<Vec<u8>>, current_device: &AtomicCell<CurrentDeviceInfo>, tap_writer: &TapWriter, ethernet_packet: &mut EthernetPacket<&mut [u8]>, sender: &Sender<Ipv4Addr>) -> io::Result<()> {
    let current_device = current_device.load();
    match ethernet_packet.protocol() {
        ethernet::protocol::Protocol::Arp => {
            let mut out_ethernet_packet = ethernet::packet::EthernetPacket::unchecked(ethernet_packet.buffer.to_vec());
            let arp_packet = ArpPacket::unchecked(ethernet_packet.payload());
            let mut out_arp_packet = ArpPacket::unchecked(out_ethernet_packet.payload_mut());
            let sender_h = arp_packet.sender_hardware_addr();
            let sender_p = arp_packet.sender_protocol_addr();
            let target_p = arp_packet.target_protocol_addr();
            if target_p == &[0, 0, 0, 0] || sender_p == &[0, 0, 0, 0] || target_p == sender_p {
                return Ok(());
            }
            //回复一个虚假的MAC地址
            out_arp_packet.set_sender_hardware_addr(&[target_p[0], target_p[1], target_p[2], target_p[3], 123, 234]);
            out_arp_packet.set_sender_protocol_addr(target_p);
            out_arp_packet.set_target_hardware_addr(sender_h);
            out_arp_packet.set_target_protocol_addr(sender_p);
            out_arp_packet.set_op_code(2);
            out_ethernet_packet.set_source(&[target_p[0], target_p[1], target_p[2], target_p[3], 123, 234]);
            out_ethernet_packet.set_destination(sender_h);

            tap_writer.write(&out_ethernet_packet.buffer)?;
        }
        ethernet::protocol::Protocol::Ipv4 => {
            // println!("in ethernet_packet {:?}", ethernet_packet);
            let mut ipv4_packet = IpV4Packet::unchecked(ethernet_packet.payload_mut());
            let src_ip = ipv4_packet.source_ip();
            let dest_ip = ipv4_packet.destination_ip();
            if src_ip != current_device.virtual_ip() || (!check_dest(dest_ip, current_device.virtual_netmask, current_device.virtual_network) && !dest_ip.is_broadcast()) {
                return Ok(());
            }
            if src_ip == dest_ip {
                if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
                    let mut icmp = IcmpPacket::unchecked(ipv4_packet.payload_mut());
                    if icmp.kind() == Kind::EchoRequest {
                        icmp.set_kind(Kind::EchoReply);
                        icmp.update_checksum();
                        let src = ipv4_packet.source_ip();
                        ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
                        ipv4_packet.set_destination_ip(src);
                        ipv4_packet.update_checksum();
                        tap_writer.write(ethernet_packet.buffer)?;
                        return Ok(());
                    }
                }
            }
            net_packet.set_source(src_ip);
            net_packet.set_destination(dest_ip);
            let data_len = ipv4_packet.buffer.len();
            net_packet.set_payload(ipv4_packet.buffer);
            //优先发到直连到地址
            if sender.send_to_id(&net_packet.buffer()[..(12 + data_len)], &dest_ip).is_err() {
                sender.send_to_addr(&net_packet.buffer()[..(12 + data_len)], current_device.connect_server)?;
            }
        }
        p => {
            log::warn!("不支持的二层协议：{:?}",p)
        }
    }
    Ok(())
}

