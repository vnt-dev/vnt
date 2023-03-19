use std::{io, thread};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use crossbeam::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::prelude::SliceRandom;
use p2p_channel::channel::sender::Sender;
use p2p_channel::punch::{NatInfo, NatType, Punch};
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
use crate::proto::message::{PunchInfo, PunchNatType};
use crate::protocol::{control_packet, MAX_TTL, NetPacket, Protocol, turn_packet, Version};

pub fn start_cone(punch: Punch<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) {
    thread::spawn(move || {
        if let Err(e) = start_(true, punch, current_device) {
            log::warn!("锥形网络打洞处理线程停止 {:?}",e);
        }
    });
}

pub fn start_symmetric(punch: Punch<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) {
    thread::spawn(move || {
        if let Err(e) = start_(false, punch, current_device) {
            log::warn!("对称网络打洞处理线程停止 {:?}",e);
        }
    });
}

fn start_(is_cone: bool, mut punch: Punch<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> io::Result<()> {
    let mut packet = NetPacket::new([0u8; 12])?;
    packet.set_version(Version::V1);
    packet.first_set_ttl(1);
    packet.set_protocol(Protocol::Control);
    packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
    loop {
        let (peer_ip, nat_info) = if is_cone {
            punch.next_cone(None)?
        } else {
            punch.next_symmetric(None)?
        };
        if let Some(route) = punch.sender().route(&peer_ip) {
            if route.metric == 1 {
                //直连地址不需要打洞
                continue;
            }
        }
        packet.set_source(current_device.load().virtual_ip());
        packet.set_destination(peer_ip);
        log::info!("发起打洞，目标:{:?},{:?}",peer_ip,nat_info);
        if let Err(e) = punch.punch(packet.buffer(), peer_ip, nat_info) {
            log::warn!("peer_ip:{:?},e:{:?}",peer_ip,e);
        }
    }
}

pub fn start_punch(nat_test: NatTest, device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>, sender: Sender<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) {
    thread::spawn(move || {
        if let Err(e) = start_punch_(nat_test, device_list, sender, current_device) {
            log::warn!("对称网络打洞处理线程停止 {:?}",e);
        }
    });
}

fn start_punch_(nat_test: NatTest, device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>, sender: Sender<Ipv4Addr>, current_device: Arc<AtomicCell<CurrentDeviceInfo>>) -> crate::Result<()> {
    loop {
        if sender.is_close() {
            return Ok(());
        }
        let current_device = current_device.load();
        let nat_info = nat_test.nat_info();
        {
            let mut list = device_list.lock().clone().1;
            list.shuffle(&mut rand::thread_rng());
            let mut count = 0;
            for info in list {
                if info.virtual_ip <= current_device.virtual_ip {
                    continue;
                }
                if let Some(route) = sender.route(&info.virtual_ip) {
                    if route.metric == 1 {
                        //直连地址不需要打洞
                        continue;
                    }
                }
                count += 1;
                if count > 3 {
                    break;
                }
                let buf = punch_packet(current_device.virtual_ip(), &nat_info, info.virtual_ip)?;
                sender.send_to_addr(&buf, current_device.connect_server)?;
            }
        }
        match nat_info.nat_type {
            NatType::Symmetric => {
                thread::sleep(Duration::from_secs(28));
            }
            NatType::Cone => {
                thread::sleep(Duration::from_secs(20));
            }
        }
    }
}

pub fn punch_packet(virtual_ip: Ipv4Addr, nat_info: &NatInfo, dest: Ipv4Addr) -> crate::Result<Vec<u8>> {
    let mut punch_reply = PunchInfo::new();
    punch_reply.reply = false;
    punch_reply.public_ip_list = nat_info.public_ips.iter().map(|i| {
        match i {
            IpAddr::V4(ip) => {
                u32::from_be_bytes(ip.octets())
            }
            IpAddr::V6(_) => {
                panic!()
            }
        }
    }).collect();
    punch_reply.public_port = nat_info.public_port as u32;
    punch_reply.public_port_range = nat_info.public_port_range as u32;
    punch_reply.local_ip = match nat_info.local_ip {
        IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
        IpAddr::V6(_) => {
            panic!()
        }
    };
    punch_reply.local_port = nat_info.local_port as u32;
    punch_reply.nat_type = protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
    let bytes = punch_reply.write_to_bytes()?;
    let mut net_packet = NetPacket::new(vec![0u8; 12 + bytes.len()])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::OtherTurn);
    net_packet.set_transport_protocol(turn_packet::Protocol::Punch.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(virtual_ip);
    net_packet.set_destination(dest);
    net_packet.set_payload(&bytes);
    Ok(net_packet.into_buffer())
}