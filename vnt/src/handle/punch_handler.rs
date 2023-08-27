use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
use crate::proto::message::{PunchInfo, PunchNatType};
use crate::protocol::{control_packet, other_turn_packet, NetPacket, Protocol, Version, MAX_TTL};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::prelude::SliceRandom;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use std::io;
use tokio::sync::mpsc::Receiver;
use crate::channel::punch::{NatInfo, Punch};
use crate::channel::sender::ChannelSender;
use crate::cipher::Cipher;
use crate::core::status::VntWorker;
use crate::protocol::body::ENCRYPTION_RESERVED;

pub fn start(mut worker: VntWorker, receiver: Receiver<(Ipv4Addr, NatInfo)>,
             punch: Punch, current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
             client_cipher: Cipher, ) {
    tokio::spawn(async move {
        tokio::select! {
            _=start0(receiver, punch, current_device,client_cipher)=>{}
            _=worker.stop_wait()=>{
                return;
            }
        }
        worker.stop_all();
    });
}

pub async fn start0(mut receiver: Receiver<(Ipv4Addr, NatInfo)>,
                    mut punch: Punch, current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
                    client_cipher: Cipher, ) {
    while let Some((peer_ip, nat_info)) = receiver.recv().await {
        if let Err(e) = start_(&client_cipher, &mut punch, &current_device, peer_ip, nat_info).await {
            log::warn!("网络打洞异常 {:?}", e);
        }
    }
}

async fn start_(
    client_cipher: &Cipher,
    punch: &mut Punch,
    current_device: &Arc<AtomicCell<CurrentDeviceInfo>>,
    peer_ip: Ipv4Addr,
    nat_info: NatInfo,
) -> io::Result<()> {
    let mut packet = NetPacket::new_encrypt([0u8; 12 + ENCRYPTION_RESERVED])?;
    packet.set_version(Version::V1);
    packet.first_set_ttl(1);
    packet.set_protocol(Protocol::Control);
    packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
    packet.set_source(current_device.load().virtual_ip());
    packet.set_destination(peer_ip);
    log::info!("发起打洞，目标:{:?},{:?}", peer_ip, nat_info);
    client_cipher.encrypt_ipv4(&mut packet)?;
    punch.punch(packet.buffer(), peer_ip, nat_info).await
}

pub async fn start_punch(
    mut worker: VntWorker,
    nat_test: NatTest,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    sender: ChannelSender,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) {
    let mut num = 0;
    let sleep_time = [3, 5, 7, 11, 13, 17, 19, 23, 29];
    loop {
        if sender.is_close() {
            break;
        }
        tokio::select! {
            rs= start_punch_(Duration::from_secs(sleep_time[num % sleep_time.len()]),&nat_test, &device_list,
                &sender, &current_device,&client_cipher)=>{
                 if let Err(e) = rs {
                    log::warn!("打洞处理任务异常 {:?}", e);
                }
            }
           _=worker.stop_wait()=>{
                break;
            }
        }
        num += 1;
    }
}

async fn start_punch_(
    sleep_time: Duration,
    nat_test: &NatTest,
    device_list: &Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    sender: &ChannelSender,
    current_device: &Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: &Cipher,
) -> crate::Result<()> {
    let current_device = current_device.load();
    let nat_info = nat_test.nat_info();
    let mut list = device_list.lock().clone().1;
    list.shuffle(&mut rand::thread_rng());
    let mut count = 0;
    for info in list {
        if info.virtual_ip <= current_device.virtual_ip {
            continue;
        }
        if !sender.need_punch(&info.virtual_ip) {
            continue;
        }
        count += 1;
        if count > 2 {
            break;
        }
        let packet = punch_packet(client_cipher, current_device.virtual_ip(), &nat_info, info.virtual_ip)?;
        let _ = sender.send_main(packet.buffer(), current_device.connect_server).await;
    }
    tokio::time::sleep(sleep_time).await;
    Ok(())
}

pub fn punch_packet(
    client_cipher: &Cipher,
    virtual_ip: Ipv4Addr,
    nat_info: &NatInfo,
    dest: Ipv4Addr,
) -> crate::Result<NetPacket<Vec<u8>>> {
    let mut punch_reply = PunchInfo::new();
    punch_reply.reply = false;
    punch_reply.public_ip_list = nat_info
        .public_ips
        .iter()
        .map(|ip| u32::from_be_bytes(ip.octets()))
        .collect();
    punch_reply.public_port = nat_info.public_port as u32;
    punch_reply.public_port_range = nat_info.public_port_range as u32;
    punch_reply.local_ip = u32::from_be_bytes(nat_info.local_ip.octets());
    punch_reply.local_port = nat_info.local_port as u32;
    punch_reply.nat_type = protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
    let bytes = punch_reply.write_to_bytes()?;
    let mut net_packet = NetPacket::new_encrypt(vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED])?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::OtherTurn);
    net_packet.set_transport_protocol(other_turn_packet::Protocol::Punch.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(virtual_ip);
    net_packet.set_destination(dest);
    net_packet.set_payload(&bytes)?;
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
