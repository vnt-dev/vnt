use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::{Div, Mul};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use protobuf::Message;
use rand::prelude::SliceRandom;

use crate::channel::context::ChannelContext;
use crate::channel::punch::{NatInfo, NatType, Punch};
use crate::cipher::Cipher;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::nat::NatTest;
use crate::proto::message::{PunchInfo, PunchNatType};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{control_packet, other_turn_packet, NetPacket, Protocol, MAX_TTL};
use crate::util::Scheduler;

#[derive(Clone)]
pub struct PunchSender {
    sender_self: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_peer: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_cone_self: SyncSender<(Ipv4Addr, NatInfo)>,
    sender_cone_peer: SyncSender<(Ipv4Addr, NatInfo)>,
}

impl PunchSender {
    pub fn send(&self, src_peer: bool, ip: Ipv4Addr, info: NatInfo) -> bool {
        log::info!(
            "发送打洞协商消息,是否对端发起:{},ip:{},info:{:?}",
            src_peer,
            ip,
            info
        );
        let sender = match info.nat_type {
            NatType::Symmetric => {
                if src_peer {
                    &self.sender_peer
                } else {
                    &self.sender_self
                }
            }
            NatType::Cone => {
                if src_peer {
                    &self.sender_cone_peer
                } else {
                    &self.sender_cone_self
                }
            }
        };
        sender.try_send((ip, info)).is_ok()
    }
}

pub struct PunchReceiver {
    receiver_peer: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_self: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_cone_peer: Receiver<(Ipv4Addr, NatInfo)>,
    receiver_cone_self: Receiver<(Ipv4Addr, NatInfo)>,
}

pub fn punch_channel() -> (PunchSender, PunchReceiver) {
    let (sender_self, receiver_self) = sync_channel(0);
    let (sender_peer, receiver_peer) = sync_channel(0);
    let (sender_cone_peer, receiver_cone_peer) = sync_channel(0);
    let (sender_cone_self, receiver_cone_self) = sync_channel(0);
    (
        PunchSender {
            sender_self,
            sender_peer,
            sender_cone_peer,
            sender_cone_self,
        },
        PunchReceiver {
            receiver_peer,
            receiver_self,
            receiver_cone_peer,
            receiver_cone_self,
        },
    )
}

pub fn punch(
    scheduler: &Scheduler,
    context: ChannelContext,
    nat_test: NatTest,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    receiver: PunchReceiver,
    punch: Punch,
) {
    let punch_record = Arc::new(Mutex::new(HashMap::new()));
    let last_punch_record = HashMap::new();
    punch_request(
        scheduler,
        context,
        nat_test,
        device_map,
        current_device.clone(),
        client_cipher.clone(),
        0,
        punch_record.clone(),
        last_punch_record,
    );
    let f = |receiver: Receiver<(Ipv4Addr, NatInfo)>| {
        let punch = punch.clone();
        let current_device = current_device.clone();
        let client_cipher = client_cipher.clone();
        let punch_record = punch_record.clone();
        thread::Builder::new()
            .name("punch".into())
            .spawn(move || {
                punch_start(receiver, punch, current_device, client_cipher, punch_record);
            })
            .expect("punch");
    };
    f(receiver.receiver_peer);
    f(receiver.receiver_self);
    f(receiver.receiver_cone_peer);
    f(receiver.receiver_cone_self);
}

/// 接收打洞消息，配合对端打洞
fn punch_start(
    receiver: Receiver<(Ipv4Addr, NatInfo)>,
    mut punch: Punch,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    punch_record: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
) {
    while let Ok((peer_ip, nat_info)) = receiver.recv() {
        let mut packet = NetPacket::new_encrypt([0u8; 12 + ENCRYPTION_RESERVED]).unwrap();
        packet.set_default_version();
        packet.first_set_ttl(1);
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::PunchRequest.into());
        packet.set_source(current_device.load().virtual_ip());
        packet.set_destination(peer_ip);
        let count = {
            let mut guard = punch_record.lock();
            if let Some(v) = guard.get_mut(&peer_ip) {
                *v += 1;
                *v
            } else {
                guard.insert(peer_ip, 0);
                0
            }
        };
        log::info!("第{}次发起打洞,目标:{:?},{:?} ", count, peer_ip, nat_info);

        if let Err(e) = client_cipher.encrypt_ipv4(&mut packet) {
            log::error!("{:?}", e);
            continue;
        }
        if let Err(e) = punch.punch(packet.buffer(), peer_ip, nat_info, count < 2, count) {
            log::warn!("{:?}", e)
        }
    }
}

/// 定时发起打洞请求
fn punch_request(
    scheduler: &Scheduler,
    context: ChannelContext,
    nat_test: NatTest,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    count: usize,
    punch_record: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
    mut last_punch_record: HashMap<Ipv4Addr, PunchRecordItem>,
) {
    let curr = current_device.load();
    let secs = if curr.status.online() {
        if let Err(e) = punch0(
            &context,
            &nat_test,
            &device_map,
            curr,
            &client_cipher,
            &punch_record,
            &mut last_punch_record,
            count,
        ) {
            log::warn!("{:?}", e)
        }
        let sleep_time = [6, 7];
        Duration::from_secs(sleep_time[count % sleep_time.len()])
    } else {
        Duration::from_secs(5)
    };
    let rs = scheduler.timeout(secs, move |s| {
        punch_request(
            s,
            context,
            nat_test,
            device_map,
            current_device,
            client_cipher,
            count + 1,
            punch_record,
            last_punch_record,
        );
    });
    if !rs {
        log::info!("定时任务停止");
    }
}
#[derive(Copy, Clone, Default)]
struct PunchRecordItem {
    pub punch_record: usize,
    pub last_p2p_num: usize,
}

/// 随机对需要打洞的客户端发起打洞请求
fn punch0(
    context: &ChannelContext,
    nat_test: &NatTest,
    device_map: &Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    current_device: CurrentDeviceInfo,
    client_cipher: &Cipher,
    punch_record: &Mutex<HashMap<Ipv4Addr, usize>>,
    last_punch_record: &mut HashMap<Ipv4Addr, PunchRecordItem>,
    total_count: usize,
) -> anyhow::Result<()> {
    let nat_info = nat_test.nat_info();
    if total_count < 10
        && (nat_info.public_ips.is_empty()
            || nat_info.public_ports.is_empty()
            || nat_info.public_ports[0] == 0
            || nat_info.public_ports.iter().filter(|&&v| v == 0).count()
                > nat_info.public_ports.len() / 2)
    {
        log::info!("未获取到公网地址，暂时放弃打洞,第{}轮", total_count);
        return Ok(());
    }
    let current_ip = current_device.virtual_ip;
    let mut list: Vec<PeerDeviceInfo> = device_map
        .lock()
        .1
        .values()
        .filter(|info| !info.wireguard && info.virtual_ip > current_ip)
        .cloned()
        .collect();
    list.shuffle(&mut rand::thread_rng());
    for info in list {
        if info.status.is_offline() {
            // 客户端掉线了要重置打洞记录
            punch_record.lock().remove(&info.virtual_ip);
            continue;
        }
        let mut punch_count = punch_record
            .lock()
            .get(&info.virtual_ip)
            .cloned()
            .unwrap_or(0)
            .mul(2)
            .div(3);
        let p2p_num = context.route_table.p2p_num(&info.virtual_ip);
        let mut max_punch_interval = 50;
        if p2p_num > 0 {
            if p2p_num >= context.channel_num() {
                //通道数满足要求，不再打洞
                if punch_count != 0 {
                    punch_record.lock().remove(&info.virtual_ip);
                }
                continue;
            }
            //有p2p通道，但是通道数量不够，则继续打洞
            // 提高等待上限
            max_punch_interval = 300;
        }
        // 能发起打洞的前提是自己空闲，这里会间隔5秒以上发起一次打洞，所以假定上一轮打洞已结束
        let last_punch = last_punch_record.entry(info.virtual_ip).or_default();
        if last_punch.last_p2p_num > p2p_num {
            // 打的洞掉线了,需要重置重新打
            punch_record.lock().remove(&info.virtual_ip);
            punch_count = 0;
        }

        // 梯度增加打洞时间间隔
        if total_count > last_punch.punch_record + punch_count.min(max_punch_interval) {
            // 记录打洞周期，抑制下一次打洞，从而递减打洞频率
            last_punch.punch_record = total_count;
            last_punch.last_p2p_num = p2p_num;
            let packet = punch_packet(
                client_cipher,
                current_device.virtual_ip(),
                &nat_info,
                info.virtual_ip,
            )?;
            log::info!(
                "目标:{:?},当前nat:{:?} 第{}次发起打洞协商请求， 第:{}轮",
                info.virtual_ip,
                nat_info,
                punch_count,
                total_count,
            );
            context.send_default(&packet, current_device.connect_server)?;
            break;
        }
    }
    Ok(())
}

fn punch_packet(
    client_cipher: &Cipher,
    virtual_ip: Ipv4Addr,
    nat_info: &NatInfo,
    dest: Ipv4Addr,
) -> anyhow::Result<NetPacket<Vec<u8>>> {
    let mut punch_reply = PunchInfo::new();
    punch_reply.reply = false;
    punch_reply.public_ip_list = nat_info
        .public_ips
        .iter()
        .map(|ip| u32::from_be_bytes(ip.octets()))
        .collect();
    punch_reply.public_port = nat_info.public_ports.get(0).map_or(0, |v| *v as u32);
    punch_reply.public_ports = nat_info.public_ports.iter().map(|e| *e as u32).collect();
    punch_reply.public_port_range = nat_info.public_port_range as u32;
    punch_reply.public_tcp_port = nat_info.public_tcp_port as u32;
    punch_reply.local_ip = u32::from(nat_info.local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED));
    punch_reply.local_port = nat_info.udp_ports[0] as u32;
    punch_reply.tcp_port = nat_info.tcp_port as u32;
    punch_reply.udp_ports = nat_info.udp_ports.iter().map(|e| *e as u32).collect();
    if let Some(ipv6) = nat_info.ipv6 {
        punch_reply.ipv6_port = nat_info.udp_ports[0] as u32;
        punch_reply.ipv6 = ipv6.octets().to_vec();
    }
    punch_reply.nat_type = protobuf::EnumOrUnknown::new(PunchNatType::from(nat_info.nat_type));
    punch_reply.punch_model = protobuf::EnumOrUnknown::new(nat_info.punch_model.into());
    log::info!("请求打洞={:?}", punch_reply);
    let bytes = punch_reply
        .write_to_bytes()
        .map_err(|e| anyhow!("punch_packet {:?}", e))?;
    let mut net_packet = NetPacket::new_encrypt(vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED])?;
    net_packet.set_default_version();
    net_packet.set_protocol(Protocol::OtherTurn);
    net_packet.set_transport_protocol(other_turn_packet::Protocol::Punch.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_source(virtual_ip);
    net_packet.set_destination(dest);
    net_packet.set_payload(&bytes)?;
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
