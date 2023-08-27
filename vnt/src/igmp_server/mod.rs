use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use parking_lot::RwLock;
use packet::igmp::igmp_v2::IgmpV2Packet;
use packet::igmp::igmp_v3::{IgmpV3QueryPacket, IgmpV3RecordType, IgmpV3ReportPacket};
use packet::igmp::IgmpType;
use packet::ip::ipv4::protocol::Protocol;
use crate::tun_tap_device::DeviceWriter;

//1. 定时发送query，启动时20秒一次，连发3次，之后8分钟一次
//2. 接收网关的igmp report 维护组播源信息
#[derive(Clone, Debug)]
pub struct Multicast {
    //成员虚拟ip
    members: HashMap<Ipv4Addr, Instant>,
    //是否是过滤模式
    //成员过滤或包含的源ip
    map: HashMap<Ipv4Addr, (bool, HashSet<Ipv4Addr>)>,
}

impl Multicast {
    pub fn new() -> Self {
        Self {
            members: Default::default(),
            map: Default::default(),
        }
    }
    pub fn is_send(&self, ip: &Ipv4Addr) -> bool {
        if self.members.contains_key(ip) {
            if let Some((is_include, set)) = self.map.get(ip) {
                if *is_include {
                    set.contains(ip)
                } else {
                    !set.contains(ip)
                }
            } else {
                true
            }
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct IgmpServer {
    multicast: Arc<DashMap<Ipv4Addr, Arc<RwLock<Multicast>>>>,
}

impl IgmpServer {
    pub fn new(device_writer: DeviceWriter) -> Self {
        let multicast: Arc<DashMap<Ipv4Addr, Arc<RwLock<Multicast>>>> = Arc::new(DashMap::new());
        std::thread::spawn(move || {
            //预留以太网帧头和ip头
            let mut buf = [0; 14 + 24 + 12];
            let dest = Ipv4Addr::new(224, 0, 0, 1);
            let src = Ipv4Addr::new(10, 26, 0, 1);
            {
                let buf = &mut buf[14..];
                let len = buf.len();
                // ipv4 头部20字节
                buf[0] = 0b0100_0110;
                //写入总长度
                buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                //ttl
                buf[8] = 1;
                buf[20] = 0x94;
                buf[21] = 0x04;
                let mut ipv4 = packet::ip::ipv4::packet::IpV4Packet::unchecked(buf);
                ipv4.set_flags(2);
                ipv4.set_protocol(Protocol::Igmp);
                ipv4.set_source_ip(src);
                ipv4.set_destination_ip(dest);
                ipv4.update_checksum();
            }
            {
                let mut igmp_query = IgmpV3QueryPacket::unchecked(&mut buf[14 + 24..]);
                igmp_query.set_igmp_type();
                igmp_query.set_max_resp_code(50);
                igmp_query.set_group_address(Ipv4Addr::UNSPECIFIED);
                igmp_query.set_qrv(2);
                igmp_query.set_qqic(10);
                igmp_query.update_checksum();
            }
            loop {
                let _ = device_writer.write_ipv4(&mut buf);
                std::thread::sleep(Duration::from_secs(20))
            }
        });
        Self {
            multicast,
        }
    }
    pub fn load(&self, multicast_addr: &Ipv4Addr) -> Option<Arc<RwLock<Multicast>>> {
        if let Some(entry) = self.multicast.get(multicast_addr) {
            Some(entry.value().clone())
        } else {
            None
        }
    }
    pub fn handle(&self, buf: &[u8], source: Ipv4Addr) -> crate::Result<()> {
        for x in self.multicast.iter() {
            let mut list = Vec::new();
            let mut write_guard = x.value().write();
            for (ip, time) in &write_guard.members {
                if time.elapsed() > Duration::from_secs(30) {
                    list.push(*ip);
                }
            }
            for ip in list {
                write_guard.members.remove(&ip);
                write_guard.map.remove(&ip);
            }
        }
        match IgmpType::from(buf[0]) {
            IgmpType::Query => {}
            IgmpType::ReportV1 | IgmpType::ReportV2 => {
                //加入组播，v1和v2差不多
                let report = IgmpV2Packet::new(buf)?;
                let multicast_addr = report.group_address();
                if !multicast_addr.is_multicast() {
                    return Ok(());
                }
                let multi = {
                    self.multicast.entry(multicast_addr).or_insert_with(|| {
                        Arc::new(RwLock::new(Multicast::new()))
                    }).value().clone()
                };
                let mut guard = multi.write();
                guard.members.insert(source, Instant::now());
            }
            IgmpType::LeaveV2 => {
                //退出组播
                let leave = IgmpV2Packet::new(buf)?;
                let multicast_addr = leave.group_address();
                if !multicast_addr.is_multicast() {
                    return Ok(());
                }
                if let Some(entry) = self.multicast.get(&multicast_addr) {
                    let mut guard = entry.value().write();
                    guard.map.remove(&source);
                    guard.members.remove(&source);
                }
            }
            IgmpType::ReportV3 => {
                let report = IgmpV3ReportPacket::new(buf)?;
                if let Some(group_records) = report.group_records() {
                    for group_record in group_records {
                        let multicast_addr = group_record.multicast_address();
                        if !multicast_addr.is_multicast() {
                            return Ok(());
                        }
                        let multi = self.multicast.entry(multicast_addr).or_insert_with(|| {
                            Arc::new(RwLock::new(Multicast::new()))
                        }).value().clone();
                        let mut guard = multi.write();

                        match group_record.record_type() {
                            IgmpV3RecordType::ModeIsInclude | IgmpV3RecordType::ChangeToIncludeMode => {
                                match group_record.source_addresses() {
                                    None => {
                                        //不接收所有
                                        guard.members.remove(&source);
                                        guard.map.remove(&source);
                                    }
                                    Some(src) => {
                                        guard.members.insert(source, Instant::now());
                                        guard.map.insert(source, (true, HashSet::from_iter(src)));
                                    }
                                }
                            }

                            IgmpV3RecordType::ModeIsExclude | IgmpV3RecordType::ChangeToExcludeMode => {
                                match group_record.source_addresses() {
                                    None => {
                                        //接收所有
                                        guard.members.insert(source, Instant::now());
                                        guard.map.remove(&source);
                                    }
                                    Some(src) => {
                                        guard.members.insert(source, Instant::now());
                                        guard.map.insert(source, (false, HashSet::from_iter(src)));
                                    }
                                }
                            }
                            IgmpV3RecordType::AllowNewSources => {
                                //在已有源的基础上，接收目标源，如果是排除模式，则删除；是包含模式则添加
                                match group_record.source_addresses() {
                                    None => {}
                                    Some(src) => {
                                        match guard.map.get_mut(&source) {
                                            None => {}
                                            Some((is_include, set)) => {
                                                for ip in src {
                                                    if *is_include {
                                                        set.insert(ip);
                                                    } else {
                                                        set.remove(&ip);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            IgmpV3RecordType::BlockOldSources => {
                                //在已有源的基础上，不接收目标源
                                match group_record.source_addresses() {
                                    None => {}
                                    Some(src) => {
                                        match guard.map.get_mut(&source) {
                                            None => {}
                                            Some((is_include, set)) => {
                                                for ip in src {
                                                    if *is_include {
                                                        set.remove(&ip);
                                                    } else {
                                                        set.insert(ip);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            IgmpV3RecordType::Unknown(_) => {}
                        }
                    }
                }
            }
            IgmpType::Unknown(_) => {}
        }
        Ok(())
    }
}