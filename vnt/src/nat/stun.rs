use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use crate::channel::punch::NatType;
use crate::channel::socket::{bind_udp, LocalInterface};
use rand::RngCore;
use std::net::UdpSocket;
use stun_format::Attr;

pub fn stun_test_nat(
    stun_servers: Vec<String>,
    default_interface: &LocalInterface,
) -> anyhow::Result<(NatType, Vec<Ipv4Addr>, u16)> {
    let mut nat_type = NatType::Cone;
    let mut port_range = 0;
    let mut hash_set = HashSet::new();
    for _ in 0..2 {
        let stun_servers = stun_servers.clone();
        match stun_test_nat0(stun_servers, default_interface) {
            Ok((nat_type_t, ip_list_t, port_range_t)) => {
                if nat_type_t == NatType::Symmetric {
                    nat_type = NatType::Symmetric;
                }
                for x in ip_list_t {
                    hash_set.insert(x);
                }
                if port_range < port_range_t {
                    port_range = port_range_t;
                }
            }
            Err(e) => {
                log::warn!("{:?}", e);
            }
        }
    }
    Ok((nat_type, hash_set.into_iter().collect(), port_range))
}

pub fn stun_test_nat0(
    stun_servers: Vec<String>,
    default_interface: &LocalInterface,
) -> anyhow::Result<(NatType, Vec<Ipv4Addr>, u16)> {
    let udp = bind_udp("0.0.0.0:0".parse().unwrap(), default_interface)?;
    udp.set_nonblocking(false)?;
    let udp: UdpSocket = udp.into();
    udp.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut nat_type = NatType::Cone;
    let mut min_port = u16::MAX;
    let mut max_port = 0;
    let mut hash_set = HashSet::new();
    let mut pub_addrs = HashSet::new();
    for x in &stun_servers {
        match test_nat(&udp, x) {
            Ok(addr) => {
                pub_addrs.extend(addr);
            }
            Err(e) => {
                log::warn!("stun {} error {:?} ", x, e);
            }
        }
    }
    if pub_addrs.len() > 1 {
        nat_type = NatType::Symmetric;
    }
    for addr in &pub_addrs {
        if let SocketAddr::V4(addr) = addr {
            hash_set.insert(*addr.ip());
            if min_port > addr.port() {
                min_port = addr.port()
            }
            if max_port < addr.port() {
                max_port = addr.port()
            }
        }
    }
    if hash_set.is_empty() {
        Ok((nat_type, vec![], 0))
    } else {
        Ok((
            nat_type,
            hash_set.into_iter().collect(),
            max_port - min_port,
        ))
    }
}

fn test_nat(udp: &UdpSocket, stun_server: &String) -> io::Result<HashSet<SocketAddr>> {
    udp.connect(stun_server)?;
    let tid = rand::thread_rng().next_u64() as u128;
    let mut addr = HashSet::new();
    let (mapped_addr1, changed_addr1) = test_nat_(&udp, stun_server, true, true, tid)?;
    if mapped_addr1.is_ipv4() {
        addr.insert(mapped_addr1);
    }
    if let Some(changed_addr1) = changed_addr1 {
        if udp.connect(changed_addr1).is_ok() {
            match test_nat_(&udp, stun_server, false, false, tid + 1) {
                Ok((mapped_addr2, _)) => {
                    if mapped_addr2.is_ipv4() {
                        addr.insert(mapped_addr1);
                    }
                }
                Err(e) => {
                    log::warn!("stun {} error {:?} ", stun_server, e);
                }
            }
        }
    }
    log::info!(
        "stun {} mapped_addr {:?}  changed_addr {:?}",
        stun_server,
        addr,
        changed_addr1,
    );

    Ok(addr)
}

fn test_nat_(
    udp: &UdpSocket,
    stun_server: &String,
    change_ip: bool,
    change_port: bool,
    tid: u128,
) -> io::Result<(SocketAddr, Option<SocketAddr>)> {
    for _ in 0..2 {
        let mut buf = [0u8; 28];
        let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
        msg.typ(stun_format::MsgType::BindingRequest);
        msg.tid(tid);
        msg.add_attr(Attr::ChangeRequest {
            change_ip,
            change_port,
        });
        udp.send(msg.as_bytes())?;
        let mut buf = [0; 10240];
        let (len, _addr) = match udp.recv_from(&mut buf) {
            Ok(rs) => rs,
            Err(e) => {
                log::warn!("stun {} error {:?}", stun_server, e);
                continue;
            }
        };
        let msg = stun_format::Msg::from(&buf[..len]);
        let mut mapped_addr = None;
        let mut changed_addr = None;
        for x in msg.attrs_iter() {
            match x {
                Attr::MappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(stun_addr(addr));
                    }
                }
                Attr::ChangedAddress(addr) => {
                    if changed_addr.is_none() {
                        let _ = changed_addr.insert(stun_addr(addr));
                    }
                }
                Attr::XorMappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(stun_addr(addr));
                    }
                }
                _ => {}
            }
            if changed_addr.is_some() && mapped_addr.is_some() {
                return Ok((mapped_addr.unwrap(), changed_addr));
            }
        }
        if let Some(addr) = mapped_addr {
            return Ok((addr, changed_addr));
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "stun response err"))
}

fn stun_addr(addr: stun_format::SocketAddr) -> SocketAddr {
    match addr {
        stun_format::SocketAddr::V4(ip, port) => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        }
        stun_format::SocketAddr::V6(ip, port) => {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        }
    }
}

const TAG: u128 = 1827549368 << 64;

pub fn send_stun_request() -> Vec<u8> {
    let mut buf = [0u8; 28];
    let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
    msg.typ(stun_format::MsgType::BindingRequest);
    let id = rand::thread_rng().next_u64() as u128;
    msg.tid(id | TAG);
    msg.add_attr(Attr::ChangeRequest {
        change_ip: false,
        change_port: false,
    });
    msg.as_bytes().to_vec()
}

pub fn recv_stun_response(buf: &[u8]) -> Option<SocketAddr> {
    let msg = stun_format::Msg::from(buf);
    if let Some(tid) = msg.tid() {
        if tid & TAG != TAG {
            return None;
        }
    }
    for x in msg.attrs_iter() {
        match x {
            Attr::MappedAddress(addr) => {
                return Some(stun_addr(addr));
            }
            Attr::XorMappedAddress(addr) => {
                return Some(stun_addr(addr));
            }
            _ => {}
        }
    }
    None
}
