use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use std::{io, thread};

use crate::proto::message::NatType;

// #[derive(Debug, Copy, Clone, PartialEq)]
// pub enum NatType {
//     Symmetric,
//     Cone,
// }
//
// impl Into<u8> for NatType {
//     fn into(self) -> u8 {
//         match self {
//             NatType::Symmetric => 0,
//             NatType::Cone => 1,
//         }
//     }
// }

/// 返回所有公网ip和端口变化范围
pub fn public_ip_list() -> io::Result<(NatType, Vec<Ipv4Addr>, u16)> {
    let mut hash_set = HashSet::new();
    let mut max_port_range = 0;
    let mut nat_type = NatType::Cone;
    let mut port = 88;
    for _ in 0..3 {
        let udp = loop {
            match UdpSocket::bind(SocketAddr::new(IpAddr::from(Ipv4Addr::from(0)), port)) {
                Ok(udp) => {
                    break udp;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::AddrInUse {
                        port += 1;
                        continue;
                    }
                    return Err(e);
                }
            }
        };
        let (set, min_port, max_port) = public_ip_list_(&udp)?;
        drop(udp);
        let port_range = max_port - min_port;
        //有多个ip或者端口有变化，说明是对称nat
        if nat_type == NatType::Cone && (set.len() > 1 || port_range != 0) {
            nat_type = NatType::Symmetric;
        }
        if max_port_range < port_range {
            max_port_range = port_range;
        }
        for x in set {
            hash_set.insert(x);
        }
        thread::sleep(Duration::from_micros(5));
    }
    Ok((nat_type, hash_set.into_iter().collect(), max_port_range))
}

/// 测试样本较少，可能不对
///
/// - 移动宽带：锥形网络、一个ip、端口和局域网端口不相同
/// - 电信宽带：锥形网络、一个ip，端口和局域网端口不相同
/// - 联调宽带：对称网络、端口不变ip轮流用
/// - 移动4g：对称网络、ip端口都变  使用小的端口变化量小
/// - 联通4g：对称网络、只有一个ip 端口变化大
/// - 电信4g：对称网络只有一个ip 公网端口比较连续
/// - 综上：客户端使用小端口，针对对称网络 尝试所有ip 公网端口+-变化量的范围
/// - 打通概率 移动宽带=电信宽带>联调宽带>电信4g>移动4g>>联调4g
pub fn public_ip_list_(udp: &UdpSocket) -> io::Result<(HashSet<Ipv4Addr>, u16, u16)> {
    // println!("local port {:?}", udp.local_addr().unwrap().port());
    udp.set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buf = [0u8; 128];
    let _ = udp.send_to(b"NatTest", "nat1.wherewego.top:35061")?;
    let _ = udp.send_to(b"NatTest", "nat1.wherewego.top:35062")?;
    let _ = udp.send_to(b"NatTest", "nat2.wherewego.top:35061")?;
    let _ = udp.send_to(b"NatTest", "nat2.wherewego.top:35062")?;
    let mut hash_set = HashSet::new();
    let mut count = 0;
    let mut min_port = 65535;
    let mut max_port = 0;
    for _ in 0..4 {
        if let Ok(len) = udp.recv(&mut buf) {
            if len != 16 || &buf[..10] != &b"NatType213"[..] {
                continue;
            }
            let port = u16::from_be_bytes([buf[14], buf[15]]);
            if min_port > port {
                min_port = port;
            }
            if max_port < port {
                max_port = port;
            }
            let ip = Ipv4Addr::new(buf[10], buf[11], buf[12], buf[13]);
            // println!("pub  {:?}:{}", ip, port);
            hash_set.insert(ip);
            count += 1;
        }
    }
    if count <= 1 {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    Ok((hash_set, min_port, max_port))
}

/// 返回nat类型
pub fn nat_test() -> io::Result<NatType> {
    for _ in 0..3 {
        if NatType::Symmetric == nat_test_()? {
            return Ok(NatType::Symmetric);
        }
        thread::sleep(Duration::from_micros(5));
    }
    Ok(NatType::Cone)
}

pub fn nat_test_() -> io::Result<NatType> {
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    udp.set_read_timeout(Some(Duration::from_millis(300)))?;
    let mut buf = [0u8; 128];
    let _ = udp.send_to(b"NatTest", "nat1.wherewego.top:35061")?;
    let _ = udp.send_to(b"NatTest", "nat1.wherewego.top:35062")?;
    let _ = udp.send_to(b"NatTest", "nat2.wherewego.top:35061")?;
    let _ = udp.send_to(b"NatTest", "nat2.wherewego.top:35062")?;
    let mut tmp_ip_port: Option<[u8; 6]> = None;
    let mut count = 0;
    for _ in 0..4 {
        if let Ok(len) = udp.recv(&mut buf) {
            if len != 16 || &buf[..10] != &b"NatType213"[..] {
                continue;
            }
            count += 1;
            let mut ip_port = [0u8; 6];
            ip_port.copy_from_slice(&buf[10..16]);
            if let Some(tmp_ip_port) = &tmp_ip_port {
                if tmp_ip_port != &ip_port {
                    return Ok(NatType::Symmetric);
                }
            } else {
                tmp_ip_port = Some(ip_port);
            }
        }
    }
    if count <= 1 {
        return Err(io::Error::from(io::ErrorKind::TimedOut));
    }
    Ok(NatType::Cone)
}

#[test]
fn nat_test_run() {
    let udp = UdpSocket::bind("0.0.0.0:101").unwrap();
    let print = public_ip_list_(&udp).unwrap();
    println!("{:?}", print);
}
