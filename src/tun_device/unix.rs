use std::io;
use std::io::{Error, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use bytes::BufMut;
use tun::Device;
use tun::platform::posix::{Reader, Writer};

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> crate::error::Result<(TunWriter, TunReader)> {
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });

    let dev = tun::create(&config).unwrap();

    // let up_eth_str: String = format!("ifconfig utun3 {:?} {:?} up ", address, gateway);
    let route_add_str: String = format!(
        "sudo route -n add -net {:?} -netmask {:?} {:?}",
        address, netmask, gateway
    );
    //
    // let up_eth_out = Command::new("sh")
    //     .arg("-c")
    //     .arg(up_eth_str)
    //     .output()
    //     .expect("sh exec error!");
    // if !up_eth_out.status.success() {
    //     return Err(crate::error::Error::Stop(format!("设置地址失败:{:?}", up_eth_out)));
    // }
    // println!("{:?}", up_eth_out);
    let if_config_out = Command::new("sh")
        .arg("-c")
        .arg(route_add_str)
        .output()
        .expect("sh exec error!");
    if !if_config_out.status.success() {
        return Err(crate::error::Error::Stop(format!("设置路由失败:{:?}", if_config_out)));
    }
    // println!("{:?}", if_config_out);
    // let cmd_str: String = " ifconfig|grep  flags=8051|awk -F ':' '{print $1}'|tail -1".to_string();
    //
    // let cmd_str_out = Command::new("sh")
    //     .arg("-c")
    //     .arg(cmd_str)
    //     .output()
    //     .expect("sh exec error!");
    // if !cmd_str_out.status.success(){
    //     return Err(Error::Stop(format!("设置路由失败:{:?}", cmd_str_out)));
    // }
    // println!("{:?}", cmd_str_out);
    let packet_information = dev.has_packet_information();
    let (reader, writer) = dev.split();
    Ok((
        TunWriter(writer, packet_information),
        TunReader(reader, packet_information),
    ))
}

pub struct TunReader(Reader, bool);

impl TunReader {
    pub fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> io::Result<&mut [u8]> {
        let len = self.0.read(buf)?;
        if self.1 {
            Ok(&mut buf[4..len])
        } else {
            Ok(&mut buf[..len])
        }
    }
}

pub struct TunWriter(Writer, bool);

impl TunWriter {
    pub fn write(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.1 {
            let mut buf = Vec::<u8>::with_capacity(4 + packet.len());
            buf.put_u16(0);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            buf.put_u16(libc::PF_INET as u16);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            buf.put_u16(libc::ETH_P_IP as u16);
            buf.extend_from_slice(packet);
            self.0.write_all(&buf)
        } else {
            self.0.write_all(packet)
        }
    }
}

// pub fn main1() {
//     loop {
//         let len = reader.read(&mut buffer).unwrap();
//         println!("{:?}", &buffer[..len]);
//         match ip::Packet::new(&buffer[4..len]) {
//             Ok(ip::Packet::V4(pkt)) => {
//                 match icmp::Packet::new(pkt.payload()) {
//                     Ok(icmp) => {
//                         match icmp.echo() {
//                             Ok(icmp) => {
//                                 println!("{:?}", icmp);
//                                 let reply = ip::v4::Builder::default()
//                                     .id(0x42)
//                                     .unwrap()
//                                     .ttl(64)
//                                     .unwrap()
//                                     .source(pkt.destination())
//                                     .unwrap()
//                                     .destination(pkt.source())
//                                     .unwrap()
//                                     .icmp()
//                                     .unwrap()
//                                     .echo()
//                                     .unwrap()
//                                     .reply()
//                                     .unwrap()
//                                     .identifier(icmp.identifier())
//                                     .unwrap()
//                                     .sequence(icmp.sequence())
//                                     .unwrap()
//                                     .payload(icmp.payload())
//                                     .unwrap()
//                                     .build()
//                                     .unwrap();
//                                 let l = reply.len();
//                                 &mut buffer[4..(l + 4)].copy_from_slice(&reply);
//                                 // writer.write_all(&buffer[..4]).unwrap();
//                                 writer.write_all(&buffer[..(l + 4)]).unwrap();
//                             }
//                             Err(_) => {}
//                         }
//                     }
//                     Err(_) => {}
//                 }
//             }
//             _ => {}
//         }
//     }
// }
