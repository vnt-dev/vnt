use crate::packet::ethernet::protocol::Protocol;
use std::io;

pub mod arp;
pub mod ethernet;

const MAC: [u8; 6] = [0xf, 0xf, 0xf, 0xf, 0xe, 0x9];
pub fn read_tap<W, R>(buf: &mut [u8], read_fn: R, write_fn: W) -> io::Result<usize>
where
    W: Fn(&[u8]) -> io::Result<usize>,
    R: Fn(&mut [u8]) -> io::Result<usize>,
{
    let mut eth_buf = [0; 65536];
    loop {
        let len = read_fn(&mut eth_buf)?;
        //处理arp包
        let mut ether = ethernet::packet::EthernetPacket::unchecked(&mut eth_buf[..len]);
        match ether.protocol() {
            Protocol::Ipv4 => {
                let len = ether.payload().len();
                if len > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::Other, "short"));
                }
                buf[..len].copy_from_slice(ether.payload());
                return Ok(len);
            }
            Protocol::Arp => {
                let mut arp_packet = arp::packet::ArpPacket::unchecked(ether.payload_mut());
                let sender_h: [u8; 6] = arp_packet.sender_hardware_addr().try_into().unwrap();
                let sender_p: [u8; 4] = arp_packet.sender_protocol_addr().try_into().unwrap();
                let target_p: [u8; 4] = arp_packet.target_protocol_addr().try_into().unwrap();
                if target_p == [0, 0, 0, 0] || sender_p == [0, 0, 0, 0] || target_p == sender_p {
                    continue;
                }
                if arp_packet.op_code() == 1 {
                    //回复一个默认的MAC
                    arp_packet.set_op_code(2);
                    arp_packet.set_target_hardware_addr(&sender_h);
                    arp_packet.set_target_protocol_addr(&sender_p);
                    arp_packet.set_sender_protocol_addr(&target_p);
                    arp_packet.set_sender_hardware_addr(&MAC);
                    ether.set_destination(&sender_h);
                    ether.set_source(&MAC);
                    write_fn(ether.buffer)?;
                }
            }
            _ => {
                //忽略这些数据
            }
        }
    }
}
pub fn write_tap<W>(buf: &[u8], write_fn: W, mac: &[u8; 6]) -> io::Result<usize>
where
    W: Fn(&[u8]) -> io::Result<usize>,
{
    // 封装二层数据
    let mut ether = ethernet::packet::EthernetPacket::unchecked(vec![0; 14 + buf.len()]);
    ether.set_source(&MAC);
    ether.set_destination(mac);
    ether.set_protocol(Protocol::Ipv4);
    ether.payload_mut().copy_from_slice(buf);
    write_fn(&ether.buffer)
}
