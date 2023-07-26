use std::net::Ipv4Addr;

use byteorder::BigEndian;
use byteorder::ReadBytesExt;

pub mod icmp;
pub mod igmp;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod ethernet;
pub mod arp;
// pub enum IpUpperLayer<B> {
//     UDP(UdpPacket<B>),
//     Unknown(B),
// }
//
// impl<B: AsRef<[u8]>> fmt::Debug for IpUpperLayer<B> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             IpUpperLayer::UDP(p) => {
//                 f.debug_struct("udp::Packet")
//                     .field("data", p).finish()
//             }
//             IpUpperLayer::Unknown(p) => {
//                 f.debug_struct("Unknown")
//                     .field("data", &p.as_ref()).finish()
//             }
//         }
//     }
// }

/// https://datatracker.ietf.org/doc/html/rfc1071 4.1节
///
/// 计算校验和，各协议都是通用的
/// 计算：
/// 首先将校验和置0，然后对首部每个16位数进行二进制反码求和，
/// 得到校验和之后，持续取高16位加到低16位，直到高16位全为0
/// 最后取反
///
/// 校验：
/// 在已有校验和的情况下，再计算校验和，正确的数据计算得到的值为0
/*
unsigned short getChecksum(unsigned short * iphead, int count)
{
    unsigned long int sum = 0;
    unsigned short checksum = 0;

    printf("\nStarting adress: %p\n", iphead);

    while(count > 1) {
        sum += * (unsigned short *) (iphead);
        count -=2;
        printf("a: %p, content is: %d, new sum: %ld\n", iphead, (unsigned short) *(iphead), sum);
        iphead++;
    }

    if(count > 0) {
        sum += * (unsigned short *) (iphead);
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;

    return checksum;
}
 */
pub fn cal_checksum(buffer: &[u8]) -> u16 {
    use std::io::Cursor;
    let mut sum = 0;
    let length = buffer.len();
    let mut buffer = Cursor::new(buffer);
    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        sum += u32::from(value);
    }
    if length & 1 == 1 {
        //奇数,说明还有一位,不足的补0
        sum += u32c(buffer.read_u8().unwrap(), 0);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// ipv4上层协议校验和计算方式
/// ipv4 udp伪首部 用于参与计算首部校验和
/*
   0      7 8     15 16    23 24    31
   +--------+--------+--------+--------+
   |          source address           |
   +--------+--------+--------+--------+
   |        destination address        |
   +--------+--------+--------+--------+
   |  zero  |protocol|       length    |
   +--------+--------+--------+--------+
*/
pub fn ipv4_cal_checksum(
    buffer: &[u8],
    src_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
    protocol: u8,
) -> u16 {
    use std::io::Cursor;
    let length = buffer.len();
    let mut sum = 0;
    let src_ip = src_ip.octets();
    sum += u32c(src_ip[0], src_ip[1]);
    sum += u32c(src_ip[2], src_ip[3]);
    let dest_ip = dest_ip.octets();
    sum += u32c(dest_ip[0], dest_ip[1]);
    sum += u32c(dest_ip[2], dest_ip[3]);
    sum += u32c(0, protocol);
    sum += length as u32;
    let mut buffer = Cursor::new(buffer);
    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        sum += u32::from(value);
    }
    if length & 1 == 1 {
        //奇数,说明还有一位
        sum += u32c(buffer.read_u8().unwrap(), 0);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[inline]
fn u32c(x: u8, y: u8) -> u32 {
    ((x as u32) << 8) | y as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let sum = cal_checksum(&[255, 255]);
        println!("{:?}", sum);
    }
}
