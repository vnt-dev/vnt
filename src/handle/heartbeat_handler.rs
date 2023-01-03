use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use chrono::Local;

use crate::error::*;
use crate::handle::DIRECT_ROUTE_TABLE;
use crate::protocol::control_packet::PingPacket;
use crate::protocol::{control_packet, NetPacket, Protocol, Version};
use crate::DEVICE_LIST;

pub fn handle_loop(udp: UdpSocket, server_addr: SocketAddr) -> Result<()> {
    const INTERVAL: u64 = 3000;
    const MAX_INTERVAL: i64 = 3000 * 5;
    let mut buf = [0u8; (4 + 8 + 4)];
    let mut net_packet = NetPacket::new(&mut buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
    net_packet.set_ttl(255);
    loop {
        let current_time = Local::now().timestamp();
        {
            let mut ping = PingPacket::new(net_packet.payload_mut())?;
            ping.set_time(current_time);
            let epoch = { DEVICE_LIST.lock().0 };
            ping.set_epoch(epoch);
        }
        udp.send_to(net_packet.buffer(), server_addr)?;
        for x in DIRECT_ROUTE_TABLE.iter() {
            let virtual_ip = x.key().clone();
            let route = x.value().clone();
            drop(x);
            if current_time - route.recv_time <= MAX_INTERVAL {
                udp.send_to(net_packet.buffer(), route.address)?;
            } else {
                DIRECT_ROUTE_TABLE.remove_if(&virtual_ip, |_, route| {
                    current_time - route.recv_time > MAX_INTERVAL
                });
            }
        }
        thread::sleep(Duration::from_millis(INTERVAL));
    }
}
