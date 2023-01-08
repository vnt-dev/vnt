use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use chrono::Local;
use tokio::sync::watch::Receiver;
use tokio::time::sleep;

use crate::{CurrentDeviceInfo, DEVICE_LIST};
use crate::error::*;
use crate::handle::{ApplicationStatus, DIRECT_ROUTE_TABLE};
use crate::protocol::{control_packet, NetPacket, Protocol, Version};
use crate::protocol::control_packet::PingPacket;

pub async fn start<F>(status_watch: Receiver<ApplicationStatus>,
                      udp: UdpSocket, cur_info: CurrentDeviceInfo, stop_fn: F)
    where F: FnOnce() + Send + 'static {
    tokio::spawn(async move {
        match handle_loop(status_watch, udp, cur_info.connect_server).await {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}",e)
            }
        }
        stop_fn();
    });
}

async fn handle_loop(mut status_watch: Receiver<ApplicationStatus>, udp: UdpSocket, server_addr: SocketAddr) -> Result<()> {
    const INTERVAL: u64 = 3000;
    const MAX_INTERVAL: i64 = 3000 * 3;
    let mut buf = [0u8; (4 + 8 + 4)];
    let mut net_packet = NetPacket::new(&mut buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(Protocol::Control);
    net_packet.set_transport_protocol(control_packet::Protocol::Ping.into());
    net_packet.set_ttl(255);
    loop {
        let current_time = Local::now().timestamp_millis();
        {
            let mut ping = PingPacket::new(net_packet.payload_mut())?;
            ping.set_time(current_time);
            let epoch = { DEVICE_LIST.lock().0 };
            ping.set_epoch(epoch);
        }
        let _ = udp.send_to(net_packet.buffer(), server_addr);
        for x in DIRECT_ROUTE_TABLE.iter() {
            let virtual_ip = x.key().clone();
            let route = x.value().clone();
            drop(x);
            if current_time - route.recv_time <= MAX_INTERVAL {
                let _ = udp.send_to(net_packet.buffer(), route.address);
            } else {
                DIRECT_ROUTE_TABLE.remove_if(&virtual_ip, |_, route| {
                    current_time - route.recv_time > MAX_INTERVAL
                });
            }
        }
        tokio::select! {
             _ = sleep(Duration::from_millis(INTERVAL))=>{

            }
            status = status_watch.changed() =>{
                status?;
                if *status_watch.borrow() != ApplicationStatus::Starting{
                    return Ok(())
                }
            }
        }
    }
}
