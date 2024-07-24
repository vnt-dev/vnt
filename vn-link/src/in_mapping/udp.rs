use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use lwip_rs::udp::UdpSocketWrite;
use vnt::handle::CurrentDeviceInfo;

pub async fn udp_mapping_start(
    udp: UdpSocket,
    lwip_udp_write: UdpSocketWrite,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    in_udp_map: &Arc<
        Mutex<
            HashMap<
                (SocketAddr, SocketAddr),
                (Arc<UdpSocket>, Option<SocketAddr>, Arc<AtomicCell<Instant>>),
            >,
        >,
    >,

    dest: SocketAddr,
) {
    let udp = Arc::new(udp);
    let mut buf = [0u8; 65536];
    loop {
        let (len, addr) = match udp.recv_from(&mut buf).await {
            Ok(rs) => rs,
            Err(e) => {
                log::warn!("recv_from {} {}", dest, e);
                continue;
            }
        };
        let current_info = current_device.load();
        if current_info.virtual_ip.is_unspecified() {
            continue;
        }
        if let IpAddr::V4(ip) = dest.ip() {
            if ip == current_info.virtual_ip {
                //防止用错参数的
                log::warn!("目的地址不能是本地虚拟ip udp->{}", dest);
                continue;
            }
        }
        let src = SocketAddr::new(IpAddr::V4(current_info.virtual_ip), addr.port());
        in_udp_map.lock().insert(
            (dest, src),
            (
                udp.clone(),
                Some(addr),
                Arc::new(AtomicCell::new(Instant::now())),
            ),
        );

        if let Err(e) = lwip_udp_write.send(&buf[..len], &src, &dest) {
            log::warn!("lwip_udp_write {}->{} {}", src, dest, e);
        }
    }
}
