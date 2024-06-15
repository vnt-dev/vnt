use crossbeam_utils::atomic::AtomicCell;
use lwip_rs::udp::{UdpSocketRead, UdpSocketWrite};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use vnt::handle::CurrentDeviceInfo;

pub async fn udp_mapping_start(
    lwip_udp_write: UdpSocketWrite,
    mut lwip_udp_read: UdpSocketRead,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    in_udp_map: Arc<
        Mutex<
            HashMap<
                (SocketAddr, SocketAddr),
                (Arc<UdpSocket>, Option<SocketAddr>, Arc<AtomicCell<Instant>>),
            >,
        >,
    >,
) {
    loop {
        let (buf, src, dest) = match lwip_udp_read.recv().await {
            Ok(rs) => rs,
            Err(e) => {
                log::warn!("udp_mapping err  {:?}", e);
                break;
            }
        };
        if let Err(e) = handle(
            &current_device,
            &lwip_udp_write,
            &in_udp_map,
            buf,
            src,
            dest,
        )
        .await
        {
            log::warn!("udp_mapping err {}->{} {:?}", src, dest, e)
        }
    }
}

async fn handle(
    current_device: &AtomicCell<CurrentDeviceInfo>,
    lwip_udp_write: &UdpSocketWrite,
    map: &Arc<
        Mutex<
            HashMap<
                (SocketAddr, SocketAddr),
                (Arc<UdpSocket>, Option<SocketAddr>, Arc<AtomicCell<Instant>>),
            >,
        >,
    >,
    buf: Vec<u8>,
    src: SocketAddr,
    dest: SocketAddr,
) -> anyhow::Result<()> {
    let option = map.lock().get(&(src, dest)).cloned();

    if let Some((dest_udp, addr, time)) = option {
        time.store(Instant::now());
        if let Some(addr) = addr {
            dest_udp.send_to(&buf, addr).await?;
        } else {
            dest_udp.send(&buf).await?;
        }
    } else {
        let mut real_dest = dest;
        let peer_udp_socket = match UdpSocket::bind(format!("0.0.0.0:{}", src.port())).await {
            Ok(udp) => udp,
            Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
        };
        if let IpAddr::V4(ip) = dest.ip() {
            let device_info = current_device.load();
            if ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip == device_info.virtual_ip
                || ip == device_info.broadcast_ip
            {
                //是自己
                real_dest.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
        }
        peer_udp_socket.connect(real_dest).await?;
        peer_udp_socket.send(&buf).await?;
        let peer_udp_socket = Arc::new(peer_udp_socket);
        let time = Arc::new(AtomicCell::new(Instant::now()));
        let map = map.clone();
        map.lock()
            .insert((src, dest), (peer_udp_socket.clone(), None, time.clone()));
        let lwip_udp_write = lwip_udp_write.clone();
        tokio::spawn(async move {
            peer_udp_handle(peer_udp_socket, lwip_udp_write, src, dest, time).await;
            map.lock().remove(&(src, dest));
        });
    }
    Ok(())
}

async fn peer_udp_handle(
    peer_udp_socket: Arc<UdpSocket>,
    lwip_udp_write: UdpSocketWrite,
    src: SocketAddr,
    dest: SocketAddr,
    time: Arc<AtomicCell<Instant>>,
) {
    let mut buf = [0u8; 65536];
    loop {
        match tokio::time::timeout(Duration::from_secs(600), peer_udp_socket.recv(&mut buf)).await {
            Ok(rs) => match rs {
                Ok(len) => match lwip_udp_write.send(&buf[..len], &dest, &src) {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("udp proxy {}->{} {:?}", dest, src, e);
                        break;
                    }
                },
                Err(e) => {
                    log::warn!("udp proxy {}->{} {:?}", dest, src, e);
                    break;
                }
            },
            Err(_) => {
                if time.load().elapsed() > Duration::from_secs(580) {
                    //超时关闭
                    log::warn!("udp proxy timeout {}->{}", dest, src,);
                    break;
                }
            }
        }
    }
}
