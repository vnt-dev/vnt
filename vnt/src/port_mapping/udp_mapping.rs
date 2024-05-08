use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub async fn udp_mapping(bind_addr: SocketAddr, destination: String) -> anyhow::Result<()> {
    let udp = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("port proxy UDP binding {:?} failed", bind_addr))?;
    let udp = Arc::new(udp);

    let inner_map: Arc<Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(64)));

    tokio::spawn(async move {
        let mut buf = [0; 65536];
        loop {
            match udp.recv_from(&mut buf).await {
                Ok((len, src_addr)) => {
                    if let Err(e) =
                        udp_mapping0(&buf[..len], src_addr, &inner_map, &udp, &destination).await
                    {
                        log::warn!("udp port mapping {}->{} {:?}", src_addr, destination, e);
                    }
                }
                Err(e) => {
                    log::warn!("port proxy UDP  {:?}", e);
                }
            }
        }
    });
    Ok(())
}

async fn udp_mapping0(
    buf: &[u8],
    src_addr: SocketAddr,
    inner_map: &Arc<Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>>>,
    udp_socket: &Arc<UdpSocket>,
    destination: &String,
) -> anyhow::Result<()> {
    let option = inner_map.lock().get(&src_addr).cloned();
    if let Some((udp, time)) = option {
        time.store(Instant::now());
        udp.send(buf).await?;
    } else {
        let dest_udp = UdpSocket::bind("0.0.0.0:0").await?;
        dest_udp.connect(destination).await?;
        dest_udp.send(buf).await?;
        let destination_addr = dest_udp.peer_addr()?;
        let udp_socket = udp_socket.clone();
        let inner_map = inner_map.clone();
        let dest_udp = Arc::new(dest_udp);
        let time = Arc::new(AtomicCell::new(Instant::now()));
        inner_map
            .lock()
            .insert(src_addr, (dest_udp.clone(), time.clone()));
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match tokio::time::timeout(Duration::from_secs(600), dest_udp.recv(&mut buf)).await
                {
                    Ok(rs) => match rs {
                        Ok(len) => match udp_socket.send_to(&buf[..len], src_addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!(
                                    "udp port mapping {}->{} {:?}",
                                    src_addr,
                                    destination_addr,
                                    e
                                );
                                break;
                            }
                        },
                        Err(e) => {
                            log::warn!(
                                "udp port mapping {}->{} {:?}",
                                src_addr,
                                destination_addr,
                                e
                            );
                            break;
                        }
                    },
                    Err(_) => {
                        if time.load().elapsed() > Duration::from_secs(580) {
                            //超时关闭
                            log::warn!(
                                "udp port mapping timeout {}->{}  ",
                                src_addr,
                                destination_addr
                            );
                            break;
                        }
                    }
                }
            }
            inner_map.lock().remove(&src_addr);
        });
    }
    Ok(())
}
