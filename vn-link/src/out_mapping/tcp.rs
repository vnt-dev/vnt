use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use tokio::net::TcpStream;

use lwip_rs::tcp_listener::TcpListener;
use lwip_rs::tcp_stream::TcpStream as LwIpTcpStream;
use vnt::handle::CurrentDeviceInfo;

pub async fn tcp_mapping_listen(
    mut tcp_listener: TcpListener,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
) {
    loop {
        let stream = match tcp_listener.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!("tcp_mapping_listen err  {:?}", e);
                break;
            }
        };
        let device_info = current_device.load();
        tokio::spawn(async move {
            let dest = stream.dest_addr();
            let src = stream.src_addr();
            if let Err(e) = tcp_mapping_handle(stream, device_info).await {
                log::warn!("tcp_mapping_handle {}->{} {:?}", src, dest, e)
            }
        });
    }
}

async fn tcp_mapping_handle(
    tcp_stream: LwIpTcpStream,
    device_info: CurrentDeviceInfo,
) -> anyhow::Result<()> {
    let mut dest = tcp_stream.dest_addr();
    // let src = tcp_stream.src_addr();
    if let IpAddr::V4(ip) = dest.ip() {
        if ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
            || ip == device_info.virtual_ip
            || ip == device_info.broadcast_ip
        {
            //是自己
            dest.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
    }
    let peer_stream = TcpStream::connect(dest).await?;
    if dest.port() == peer_stream.local_addr()?.port() {
        return Err(anyhow::anyhow!("tcp port loop"));
    }
    tcp_copy(tcp_stream, peer_stream);
    Ok(())
}

pub(crate) fn tcp_copy(lw_tcp: LwIpTcpStream, tokio_tcp: TcpStream) {
    let (mut write, mut read) = lw_tcp.into_split();
    let (mut peer_read, mut peer_write) = tokio_tcp.into_split();
    tokio::spawn(async move { tokio::io::copy(&mut read, &mut peer_write).await });
    tokio::spawn(async move { tokio::io::copy(&mut peer_read, &mut write).await });
}
