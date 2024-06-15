use crate::out_mapping::tcp::tcp_copy;
use crossbeam_utils::atomic::AtomicCell;
use lwip_rs::tcp_stream::TcpStream as LwIpTcpStream;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use vnt::handle::CurrentDeviceInfo;

pub async fn tcp_mapping_listen(
    tcp_listener: TcpListener,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    dest: SocketAddr,
) {
    loop {
        let (stream, addr) = match tcp_listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(e) => {
                log::warn!("tcp_mapping_listen {:?} dest {}", e, dest);
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
                log::warn!("目的地址不能是本地虚拟ip tcp->{}", dest);
                continue;
            }
        }
        let src = SocketAddr::new(IpAddr::V4(current_info.virtual_ip), addr.port());
        tokio::spawn(async move {
            match LwIpTcpStream::connect(src, dest, Duration::from_secs(5)).await {
                Ok(lw_tcp) => {
                    tcp_copy(lw_tcp, stream);
                }
                Err(e) => {
                    log::warn!("{}  {}->{} {}", addr, src, dest, e);
                }
            };
        });
    }
}
