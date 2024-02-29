use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::Context;
use crate::cipher::Cipher;
use crate::handle::{BaseConfigInfo, CurrentDeviceInfo};
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{control_packet, NetPacket, Protocol, Version, MAX_TTL};
use crate::util::Scheduler;

pub fn addr_request(
    scheduler: &Scheduler,
    context: Context,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    server_cipher: Cipher,
    config: BaseConfigInfo,
) {
    addr_request0(&context, &current_device_info, &server_cipher, &config);
    // 9秒发送一次
    let rs = scheduler.timeout(Duration::from_secs(9), |s| {
        addr_request(s, context, current_device_info, server_cipher, config)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

pub fn addr_request0(
    context: &Context,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    server_cipher: &Cipher,
    config: &BaseConfigInfo,
) {
    let mut current_dev = current_device.load();
    // 探测服务端地址变化
    if let Ok(mut addr) = config.server_addr.to_socket_addrs() {
        if let Some(addr) = addr.next() {
            if addr != current_dev.connect_server {
                let mut tmp = current_dev.clone();
                tmp.connect_server = addr;
                let rs = current_device.compare_exchange(current_dev, tmp);
                current_dev.connect_server = addr;
                log::info!(
                    "服务端地址变化,旧地址:{}，新地址:{},替换结果:{}",
                    current_dev.connect_server,
                    addr,
                    rs.is_ok()
                );
            }
        }
    }
    if current_dev.connect_server.is_ipv4() {
        // 如果连接的是ipv4服务，则探测公网端口
        let gateway_ip = current_dev.virtual_gateway;
        let src_ip = current_dev.virtual_ip;
        let mut packet = NetPacket::new_encrypt([0; 12 + ENCRYPTION_RESERVED]).unwrap();
        packet.set_version(Version::V1);
        packet.set_gateway_flag(true);
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::AddrRequest.into());
        packet.first_set_ttl(MAX_TTL);
        packet.set_source(src_ip);
        packet.set_destination(gateway_ip);
        if let Err(e) = server_cipher.encrypt_ipv4(&mut packet) {
            log::warn!("AddrRequest err={:?}", e)
        } else {
            context.try_send_all_main(packet.buffer(), current_dev.connect_server);
        }
    }
}
