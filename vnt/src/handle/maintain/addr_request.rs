use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::ChannelContext;
use crate::channel::punch::NatType;
use crate::cipher::Cipher;
use crate::handle::{BaseConfigInfo, CurrentDeviceInfo};
use crate::nat::NatTest;
use crate::protocol::body::ENCRYPTION_RESERVED;
use crate::protocol::{control_packet, NetPacket, Protocol, MAX_TTL};
use crate::util::Scheduler;

pub fn addr_request(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    server_cipher: Cipher,
    nat_test: NatTest,
    _config: BaseConfigInfo,
) {
    pub_address_request(
        scheduler,
        context,
        current_device_info.clone(),
        server_cipher,
        nat_test,
        0,
    );
}

fn pub_address_request(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    server_cipher: Cipher,
    nat_test: NatTest,
    count: usize,
) {
    let channel_num = context.channel_num();
    let index = count % channel_num;
    let mut time = if index == channel_num - 1 { 19 } else { 1 };
    if let Err(e) = addr_request0(
        &context,
        &current_device_info,
        &server_cipher,
        &nat_test,
        index,
    ) {
        log::warn!("{:?}", e);
    }
    let nat_info = nat_test.nat_info();
    if nat_info.nat_type == NatType::Symmetric {
        //对称网络探测端口没啥作用，把频率放低，（锥形网络也只在打洞前需要探测端口，后续可以改改）
        if !nat_info.public_ports.contains(&0) && !nat_info.public_ips.is_empty() {
            time = 600;
        }
    }

    let rs = scheduler.timeout(Duration::from_secs(time), move |s| {
        pub_address_request(
            s,
            context,
            current_device_info,
            server_cipher,
            nat_test,
            index + 1,
        )
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn addr_request0(
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    server_cipher: &Cipher,
    nat_test: &NatTest,
    index: usize,
) -> anyhow::Result<()> {
    let current_dev = current_device.load();
    if current_dev.status.offline() {
        return Ok(());
    }

    if current_dev.connect_server.is_ipv4() && !context.is_main_tcp() {
        // 如果连接的是ipv4服务，则探测公网端口
        let gateway_ip = current_dev.virtual_gateway;
        let src_ip = current_dev.virtual_ip;
        let mut packet = NetPacket::new_encrypt([0; 12 + ENCRYPTION_RESERVED]).unwrap();
        packet.set_default_version();
        packet.set_gateway_flag(true);
        packet.set_protocol(Protocol::Control);
        packet.set_transport_protocol(control_packet::Protocol::AddrRequest.into());
        packet.first_set_ttl(MAX_TTL);
        packet.set_source(src_ip);
        packet.set_destination(gateway_ip);
        server_cipher.encrypt_ipv4(&mut packet)?;
        context.send_main_udp(index, packet.buffer(), current_dev.connect_server)?;
    } else {
        let (data, addr) = nat_test.send_data()?;
        context.send_main_udp(index, &data, addr)?;
    }
    Ok(())
}
