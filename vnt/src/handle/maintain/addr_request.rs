use std::sync::Arc;
use std::time::Duration;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::ChannelContext;
use crate::channel::punch::NatType;
use crate::handle::{BaseConfigInfo, CurrentDeviceInfo};
use crate::nat::NatTest;
use crate::util::Scheduler;

pub fn addr_request(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    _config: BaseConfigInfo,
) {
    pub_address_request(scheduler, context, current_device_info.clone(), nat_test, 0);
}

fn pub_address_request(
    scheduler: &Scheduler,
    context: ChannelContext,
    current_device_info: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    count: usize,
) {
    let channel_num = context.channel_num();
    let index = count % channel_num;
    if let Err(e) = addr_request0(&context, &current_device_info, &nat_test, index) {
        log::warn!("{:?}", e);
    }
    let nat_info = nat_test.nat_info();
    let time = if !nat_info.public_ports.contains(&0) && !nat_info.public_ips.is_empty() {
        //对称网络探测端口没啥作用，把频率放低，（锥形网络也只在打洞前需要探测端口，后续可以改改）
        if nat_info.nat_type == NatType::Symmetric {
            600
        } else {
            if index == channel_num - 1 {
                19
            } else {
                9
            }
        }
    } else {
        3
    };

    let rs = scheduler.timeout(Duration::from_secs(time), move |s| {
        pub_address_request(s, context, current_device_info, nat_test, index + 1)
    });
    if !rs {
        log::info!("定时任务停止");
    }
}

fn addr_request0(
    context: &ChannelContext,
    current_device: &AtomicCell<CurrentDeviceInfo>,
    nat_test: &NatTest,
    index: usize,
) -> anyhow::Result<()> {
    let current_dev = current_device.load();
    if current_dev.status.offline() {
        return Ok(());
    }
    let (data, addr) = nat_test.send_data()?;
    context.send_main_udp(index, &data, addr)?;
    Ok(())
}
