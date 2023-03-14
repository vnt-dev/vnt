use crate::tun_device::{TunReader, TunWriter};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun::Device;
use parking_lot::Mutex;

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> crate::error::Result<(TunWriter, TunReader)> {
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        // .queues(2) 用多个队列有兼容性问题
        .up();
    //
    // config.platform(|config| {
    //     config.packet_information(true);
    // });

    let dev = tun::create(&config).unwrap();
    let packet_information = dev.has_packet_information();
    let queue = dev.queue(0).unwrap();
    let reader = queue.reader();
    let writer = queue.writer();
    Ok((
        TunWriter(writer, packet_information, Arc::new(Mutex::new(dev))),
        TunReader(reader, packet_information),
    ))
}
