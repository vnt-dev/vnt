use std::io;
use std::io::{Error, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::process::Command;

use bytes::BufMut;
use tun::Device;
use tun::platform::posix::{Reader, Writer};

use crate::tun_device::{TunReader, TunWriter};

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
        .up();

    config.platform(|config| {
        config.packet_information(true);
    });

    let mut dev = tun::create(&config).unwrap();
    let packet_information = dev.has_packet_information();
    let (reader, writer) = dev.split();
    Ok((
        TunWriter(writer, packet_information),
        TunReader(reader, packet_information),
    ))
}

