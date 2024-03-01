use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;

use packet::icmp::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use tun::device::IFace;
use tun::Device;

use crate::channel::context::Context;
use crate::cipher::Cipher;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::channel_group::{channel_group, GroupSyncSender};
use crate::handle::CurrentDeviceInfo;
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::util::{SingleU64Adder, StopManager};

fn icmp(device_writer: &Device, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> io::Result<()> {
    if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            device_writer.write(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

/// 接收tun数据，并且转发到udp上
fn handle(
    context: &Context,
    data: &mut [u8],
    len: usize,
    device_writer: &Device,
    current_device: CurrentDeviceInfo,
    ip_route: &ExternalRoute,
    #[cfg(feature = "ip_proxy")] proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
) -> io::Result<()> {
    if len > 12 && data[12] >> 4 != 4 {
        //忽略非ipv4包
        return Ok(());
    }
    let ipv4_packet = IpV4Packet::new(&mut data[12..len])?;
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    if src_ip == dest_ip {
        return icmp(&device_writer, ipv4_packet);
    }
    return crate::handle::tun_tap::base_handle(
        context,
        data,
        len,
        current_device,
        ip_route,
        #[cfg(feature = "ip_proxy")]
        proxy_map,
        client_cipher,
        server_cipher,
    );
}

pub fn start(
    stop_manager: StopManager,
    context: Context,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    parallel: usize,
    mut up_counter: SingleU64Adder,
) -> io::Result<()> {
    let worker = {
        let device = device.clone();
        stop_manager.add_listener("tun_device".into(), move || {
            if let Err(e) = device.shutdown() {
                log::warn!("{:?}", e);
            }
        })?
    };
    if parallel > 1 {
        let (sender, receivers) = channel_group::<(Vec<u8>, usize)>(parallel, 16);
        for (index, receiver) in receivers.into_iter().enumerate() {
            let context = context.clone();
            let device = device.clone();
            let current_device = current_device.clone();
            let ip_route = ip_route.clone();
            #[cfg(feature = "ip_proxy")]
            let ip_proxy_map = ip_proxy_map.clone();
            let client_cipher = client_cipher.clone();
            let server_cipher = server_cipher.clone();
            thread::Builder::new()
                .name(format!("tun_handler_{}", index))
                .spawn(move || {
                    while let Ok((mut buf, len)) = receiver.recv() {
                        #[cfg(not(target_os = "macos"))]
                        let start = 0;
                        #[cfg(target_os = "macos")]
                        let start = 4;
                        match handle(
                            &context,
                            &mut buf[start..],
                            len,
                            &device,
                            current_device.load(),
                            &ip_route,
                            #[cfg(feature = "ip_proxy")]
                            &ip_proxy_map,
                            &client_cipher,
                            &server_cipher,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!("{:?}", e)
                            }
                        }
                    }
                })?;
        }
        thread::Builder::new()
            .name("tun_handler".into())
            .spawn(move || {
                if let Err(e) = start_multi(stop_manager, device, sender, &mut up_counter) {
                    log::warn!("stop:{}", e);
                }
                worker.stop_all();
            })?;
    } else {
        thread::Builder::new()
            .name("tun_handler".into())
            .spawn(move || {
                if let Err(e) = start_simple(
                    stop_manager,
                    &context,
                    device,
                    current_device,
                    ip_route,
                    #[cfg(feature = "ip_proxy")]
                    ip_proxy_map,
                    client_cipher,
                    server_cipher,
                    &mut up_counter,
                ) {
                    log::warn!("stop:{}", e);
                }
                worker.stop_all();
            })?;
    }
    Ok(())
}

fn start_simple(
    stop_manager: StopManager,
    context: &Context,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    let mut buf = [0; 1024 * 16];
    loop {
        if stop_manager.is_stop() {
            return Ok(());
        }
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        #[cfg(any(target_os = "macos"))]
        let mut buf = &mut buf[4..];
        // buf是重复利用的，需要重置头部
        buf[..12].fill(0);
        match handle(
            context,
            &mut buf,
            len,
            &device,
            current_device.load(),
            &ip_route,
            #[cfg(feature = "ip_proxy")]
            &ip_proxy_map,
            &client_cipher,
            &server_cipher,
        ) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("{:?}", e)
            }
        }
    }
}

fn start_multi(
    stop_manager: StopManager,
    device: Arc<Device>,
    mut group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    loop {
        if stop_manager.is_stop() {
            return Ok(());
        }
        let mut buf = vec![0; 1024 * 16];
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        if group_sync_sender.send((buf, len)).is_err() {
            return Ok(());
        }
    }
}
