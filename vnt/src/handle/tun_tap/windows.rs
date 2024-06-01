use crate::channel::context::ChannelContext;
use crate::channel::BUFFER_SIZE;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::channel_group::GroupSyncSender;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::util::{SingleU64Adder, StopManager};
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::sync::Arc;
use tun::device::IFace;
use tun::Device;

pub(crate) fn start_simple(
    stop_manager: StopManager,
    context: &ChannelContext,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    up_counter: &mut SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    compressor: Compressor,
) -> anyhow::Result<()> {
    let worker = {
        let device = device.clone();
        stop_manager.add_listener("tun_device".into(), move || {
            if let Err(e) = device.shutdown() {
                log::warn!("{:?}", e);
            }
        })?
    };
    if let Err(e) = start_simple0(
        context,
        device,
        current_device,
        ip_route,
        #[cfg(feature = "ip_proxy")]
        ip_proxy_map,
        client_cipher,
        server_cipher,
        up_counter,
        device_list,
        compressor,
    ) {
        log::error!("{:?}", e);
    }
    worker.stop_all();
    Ok(())
}
fn start_simple0(
    context: &ChannelContext,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    up_counter: &mut SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    compressor: Compressor,
) -> anyhow::Result<()> {
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    loop {
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        // buf是重复利用的，需要重置头部
        buf[..12].fill(0);
        match crate::handle::tun_tap::tun_handler::handle(
            context,
            &mut buf,
            len,
            &mut extend,
            &device,
            current_device.load(),
            &ip_route,
            #[cfg(feature = "ip_proxy")]
            &ip_proxy_map,
            &client_cipher,
            &server_cipher,
            &device_list,
            &compressor,
        ) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("tun/tap {:?}", e)
            }
        }
    }
}
pub(crate) fn start_multi(
    stop_manager: StopManager,
    device: Arc<Device>,
    group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> anyhow::Result<()> {
    let worker = {
        let device = device.clone();
        stop_manager.add_listener("tun_device_multi".into(), move || {
            if let Err(e) = device.shutdown() {
                log::warn!("{:?}", e);
            }
        })?
    };
    if let Err(e) = start_multi0(device, group_sync_sender, up_counter) {
        log::error!("{:?}", e);
    };
    worker.stop_all();
    Ok(())
}
fn start_multi0(
    device: Arc<Device>,
    mut group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> anyhow::Result<()> {
    loop {
        let mut buf = vec![0; 1024 * 16];
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        if group_sync_sender.send((buf, len)).is_err() {
            return Ok(());
        }
    }
}
