use crate::channel::context::ChannelContext;
use crate::channel::BUFFER_SIZE;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::util::StopManager;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun_rs::{InterruptEvent, SyncDevice};

pub(crate) fn start_simple(
    stop_manager: StopManager,
    context: &ChannelContext,
    device: Arc<SyncDevice>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    compressor: Compressor,
    device_stop: DeviceStop,
    allow_wire_guard: bool,
) -> anyhow::Result<()> {
    let event = Arc::new(InterruptEvent::new()?);
    let worker = {
        let event = event.clone();
        stop_manager.add_listener("tun_device".into(), move || {
            if let Err(e) = event.trigger() {
                log::warn!("{:?}", e);
            }
        })?
    };
    let worker_cell = Arc::new(AtomicCell::new(Some(worker)));

    {
        let worker_cell = worker_cell.clone();
        device_stop.set_stop_fn(move || {
            if let Some(worker) = worker_cell.take() {
                worker.stop_self()
            }
        });
    }
    if let Err(e) = start_simple0(
        context,
        device,
        event,
        current_device,
        ip_route,
        #[cfg(feature = "ip_proxy")]
        ip_proxy_map,
        client_cipher,
        server_cipher,
        device_map,
        compressor,
        allow_wire_guard,
    ) {
        log::error!("{:?}", e);
    }
    device_stop.stopped();
    if let Some(worker) = worker_cell.take() {
        worker.stop_all();
    }
    Ok(())
}

fn start_simple0(
    context: &ChannelContext,
    device: Arc<SyncDevice>,
    event: Arc<InterruptEvent>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    compressor: Compressor,
    allow_wire_guard: bool,
) -> anyhow::Result<()> {
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    loop {
        let len = device.recv_intr(&mut buf[12..],&event)? + 12;
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
            &device_map,
            &compressor,
            allow_wire_guard,
        ) {
            Ok(_) => {}
            Err(e) => {
                log::warn!("tun/tap {:?}", e)
            }
        }
    }
}
