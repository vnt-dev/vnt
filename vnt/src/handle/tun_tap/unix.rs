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
use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tun::Device;

const STOP: Token = Token(0);
const FD: Token = Token(1);

pub(crate) fn start_simple(
    stop_manager: StopManager,
    context: &ChannelContext,
    device: Arc<Device>,
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
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), STOP)?);
    let _waker = waker.clone();
    let worker = {
        stop_manager.add_listener("tun_device".into(), move || {
            if let Err(e) = waker.wake() {
                log::warn!("{:?}", e);
            }
        })?
    };
    let worker_cell = Arc::new(AtomicCell::new(Some(worker)));
    let _worker_cell = worker_cell.clone();
    device_stop.set_stop_fn(move || {
        if let Some(worker) = _worker_cell.take() {
            worker.stop_self()
        }
    });
    if let Err(e) = start_simple0(
        poll,
        context,
        device,
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
    };
    device_stop.stopped();
    if let Some(worker) = worker_cell.take() {
        worker.stop_all();
    }
    drop(_waker);
    Ok(())
}

fn start_simple0(
    mut poll: Poll,
    context: &ChannelContext,
    device: Arc<Device>,
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
    let fd = device.as_tun_fd();
    fd.set_nonblock()?;
    SourceFd(&fd.as_raw_fd()).register(poll.registry(), FD, Interest::READABLE)?;
    let mut events = Events::with_capacity(4);
    #[cfg(not(target_os = "macos"))]
    let start = 12;
    #[cfg(target_os = "macos")]
    let start = 12 - 4;
    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            crate::ignore_io_interrupted(e)?;
            continue;
        }
        for event in events.iter() {
            if event.token() == STOP {
                return Ok(());
            }
            let mut retries = 0;
            loop {
                let len = match fd.read(&mut buf[start..]) {
                    Ok(len) => len + start,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            retries += 1;
                            if retries < 8 {
                                continue;
                            }
                            break;
                        }
                        Err(e)?
                    }
                };
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
                        log::warn!("{:?}", e)
                    }
                }
            }
        }
    }
}
