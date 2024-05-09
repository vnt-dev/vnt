use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::channel_group::GroupSyncSender;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::ip_proxy::IpProxyMap;
use crate::util::{SingleU64Adder, StopManager};
use crossbeam_utils::atomic::AtomicCell;
use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};
use parking_lot::Mutex;
use std::io;
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
    up_counter: &mut SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
) -> io::Result<()> {
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), STOP)?);
    let _waker = waker.clone();
    let worker = stop_manager.add_listener("tun_device".into(), move || {
        let _ = waker.wake();
    })?;
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
        up_counter,
        device_list,
    ) {
        log::error!("{:?}", e);
    };
    worker.stop_all();
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
    up_counter: &mut SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
) -> io::Result<()> {
    let mut buf = [0; 1024 * 16];
    let fd = device.as_tun_fd();
    fd.set_nonblock()?;
    SourceFd(&fd.as_raw_fd()).register(poll.registry(), FD, Interest::READABLE)?;
    let mut evnets = Events::with_capacity(4);
    #[cfg(not(target_os = "macos"))]
    let start = 12;
    #[cfg(target_os = "macos")]
    let start = 12 - 4;
    loop {
        poll.poll(&mut evnets, None)?;
        for event in evnets.iter() {
            if event.token() == STOP {
                return Ok(());
            }
            loop {
                let len = match fd.read(&mut buf[start..]) {
                    Ok(len) => len + start,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        Err(e)?
                    }
                };
                //单线程的
                up_counter.add(len as u64);
                // buf是重复利用的，需要重置头部
                buf[..12].fill(0);
                match crate::handle::tun_tap::tun_handler::handle(
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
                    &device_list,
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

pub(crate) fn start_multi(
    stop_manager: StopManager,
    device: Arc<Device>,
    group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), STOP)?);
    let _waker = waker.clone();
    let worker = stop_manager.add_listener("tun_device".into(), move || {
        let _ = waker.wake();
    })?;
    if let Err(e) = start_multi0(poll, device, group_sync_sender, up_counter) {
        log::error!("{:?}", e);
    };
    worker.stop_all();
    drop(_waker);
    Ok(())
}

fn start_multi0(
    mut poll: Poll,
    device: Arc<Device>,
    mut group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    let fd = device.as_tun_fd();
    fd.set_nonblock()?;
    SourceFd(&fd.as_raw_fd()).register(poll.registry(), FD, Interest::READABLE)?;
    let mut evnets = Events::with_capacity(4);
    let mut buf = vec![0; 1024 * 16];
    #[cfg(not(target_os = "macos"))]
    let start = 12;
    #[cfg(target_os = "macos")]
    let start = 12 - 4;
    loop {
        poll.poll(&mut evnets, None)?;
        for event in evnets.iter() {
            if event.token() == STOP {
                return Ok(());
            }
            loop {
                let len = match fd.read(&mut buf[start..]) {
                    Ok(len) => len + start,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            break;
                        }
                        Err(e)?
                    }
                };
                //单线程的
                up_counter.add(len as u64);
                if group_sync_sender.send((buf, len)).is_err() {
                    return Ok(());
                }
                buf = vec![0; 1024 * 16];
            }
        }
    }
}
