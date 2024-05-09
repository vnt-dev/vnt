use std::io;
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;

use tun::Device;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::external_route::ExternalRoute;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
use crate::ip_proxy::IpProxyMap;
use crate::util::{SingleU64Adder, StopManager};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[repr(transparent)]
#[derive(Clone)]
pub struct DeviceAdapter {
    tun: Arc<Device>,
}
impl DeviceAdapter {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub fn new(tun: Arc<Device>) -> Self {
        Self { tun }
    }
    #[cfg(target_os = "android")]
    pub fn new(tun_device_helper: TunDeviceHelper) -> Self {
        Self {
            tun: Arc::new(AtomicCell::new(-1 as _)),
            tun_device_helper,
        }
    }
}
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl std::ops::Deref for DeviceAdapter {
    type Target = Arc<Device>;

    fn deref(&self) -> &Self::Target {
        &self.tun
    }
}

#[cfg(target_os = "android")]
#[derive(Clone)]
pub struct DeviceAdapter {
    tun: Arc<AtomicCell<std::os::fd::RawFd>>,
    tun_device_helper: TunDeviceHelper,
}
#[cfg(target_os = "android")]
impl DeviceAdapter {
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.tun.load();
        tun::Fd(fd).write(buf)
    }
    pub fn start(&self, fd: std::os::fd::RawFd) -> io::Result<()> {
        //安卓端fd是由外部释放的，所以这里这么搞免得加锁
        self.tun_device_helper.start(Arc::new(Device::new(fd)?))?;
        self.tun.store(fd);
        Ok(())
    }
}

#[derive(Clone)]
pub struct TunDeviceHelper {
    inner: Arc<AtomicCell<Option<TunDeviceHelperInner>>>,
}

struct TunDeviceHelperInner {
    stop_manager: StopManager,
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")]
    ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    parallel: usize,
    up_counter: SingleU64Adder,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
}

impl TunDeviceHelper {
    pub fn new(
        stop_manager: StopManager,
        context: ChannelContext,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        ip_route: ExternalRoute,
        #[cfg(feature = "ip_proxy")] ip_proxy_map: Option<IpProxyMap>,
        client_cipher: Cipher,
        server_cipher: Cipher,
        parallel: usize,
        up_counter: SingleU64Adder,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    ) -> Self {
        Self {
            inner: Arc::new(AtomicCell::new(Some(TunDeviceHelperInner {
                stop_manager,
                context,
                current_device,
                ip_route,
                ip_proxy_map,
                client_cipher,
                server_cipher,
                parallel,
                up_counter,
                device_list,
            }))),
        }
    }
    pub fn start(&self, device: Arc<Device>) -> io::Result<()> {
        if let Some(inner) = self.inner.take() {
            crate::handle::tun_tap::tun_handler::start(
                inner.stop_manager,
                inner.context,
                device,
                inner.current_device,
                inner.ip_route,
                #[cfg(feature = "ip_proxy")]
                inner.ip_proxy_map,
                inner.client_cipher,
                inner.server_cipher,
                inner.parallel,
                inner.up_counter,
                inner.device_list,
            )?;
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Repeated start"))
        }
    }
}
