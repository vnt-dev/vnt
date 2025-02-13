use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::compression::Compressor;
use crate::external_route::ExternalRoute;
use crate::handle::tun_tap::DeviceStop;
use crate::handle::{CurrentDeviceInfo, PeerDeviceInfo};
#[cfg(feature = "ip_proxy")]
use crate::ip_proxy::IpProxyMap;
use crate::tun_tap_device::vnt_device::DeviceWrite;
use crate::util::StopManager;
use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use tun_rs::SyncDevice;

#[repr(transparent)]
#[derive(Clone, Default)]
pub struct DeviceAdapter {
    tun: Arc<Mutex<Option<Arc<SyncDevice>>>>,
}

impl DeviceAdapter {
    pub fn insert(&self, device: Arc<SyncDevice>) {
        let r = self.tun.lock().replace(device);
        assert!(r.is_none());
    }
    /// 要保证先remove 再insert
    pub fn remove(&self) {
        drop(self.tun.lock().take());
    }
}

impl DeviceWrite for DeviceAdapter {
    #[inline]
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(tun) = self.tun.lock().as_ref() {
            tun.send(buf)
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "not tun device"))
        }
    }

    fn into_device_adapter(self) -> DeviceAdapter {
        self
    }
}

#[derive(Clone)]
pub struct TunDeviceHelper {
    inner: Arc<Mutex<TunDeviceHelperInner>>,
    device_adapter: DeviceAdapter,
    device_stop: Arc<Mutex<Option<DeviceStop>>>,
}

#[derive(Clone)]
struct TunDeviceHelperInner {
    stop_manager: StopManager,
    context: ChannelContext,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: ExternalRoute,
    #[cfg(feature = "ip_proxy")]
    ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
    compressor: Compressor,
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
        device_map: Arc<Mutex<(u16, HashMap<Ipv4Addr, PeerDeviceInfo>)>>,
        compressor: Compressor,
        device_adapter: DeviceAdapter,
    ) -> Self {
        let inner = TunDeviceHelperInner {
            stop_manager,
            context,
            current_device,
            ip_route,
            #[cfg(feature = "ip_proxy")]
            ip_proxy_map,
            client_cipher,
            server_cipher,
            device_map,
            compressor,
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
            device_adapter,
            device_stop: Default::default(),
        }
    }
    pub fn stop(&self) {
        //先停止旧的，再启动新的，改变旧网卡的IP太麻烦
        if let Some(device_stop) = self.device_stop.lock().take() {
            self.device_adapter.remove();
            loop {
                device_stop.stop();
                std::thread::sleep(std::time::Duration::from_millis(300));
                //确保停止了
                if device_stop.is_stopped() {
                    break;
                }
            }
        }
    }
    /// 要保证先stop 再start
    pub fn start(&self, device: Arc<SyncDevice>, allow_wire_guard: bool) -> io::Result<()> {
        self.device_adapter.insert(device.clone());
        let device_stop = DeviceStop::default();
        let s = self.device_stop.lock().replace(device_stop.clone());
        assert!(s.is_none());
        let inner = self.inner.lock().clone();
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
            inner.device_map,
            inner.compressor,
            device_stop,
            allow_wire_guard,
        )
    }
}
