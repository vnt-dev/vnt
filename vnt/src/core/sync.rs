use std::io;
use std::ops::Deref;
use std::time::Duration;
use tokio::runtime::Runtime;
use crate::cipher::RsaCipher;
use crate::core::{Config, Vnt, VntUtil};
use crate::handle::handshake_handler::HandshakeEnum;
use crate::handle::registration_handler::{RegResponse, ReqEnum};

pub struct VntUtilSync {
    vnt_util: VntUtil,
    runtime: Runtime,
}

pub struct VntSync {
    vnt: Vnt,
    runtime: Runtime,
}

impl VntUtilSync {
    pub fn new(config: Config) -> io::Result<VntUtilSync> {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let vnt_util = runtime.block_on(VntUtil::new(config))?;
        Ok(VntUtilSync {
            vnt_util,
            runtime,
        })
    }
    pub fn connect(&mut self) -> io::Result<()> {
        self.runtime.block_on(self.vnt_util.connect())
    }
    pub fn handshake(&mut self) -> Result<Option<RsaCipher>, HandshakeEnum> {
        self.runtime.block_on(self.vnt_util.handshake())
    }
    pub fn secret_handshake(&mut self) -> Result<(), HandshakeEnum> {
        self.runtime.block_on(self.vnt_util.secret_handshake())
    }
    pub fn register(&mut self) -> Result<RegResponse, ReqEnum> {
        self.runtime.block_on(self.vnt_util.register())
    }
    #[cfg(any(target_os = "android"))]
    pub fn create_iface(&mut self, vpn_fd: i32) {
        self.vnt_util.create_iface(vpn_fd)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub fn create_iface(&mut self) -> io::Result<crate::tun_tap_device::DriverInfo> {
        self.vnt_util.create_iface()
    }
    pub fn build(self) -> crate::Result<VntSync> {
        let runtime = self.runtime;
        let vnt = runtime.block_on(self.vnt_util.build())?;
        {
            let mut vnt = vnt.clone();
            std::thread::spawn(move || {
                runtime.block_on(vnt.wait_stop())
            });
        }
        Ok(VntSync {
            vnt,
            runtime: tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap(),
        })
    }
}

impl VntSync {
    pub fn wait_stop(&mut self) {
        self.runtime.block_on(self.vnt.wait_stop())
    }
    pub fn wait_stop_ms(&mut self, ms: u64) -> bool {
        self.runtime.block_on(self.vnt.wait_stop_ms(Duration::from_millis(ms)))
    }
}

impl Deref for VntSync {
    type Target = Vnt;

    fn deref(&self) -> &Self::Target {
        &self.vnt
    }
}