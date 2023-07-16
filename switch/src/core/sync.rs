use std::io;
use std::ops::Deref;
use std::time::Duration;
use tokio::runtime::Runtime;
use crate::core::{Config, Switch, SwitchUtil};
use crate::handle::registration_handler::{RegResponse, ReqEnum};

pub struct SwitchUtilSync {
    switch_util: SwitchUtil,
    runtime: Runtime,
}

pub struct SwitchSync {
    switch: Switch,
    runtime: Runtime,
}

impl SwitchUtilSync {
    pub fn new(config: Config) -> io::Result<SwitchUtilSync> {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let switch_util = runtime.block_on(SwitchUtil::new(config))?;
        Ok(SwitchUtilSync {
            switch_util,
            runtime,
        })
    }
    pub fn connect(&mut self) -> Result<RegResponse, ReqEnum> {
        self.runtime.block_on(self.switch_util.connect())
    }
    #[cfg(any(target_os = "android"))]
    pub fn create_iface(&mut self, vpn_fd: i32) {
        self.switch_util.create_iface(vpn_fd)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub fn create_iface(&mut self) -> io::Result<crate::tun_tap_device::DriverInfo> {
        self.switch_util.create_iface()
    }
    pub fn build(self) -> crate::Result<SwitchSync> {
        let runtime = self.runtime;
        let switch = runtime.block_on(self.switch_util.build())?;
        {
            let mut switch = switch.clone();
            std::thread::spawn(move || {
                runtime.block_on(switch.wait_stop())
            });
        }
        Ok(SwitchSync {
            switch,
            runtime: tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap(),
        })
    }
}

impl SwitchSync {
    pub fn wait_stop(&mut self) {
        self.runtime.block_on(self.switch.wait_stop())
    }
    pub fn wait_stop_ms(&mut self, ms: u64) -> bool {
        self.runtime.block_on(self.switch.wait_stop_ms(Duration::from_millis(ms)))
    }
}

impl Deref for SwitchSync {
    type Target = Switch;

    fn deref(&self) -> &Self::Target {
        &self.switch
    }
}