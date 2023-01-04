//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use crate::address::IntoAddress;
use crate::platform;

/// TUN interface OSI layer of operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    L2,
    L3,
}

impl Default for Layer {
    fn default() -> Self {
        Layer::L3
    }
}

/// Configuration builder for a TUN interface.
#[derive(Clone, Default, Debug)]
pub struct Configuration {
    pub(crate) name: Option<String>,
    pub(crate) platform: platform::Configuration,

    pub(crate) address: Option<Ipv4Addr>,
    pub(crate) destination: Option<Ipv4Addr>,
    pub(crate) broadcast: Option<Ipv4Addr>,
    pub(crate) netmask: Option<Ipv4Addr>,
    pub(crate) mtu: Option<i32>,
    pub(crate) enabled: Option<bool>,
    pub(crate) layer: Option<Layer>,
    pub(crate) queues: Option<usize>,
    pub(crate) raw_fd: Option<RawFd>,
}

impl Configuration {
    /// Access the platform dependant configuration.
    pub fn platform<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut platform::Configuration),
    {
        f(&mut self.platform);
        self
    }

    /// Set the name.
    pub fn name<S: AsRef<str>>(&mut self, name: S) -> &mut Self {
        self.name = Some(name.as_ref().into());
        self
    }

    /// Set the address.
    pub fn address<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.address = Some(value.into_address().unwrap());
        self
    }

    /// Set the destination address.
    pub fn destination<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.destination = Some(value.into_address().unwrap());
        self
    }

    /// Set the broadcast address.
    pub fn broadcast<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.broadcast = Some(value.into_address().unwrap());
        self
    }

    /// Set the netmask.
    pub fn netmask<A: IntoAddress>(&mut self, value: A) -> &mut Self {
        self.netmask = Some(value.into_address().unwrap());
        self
    }

    /// Set the MTU.
    pub fn mtu(&mut self, value: i32) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    /// Set the interface to be enabled once created.
    pub fn up(&mut self) -> &mut Self {
        self.enabled = Some(true);
        self
    }

    /// Set the interface to be disabled once created.
    pub fn down(&mut self) -> &mut Self {
        self.enabled = Some(false);
        self
    }

    /// Set the OSI layer of operation.
    pub fn layer(&mut self, value: Layer) -> &mut Self {
        self.layer = Some(value);
        self
    }

    /// Set the number of queues.
    pub fn queues(&mut self, value: usize) -> &mut Self {
        self.queues = Some(value);
        self
    }

    /// Set the raw fd.
    pub fn raw_fd(&mut self, fd: RawFd) -> &mut Self {
        self.raw_fd = Some(fd);
        self
    }
}
