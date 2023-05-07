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
#![cfg(unix)]
mod error;
pub use crate::error::*;

mod address;
pub use crate::address::IntoAddress;

mod device;
pub use crate::device::Device;

mod configuration;
pub use crate::configuration::{Configuration, Layer};

pub mod platform;
pub use crate::platform::create;

pub fn configure() -> Configuration {
    Configuration::default()
}
