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

//! macOS specific functionality.

pub mod sys;

mod device;
pub use self::device::{Device, Queue};

use crate::configuration::Configuration as C;
use crate::error::*;

/// macOS-only interface configuration.
#[derive(Copy, Clone, Default, Debug)]
pub struct Configuration {}

/// Create a TUN device with the given name.
pub fn create(configuration: &C) -> Result<Device> {
    Device::new(&configuration)
}
