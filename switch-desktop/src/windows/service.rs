// #[macro_use]
// extern crate windows_service;

use std::ffi::OsString;
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, switch_service_main);
pub fn switch_service_main(arguments: Vec<OsString>) {

}
pub fn start(){
   service_dispatcher::start("switch-service",ffi_service_main).unwrap();
}