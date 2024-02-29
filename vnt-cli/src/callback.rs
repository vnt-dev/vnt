use std::process;

use vnt::handle::callback::ConnectInfo;
use vnt::{DeviceInfo, ErrorInfo, HandshakeInfo, RegisterInfo, VntCallback};

#[derive(Clone)]
pub struct VntHandler {}

impl VntCallback for VntHandler {
    fn create_tun(&self, info: DeviceInfo) {
        println!("create_tun {}", info)
    }

    fn connect(&self, info: ConnectInfo) {
        println!("connect {}", info)
    }

    fn handshake(&self, info: HandshakeInfo) -> bool {
        println!("handshake {}", info);
        true
    }

    fn register(&self, info: RegisterInfo) -> bool {
        println!("register {}", info);
        true
    }

    fn error(&self, info: ErrorInfo) {
        println!("error {}", info);
    }

    fn stop(&self) {
        println!("stopped");
        process::exit(0)
    }
}
