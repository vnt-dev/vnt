use std::process;

use console::style;

use vnt::handle::callback::{ConnectInfo, ErrorType};
use vnt::{DeviceInfo, ErrorInfo, HandshakeInfo, RegisterInfo, VntCallback};

#[derive(Clone)]
pub struct VntHandler {}

impl VntCallback for VntHandler {
    fn success(&self) {
        println!(" {} ", style("====== Connect Successfully ======").green())
    }
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
        println!("register {}", style(info).green());
        true
    }

    fn error(&self, info: ErrorInfo) {
        println!("{}", style(format!("error {}", info)).red());
        match info.code {
            ErrorType::TokenError
            | ErrorType::AddressExhausted
            | ErrorType::IpAlreadyExists
            | ErrorType::InvalidIp
            | ErrorType::LocalIpExists => {
                self.stop();
            }
            _ => {}
        }
    }

    fn stop(&self) {
        println!("stopped");
        process::exit(0)
    }
}
