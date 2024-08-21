use std::process;

use console::style;
use vnt::{ConnectInfo, ErrorInfo, ErrorType, HandshakeInfo, RegisterInfo, VntCallback};

#[derive(Clone)]
pub struct VntHandler {}

impl VntCallback for VntHandler {
    fn success(&self) {
        println!(" {} ", style("====== Connect Successfully ======").green())
    }
    #[cfg(feature = "integrated_tun")]
    fn create_tun(&self, info: vnt::DeviceInfo) {
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
        log::error!("error {:?}", info);
        println!("{}", style(format!("error {}", info)).red());
        match info.code {
            ErrorType::TokenError
            | ErrorType::AddressExhausted
            | ErrorType::IpAlreadyExists
            | ErrorType::InvalidIp
            | ErrorType::LocalIpExists
            | ErrorType::FailedToCrateDevice => {
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
