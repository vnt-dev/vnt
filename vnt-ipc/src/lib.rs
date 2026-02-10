pub mod client;
pub mod message;
pub mod server;

pub use vnt_core::*;
const DEFAULT_PORT: u16 = 11233;

const PORT_FILE: &str = "PORT";

fn get_port_file_path() -> std::path::PathBuf {
    std::path::PathBuf::from(PORT_FILE)
}
