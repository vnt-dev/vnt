pub const PUB_STUN: [&'static str; 4] = [
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.cdnbye.com",
];
#[cfg(feature = "file_config")]
mod file_config;

use crate::identifier;
#[cfg(feature = "file_config")]
pub use file_config::read_config;

#[cfg(not(feature = "file_config"))]
pub fn read_config(_file_path: &str) -> anyhow::Result<(vnt::core::Config, Vec<String>, bool)> {
    unimplemented!()
}

pub fn get_device_id() -> String {
    if let Some(id) = identifier::get_unique_identifier() {
        id
    } else {
        let path_buf = match crate::cli::app_home() {
            Ok(path_buf) => path_buf.join("device-id"),
            Err(e) => {
                log::warn!("{:?}", e);
                return String::new();
            }
        };
        if let Ok(id) = std::fs::read_to_string(path_buf.as_path()) {
            id
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let _ = std::fs::write(path_buf, &id);
            id
        }
    }
}
