use anyhow::Context;
use std::fs;
use std::path::Path;
pub fn get_device_id() -> anyhow::Result<String> {
    match machine_uid::get() {
        Ok(id) => return Ok(id),
        Err(e) => {
            log::warn!("Failed to get system ID: {}. Using fallback.", e);
        }
    }

    get_fallback_id()
}
fn get_fallback_id() -> anyhow::Result<String> {
    let path = Path::new("device_id");

    if let Ok(content) = fs::read_to_string(path) {
        let id = content.trim();
        if !id.is_empty() {
            return Ok(id.to_string());
        }
    }

    let new_id = uuid::Uuid::new_v4().to_string();

    fs::write(path, &new_id).context("Failed to write device_id file")?;

    Ok(new_id)
}
