use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[cfg(target_arch = "x86_64")]
const WINTUN_DLL: &[u8] = include_bytes!("../dll/amd64/wintun.dll");

#[cfg(target_arch = "x86")]
const WINTUN_DLL: &[u8] = include_bytes!("../dll/x86/wintun.dll");

#[cfg(target_arch = "aarch64")]
const WINTUN_DLL: &[u8] = include_bytes!("../dll/arm64/wintun.dll");

#[cfg(target_arch = "arm")]
const WINTUN_DLL: &[u8] = include_bytes!("../dll/arm/wintun.dll");

pub fn extract_wintun() {
    if let Err(e) = extract_wintun_impl() {
        log::error!("extract wintun.dll {:?}", e);
    }
}
fn extract_wintun_impl() -> io::Result<()> {
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| Path::new("wintun.dll").to_path_buf());

    if !path.exists() {
        let mut file = fs::File::create(&path)?;
        file.write_all(WINTUN_DLL)?;
    }
    Ok(())
}
