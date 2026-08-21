use std::io;
use std::path::Path;

#[cfg(target_arch = "x86_64")]
const WINTUN_DLL: &[u8] = include_bytes!("../../../dll/amd64/wintun.dll");
#[cfg(target_arch = "x86")]
const WINTUN_DLL: &[u8] = include_bytes!("../../../dll/x86/wintun.dll");
#[cfg(target_arch = "aarch64")]
const WINTUN_DLL: &[u8] = include_bytes!("../../../dll/arm64/wintun.dll");
#[cfg(target_arch = "arm")]
const WINTUN_DLL: &[u8] = include_bytes!("../../../dll/arm/wintun.dll");

pub fn ensure_wintun(data_dir: &Path) -> io::Result<()> {
    let target = data_dir.join("wintun.dll");
    let current = std::fs::read(&target).unwrap_or_default();
    if current != WINTUN_DLL {
        std::fs::write(target, WINTUN_DLL)?;
    }
    Ok(())
}
