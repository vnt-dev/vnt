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

    ensure_dll(&path)?;
    Ok(())
}

/// 确保 path 处的 dll 与内嵌版本一致，不一致（不存在/损坏/旧版）时重写。
/// 返回是否发生了写入。只按存在性判断会让损坏或旧版 dll 永久残留。
fn ensure_dll(path: &Path) -> io::Result<bool> {
    let up_to_date = fs::read(path)
        .map(|content| content.as_slice() == WINTUN_DLL)
        .unwrap_or(false);
    if up_to_date {
        return Ok(false);
    }
    let mut file = fs::File::create(path)?;
    file.write_all(WINTUN_DLL)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dll_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vnt_wintun_test_{}_{}.dll",
            std::process::id(),
            tag
        ))
    }

    #[test]
    fn test_ensure_dll_writes_when_missing() {
        let path = temp_dll_path("missing");
        let _ = fs::remove_file(&path);
        assert!(ensure_dll(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), WINTUN_DLL);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_ensure_dll_rewrites_corrupt() {
        let path = temp_dll_path("corrupt");
        fs::write(&path, b"corrupt").unwrap();
        assert!(ensure_dll(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), WINTUN_DLL);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_ensure_dll_skips_when_up_to_date() {
        let path = temp_dll_path("uptodate");
        fs::write(&path, WINTUN_DLL).unwrap();
        assert!(!ensure_dll(&path).unwrap());
        let _ = fs::remove_file(&path);
    }
}
