pub mod client;
pub mod message;
pub mod server;

pub use vnt_core::*;
const DEFAULT_PORT: u16 = 11233;

const PORT_FILE: &str = "PORT";

fn get_port_file_path() -> std::path::PathBuf {
    // 锚定可执行文件目录，相对路径会随 CWD 变化导致读不到 PORT 文件
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join(PORT_FILE)))
        .unwrap_or_else(|| std::path::PathBuf::from(PORT_FILE))
}

#[cfg(test)]
mod tests {
    /// PORT 文件路径必须锚定到可执行文件目录（绝对路径）
    #[test]
    fn test_port_file_path_is_absolute() {
        let path = super::get_port_file_path();
        assert!(path.is_absolute(), "path should be absolute: {path:?}");
        assert_eq!(path.file_name().unwrap(), super::PORT_FILE);
    }
}
