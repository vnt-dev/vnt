mod fd;

pub use fd::Fd;
use std::process::Output;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod sockaddr;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use sockaddr::SockAddr;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn exe_cmd(cmd: &str) -> std::io::Result<Output> {
    use std::io;
    use std::process::Command;
    println!("exe cmd: {}", cmd);
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("sh exec error!");
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, out),
        ));
    }
    Ok(out)
}
