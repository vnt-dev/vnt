use std::io;
use std::os::windows::process::CommandExt;
use winapi::shared::minwindef::DWORD;
use winapi::um::winbase::CREATE_NO_WINDOW;

mod check;
mod device;
mod ffi;
mod netsh;
mod route;
mod tap;
mod tun;
pub use device::Device;

/// Encode a string as a utf16 buffer
pub fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

pub const fn ctl_code(device_type: DWORD, function: DWORD, method: DWORD, access: DWORD) -> DWORD {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub fn exe_cmd(cmd: &str) -> io::Result<()> {
    println!("exe cmd: {}", cmd);
    let out = std::process::Command::new("cmd")
        .creation_flags(CREATE_NO_WINDOW)
        .arg("/C")
        .arg(&cmd)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cmd={},out={:?}", cmd, String::from_utf8(out.stderr)),
        ));
    }
    Ok(())
}
