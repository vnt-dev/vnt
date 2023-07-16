use std::fs::File;
use std::io;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use crate::config::get_home;

const DLL_FILE: &'static [u8] = include_bytes!("../../dll/amd64/wintun.dll");

pub fn load_tun_dll() -> io::Result<()> {
    let lib_path = get_home().join("lib");
    if !lib_path.exists() {
        std::fs::create_dir(&lib_path).unwrap();
    }
    let dll_path = lib_path.join("wintun.dll");
    if !dll_path.exists() {
        let mut f = File::create(&dll_path)?;
        f.write_all(DLL_FILE)?;
        f.sync_data()?;
    }
    let dll_directory = lib_path.as_os_str();

    let dll_directory_wide: Vec<u16> = dll_directory.encode_wide().chain(Some(0)).collect();
    unsafe {
        winapi::um::winbase::SetDllDirectoryW(dll_directory_wide.as_ptr());
    }
    Ok(())
}