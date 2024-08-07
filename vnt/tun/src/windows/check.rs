use libloading::Library;
use std::ffi::{c_char, CStr, CString};
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use winapi::shared::minwindef::HINSTANCE;
use winapi::um::libloaderapi::{GetModuleFileNameA, GetModuleHandleA};

#[repr(C)]
#[derive(Debug)]
struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Debug)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

fn get_dll_path(dll_name: &str) -> Result<PathBuf, String> {
    unsafe {
        // 使用libloading加载DLL

        // 转换DLL名称为C字符串
        let dll_name_c =
            CString::new(dll_name).map_err(|e| format!("Failed to convert to CString: {}", e))?;

        // 获取DLL的模块句柄
        let h_instance: HINSTANCE = GetModuleHandleA(dll_name_c.as_ptr() as *const c_char);

        if h_instance.is_null() {
            return Err("Failed to get module handle".to_string());
        }

        // 获取DLL文件路径
        let mut buffer: [c_char; 260] = [0; 260];
        let length = GetModuleFileNameA(h_instance, buffer.as_mut_ptr(), buffer.len() as u32);

        if length == 0 {
            return Err("Failed to get module file name".to_string());
        }

        let path = CStr::from_ptr(buffer.as_ptr());
        let path_str = path
            .to_str()
            .map_err(|e| format!("Failed to convert to &str: {}", e))?;
        Ok(PathBuf::from(path_str))
    }
}

pub fn check_win_tun_dll() -> io::Result<()> {
    let _lib = unsafe {
        Library::new("wintun.dll").map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "wintun.dll not found,Please download https://www.wintun.net",
            )
        })
    };
    match get_dll_path("wintun.dll") {
        Ok(path) => match_platform(path),
        Err(e) => {
            // 能加载说明存在wintun，这里获取不到路径是代码的问题
            log::info!("{:?}", e);
            Ok(())
        }
    }
}

fn match_platform(path: PathBuf) -> io::Result<()> {
    let current_arch = if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "x86_64") {
        "AMD64"
    } else if cfg!(target_arch = "arm") {
        "ARM"
    } else if cfg!(target_arch = "aarch64") {
        "ARM64"
    } else {
        return Ok(());
    };

    let mut file = File::open(&path)?;

    // 读取 DOS 头部
    let mut dos_header = [0u8; std::mem::size_of::<DosHeader>()];
    file.read_exact(&mut dos_header)?;
    let dos_header: DosHeader = unsafe { std::ptr::read(dos_header.as_ptr() as *const _) };

    if dos_header.e_magic != 0x5A4D {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Not a valid PE file {:?}", path),
        ));
    }

    // 跳转到 PE 头部
    file.seek(io::SeekFrom::Start(dos_header.e_lfanew as u64))?;

    // 读取 PE 头部
    let mut pe_signature = [0u8; 4];
    file.read_exact(&mut pe_signature)?;
    if &pe_signature != b"PE\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Not a valid PE file {:?}", path),
        ));
    }

    // 读取文件头部
    let mut file_header = [0u8; std::mem::size_of::<FileHeader>()];
    file.read_exact(&mut file_header)?;
    let file_header: FileHeader = unsafe { std::ptr::read(file_header.as_ptr() as *const _) };
    let dll_arch = match file_header.machine {
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unknown machine type: {}", file_header.machine),
            ))
        }
    };

    if dll_arch != current_arch {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "wintun.dll architecture ({}) does not match the current platform architecture ({}).",
                dll_arch, current_arch
            ),
        ));
    }
    Ok(())
}
