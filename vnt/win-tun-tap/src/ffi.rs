// Many things will be used in the future
#![allow(unused)]

//! Module holding safe wrappers over winapi functions

use winapi::shared::basetsd::*;
use winapi::shared::guiddef::GUID;
use winapi::shared::ifdef::*;
use winapi::shared::minwindef::*;
use winapi::shared::netioapi::*;
use winapi::shared::winerror::*;

use winapi::um::combaseapi::*;
use winapi::um::errhandlingapi::*;
use winapi::um::fileapi::*;
use winapi::um::handleapi::*;
use winapi::um::ioapiset::*;
use winapi::um::setupapi::*;
use winapi::um::synchapi::*;
use winapi::um::winioctl::*;
use winapi::um::winnt::*;
use winapi::um::winreg::*;

use std::{io, mem, ptr};
use std::error::Error;
use winapi::um::minwinbase::OVERLAPPED_u;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
/// Custom type to handle variable size SP_DRVINFO_DETAIL_DATA_W
pub struct SP_DRVINFO_DETAIL_DATA_W2 {
    pub cbSize: DWORD,
    pub InfDate: FILETIME,
    pub CompatIDsOffset: DWORD,
    pub CompatIDsLength: DWORD,
    pub Reserved: ULONG_PTR,
    pub SectionName: [WCHAR; 256],
    pub InfFileName: [WCHAR; 260],
    pub DrvDescription: [WCHAR; 256],
    pub HardwareID: [WCHAR; 512],
}

pub fn string_from_guid(guid: &GUID) -> io::Result<Vec<WCHAR>> {
    // GUID_STRING_CHARACTERS + 1
    let mut string = vec![0; 39];

    match unsafe {
        StringFromGUID2(guid, string.as_mut_ptr(), string.len() as _)
    } {
        0 => Err(io::Error::new(io::ErrorKind::Other, "Insufficent buffer")),
        _ => Ok(string),
    }
}

pub fn alias_to_luid(alias: &[WCHAR]) -> io::Result<NET_LUID> {
    let mut luid = unsafe { mem::zeroed() };

    match unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } {
        0 => Ok(luid),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn luid_to_index(luid: &NET_LUID) -> io::Result<NET_IFINDEX> {
    let mut index = 0;

    match unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) } {
        0 => Ok(index),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn luid_to_guid(luid: &NET_LUID) -> io::Result<GUID> {
    let mut guid = unsafe { mem::zeroed() };

    match unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) } {
        0 => Ok(guid),
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn luid_to_alias(luid: &NET_LUID) -> io::Result<Vec<WCHAR>> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = vec![0; 257];

    match unsafe {
        ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len())
    } {
        0 => {
            Ok(alias)
        }
        err => Err(io::Error::from_raw_os_error(err as _)),
    }
}

pub fn close_handle(handle: HANDLE) -> io::Result<()> {
    match unsafe { CloseHandle(handle) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn create_file(
    file_name: &[WCHAR],
    desired_access: DWORD,
    share_mode: DWORD,
    creation_disposition: DWORD,
    flags_and_attributes: DWORD,
) -> io::Result<HANDLE> {
    match unsafe {
        CreateFileW(
            file_name.as_ptr(),
            desired_access,
            share_mode,
            ptr::null_mut(),
            creation_disposition,
            flags_and_attributes,
            ptr::null_mut(),
        )
    } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        handle => Ok(handle),
    }
}

pub fn read_file(handle: HANDLE, buffer: &mut [u8]) -> io::Result<DWORD> {
    let mut ret = 0;
    //https://www.cnblogs.com/linyilong3/archive/2012/05/03/2480451.html
    unsafe {
        let mut ip_overlapped = winapi::um::minwinbase::OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            u: Default::default(),
            hEvent: ptr::null_mut(),
        };
        if 0 == ReadFile(
            handle,
            buffer.as_mut_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped, ) {
            let e = io::Error::last_os_error();
            if e.raw_os_error().unwrap_or(0) == 997 {
                if 0 == GetOverlappedResult(handle, &mut ip_overlapped, &mut ret, 1) {
                    return Err(e);
                }
            } else {
                return Err(e);
            }
        }
        Ok(ret)
    }
}

pub fn write_file(handle: HANDLE, buffer: &[u8]) -> io::Result<DWORD> {
    let mut ret = 0;
    let mut ip_overlapped = winapi::um::minwinbase::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        u: Default::default(),
        hEvent: ptr::null_mut(),
    };
    unsafe {
        if 0 == WriteFile(
            handle,
            buffer.as_ptr() as _,
            buffer.len() as _,
            &mut ret,
            &mut ip_overlapped,
        ) {
            let e = io::Error::last_os_error();
            if e.raw_os_error().unwrap_or(0) == 997 {
                if 0 == GetOverlappedResult(handle, &mut ip_overlapped, &mut ret, 1) {
                    return Err(e);
                }
            } else {
                return Err(e);
            }
        }
        Ok(ret)
    }
}

pub fn create_device_info_list(guid: &GUID) -> io::Result<HDEVINFO> {
    match unsafe { SetupDiCreateDeviceInfoList(guid, ptr::null_mut()) } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn get_class_devs(guid: &GUID, flags: DWORD) -> io::Result<HDEVINFO> {
    match unsafe {
        SetupDiGetClassDevsW(guid, ptr::null(), ptr::null_mut(), flags)
    } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn destroy_device_info_list(devinfo: HDEVINFO) -> io::Result<()> {
    match unsafe { SetupDiDestroyDeviceInfoList(devinfo) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn class_name_from_guid(guid: &GUID) -> io::Result<Vec<WCHAR>> {
    let mut class_name = vec![0; 32];

    match unsafe {
        SetupDiClassNameFromGuidW(
            guid,
            class_name.as_mut_ptr(),
            class_name.len() as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(class_name),
    }
}

pub fn create_device_info(
    devinfo: HDEVINFO,
    device_name: &[WCHAR],
    guid: &GUID,
    device_description: &[WCHAR],
    creation_flags: DWORD,
) -> io::Result<SP_DEVINFO_DATA> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;

    match unsafe {
        SetupDiCreateDeviceInfoW(
            devinfo,
            device_name.as_ptr(),
            guid,
            device_description.as_ptr(),
            ptr::null_mut(),
            creation_flags,
            &mut devinfo_data,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(devinfo_data),
    }
}

pub fn set_selected_device(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
) -> io::Result<()> {
    match unsafe {
        SetupDiSetSelectedDevice(devinfo, devinfo_data as *const _ as _)
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn set_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: DWORD,
    value: &[WCHAR],
) -> io::Result<()> {
    match unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data as *const _ as _,
            property,
            value.as_ptr() as _,
            (value.len() * 2) as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: DWORD,
) -> io::Result<Vec<WCHAR>> {
    let mut value = vec![0; 32];

    match unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            devinfo,
            devinfo_data as *const _ as _,
            property,
            ptr::null_mut(),
            value.as_mut_ptr() as _,
            (value.len() * 2) as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(value),
    }
}

pub fn build_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: DWORD,
) -> io::Result<()> {
    match unsafe {
        SetupDiBuildDriverInfoList(
            devinfo,
            devinfo_data as *const _ as _,
            driver_type,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn destroy_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: DWORD,
) -> io::Result<()> {
    match unsafe {
        SetupDiDestroyDriverInfoList(
            devinfo,
            devinfo_data as *const _ as _,
            driver_type,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_driver_info_detail(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_W,
) -> io::Result<SP_DRVINFO_DETAIL_DATA_W2> {
    let mut drvinfo_detail: SP_DRVINFO_DETAIL_DATA_W2 =
        unsafe { mem::zeroed() };
    drvinfo_detail.cbSize = mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>() as _;

    match unsafe {
        SetupDiGetDriverInfoDetailW(
            devinfo,
            devinfo_data as *const _ as _,
            drvinfo_data as *const _ as _,
            &mut drvinfo_detail as *mut _ as _,
            mem::size_of_val(&drvinfo_detail) as _,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(drvinfo_detail),
    }
}

pub fn set_selected_driver(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    drvinfo_data: &SP_DRVINFO_DATA_W,
) -> io::Result<()> {
    match unsafe {
        SetupDiSetSelectedDriverW(
            devinfo,
            devinfo_data as *const _ as _,
            drvinfo_data as *const _ as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn set_class_install_params(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    params: &impl Copy,
) -> io::Result<()> {
    match unsafe {
        SetupDiSetClassInstallParamsW(
            devinfo,
            devinfo_data as *const _ as _,
            params as *const _ as _,
            mem::size_of_val(params) as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn call_class_installer(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    install_function: DI_FUNCTION,
) -> io::Result<()> {
    match unsafe {
        SetupDiCallClassInstaller(
            install_function,
            devinfo,
            devinfo_data as *const _ as _,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn open_dev_reg_key(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    scope: DWORD,
    hw_profile: DWORD,
    key_type: DWORD,
    sam_desired: REGSAM,
) -> io::Result<HKEY> {
    const INVALID_KEY_VALUE: HKEY = INVALID_HANDLE_VALUE as _;

    match unsafe {
        SetupDiOpenDevRegKey(
            devinfo,
            devinfo_data as *const _ as _,
            scope,
            hw_profile,
            key_type,
            sam_desired,
        )
    } {
        INVALID_KEY_VALUE => Err(io::Error::last_os_error()),
        key => Ok(key),
    }
}

pub fn notify_change_key_value(
    key: HKEY,
    watch_subtree: BOOL,
    notify_filter: DWORD,
    milliseconds: DWORD,
) -> io::Result<()> {
    let event = match unsafe {
        CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null())
    } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        event => Ok(event),
    }?;

    match unsafe {
        RegNotifyChangeKeyValue(key, watch_subtree, notify_filter, event, TRUE)
    } {
        0 => Ok(()),
        err => Err(io::Error::from_raw_os_error(err)),
    }?;

    match unsafe { WaitForSingleObject(event, milliseconds) } {
        0 => Ok(()),
        0x102 => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Registry timed out",
        )),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn enum_driver_info(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: DWORD,
    member_index: DWORD,
) -> Option<io::Result<SP_DRVINFO_DATA_W>> {
    let mut drvinfo_data: SP_DRVINFO_DATA_W = unsafe { mem::zeroed() };
    drvinfo_data.cbSize = mem::size_of_val(&drvinfo_data) as _;

    match unsafe {
        SetupDiEnumDriverInfoW(
            devinfo,
            devinfo_data as *const _ as _,
            driver_type,
            member_index,
            &mut drvinfo_data,
        )
    } {
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(drvinfo_data)),
    }
}

pub fn enum_device_info(
    devinfo: HDEVINFO,
    member_index: DWORD,
) -> Option<io::Result<SP_DEVINFO_DATA>> {
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = mem::size_of_val(&devinfo_data) as _;

    match unsafe {
        SetupDiEnumDeviceInfo(devinfo, member_index, &mut devinfo_data)
    } {
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(devinfo_data)),
    }
}

pub fn device_io_control(
    handle: HANDLE,
    io_control_code: DWORD,
    in_buffer: &impl Copy,
    out_buffer: &mut impl Copy,
) -> io::Result<()> {
    let mut junk = 0;

    match unsafe {
        DeviceIoControl(
            handle,
            io_control_code,
            in_buffer as *const _ as _,
            mem::size_of_val(in_buffer) as _,
            out_buffer as *mut _ as _,
            mem::size_of_val(out_buffer) as _,
            &mut junk,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}
