use winapi::shared::ifdef::NET_LUID;
use winapi::shared::minwindef::*;

use winapi::um::fileapi::*;
use winapi::um::setupapi::*;
use winapi::um::winnt::*;

use scopeguard::{guard, ScopeGuard};
use winreg::RegKey;

use std::io;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;

use crate::{decode_utf16, encode_utf16, ffi};

/// tap-windows hardware ID
const HARDWARE_ID: &str = "tap0901";

winapi::DEFINE_GUID! {
    GUID_NETWORK_ADAPTER,
    0x4d36e972, 0xe325, 0x11ce,
    0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18
}

/// Create a new interface and returns its NET_LUID
pub fn create_interface() -> io::Result<NET_LUID> {
    let devinfo = ffi::create_device_info_list(&GUID_NETWORK_ADAPTER)?;

    let _guard = guard((), |_| {
        let _ = ffi::destroy_device_info_list(devinfo);
    });

    let class_name = ffi::class_name_from_guid(&GUID_NETWORK_ADAPTER)?;

    let devinfo_data = ffi::create_device_info(
        devinfo,
        &class_name,
        &GUID_NETWORK_ADAPTER,
        &encode_utf16(""),
        DICD_GENERATE_ID,
    )?;

    ffi::set_selected_device(devinfo, &devinfo_data)?;
    ffi::set_device_registry_property(
        devinfo,
        &devinfo_data,
        SPDRP_HARDWAREID,
        &encode_utf16(HARDWARE_ID),
    )?;

    ffi::build_driver_info_list(devinfo, &devinfo_data, SPDIT_COMPATDRIVER)?;

    let _guard = guard((), |_| {
        let _ = ffi::destroy_driver_info_list(
            devinfo,
            &devinfo_data,
            SPDIT_COMPATDRIVER,
        );
    });

    let mut driver_version = 0;
    let mut member_index = 0;

    while let Some(drvinfo_data) = ffi::enum_driver_info(
        devinfo,
        &devinfo_data,
        SPDIT_COMPATDRIVER,
        member_index,
    ) {
        member_index += 1;

        let drvinfo_data = match drvinfo_data {
            Ok(drvinfo_data) => drvinfo_data,
            _ => continue,
        };

        if drvinfo_data.DriverVersion <= driver_version {
            continue;
        }

        let drvinfo_detail = match ffi::get_driver_info_detail(
            devinfo,
            &devinfo_data,
            &drvinfo_data,
        ) {
            Ok(drvinfo_detail) => drvinfo_detail,
            _ => continue,
        };

        let is_compatible = drvinfo_detail
            .HardwareID
            .split(|b| *b == 0)
            .map(|id| decode_utf16(id))
            .any(|id| id.eq_ignore_ascii_case(HARDWARE_ID));

        if !is_compatible {
            continue;
        }

        match ffi::set_selected_driver(devinfo, &devinfo_data, &drvinfo_data) {
            Ok(_) => (),
            _ => continue,
        }

        driver_version = drvinfo_data.DriverVersion;
    }

    if driver_version == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No driver found"));
    }

    let uninstaller = guard((), |_| {
        let _ = ffi::call_class_installer(devinfo, &devinfo_data, DIF_REMOVE);
    });

    ffi::call_class_installer(devinfo, &devinfo_data, DIF_REGISTERDEVICE)?;

    let _ = ffi::call_class_installer(
        devinfo,
        &devinfo_data,
        DIF_REGISTER_COINSTALLERS,
    );
    let _ = ffi::call_class_installer(
        devinfo,
        &devinfo_data,
        DIF_INSTALLINTERFACES,
    );

    ffi::call_class_installer(devinfo, &devinfo_data, DIF_INSTALLDEVICE)?;

    let key = ffi::open_dev_reg_key(
        devinfo,
        &devinfo_data,
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_QUERY_VALUE | KEY_NOTIFY,
    )?;

    let key = RegKey::predef(key);

    while let Err(_) = key.get_value::<DWORD, &str>("*IfType") {
        ffi::notify_change_key_value(
            key.raw_handle(),
            TRUE,
            REG_NOTIFY_CHANGE_NAME,
            2000,
        )?;
    }

    while let Err(_) = key.get_value::<DWORD, &str>("NetLuidIndex") {
        ffi::notify_change_key_value(
            key.raw_handle(),
            TRUE,
            REG_NOTIFY_CHANGE_NAME,
            2000,
        )?;
    }

    let if_type: DWORD = key.get_value("*IfType")?;
    let luid_index: DWORD = key.get_value("NetLuidIndex")?;

    // Defuse the uninstaller
    ScopeGuard::into_inner(uninstaller);

    let mut luid = NET_LUID { Value: 0 };

    luid.set_IfType(if_type as _);
    luid.set_NetLuidIndex(luid_index as _);

    Ok(luid)
}

/// Check if the given interface exists and is a valid tap-windows device
pub fn check_interface(luid: &NET_LUID) -> io::Result<()> {
    let devinfo = ffi::get_class_devs(&GUID_NETWORK_ADAPTER, DIGCF_PRESENT)?;

    let _guard = guard((), |_| {
        let _ = ffi::destroy_device_info_list(devinfo);
    });

    let mut member_index = 0;

    while let Some(devinfo_data) = ffi::enum_device_info(devinfo, member_index)
    {
        member_index += 1;

        let devinfo_data = match devinfo_data {
            Ok(devinfo_data) => devinfo_data,
            Err(_) => continue,
        };

        let hardware_id = match ffi::get_device_registry_property(
            devinfo,
            &devinfo_data,
            SPDRP_HARDWAREID,
        ) {
            Ok(hardware_id) => hardware_id,
            Err(_) => continue,
        };

        if !decode_utf16(&hardware_id).eq_ignore_ascii_case(HARDWARE_ID) {
            continue;
        }

        let key = match ffi::open_dev_reg_key(
            devinfo,
            &devinfo_data,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            KEY_QUERY_VALUE | KEY_NOTIFY,
        ) {
            Ok(key) => RegKey::predef(key),
            Err(_) => continue,
        };

        let if_type: DWORD = match key.get_value("*IfType") {
            Ok(if_type) => if_type,
            Err(_) => continue,
        };

        let luid_index: DWORD = match key.get_value("NetLuidIndex") {
            Ok(luid_index) => luid_index,
            Err(_) => continue,
        };

        let mut luid2 = NET_LUID { Value: 0 };

        luid2.set_IfType(if_type as _);
        luid2.set_NetLuidIndex(luid_index as _);

        if luid.Value != luid2.Value {
            continue;
        }

        // Found it!
        return Ok(());
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "TAP Device not found"))
}

/// Deletes an existing interface
pub fn delete_interface(luid: &NET_LUID) -> io::Result<()> {
    let devinfo = ffi::get_class_devs(&GUID_NETWORK_ADAPTER, DIGCF_PRESENT)?;

    let _guard = guard((), |_| {
        let _ = ffi::destroy_device_info_list(devinfo);
    });

    let mut member_index = 0;

    while let Some(devinfo_data) = ffi::enum_device_info(devinfo, member_index)
    {
        member_index += 1;

        let devinfo_data = match devinfo_data {
            Ok(devinfo_data) => devinfo_data,
            Err(_) => continue,
        };

        let hardware_id = match ffi::get_device_registry_property(
            devinfo,
            &devinfo_data,
            SPDRP_HARDWAREID,
        ) {
            Ok(hardware_id) => hardware_id,
            Err(_) => continue,
        };

        if !decode_utf16(&hardware_id).eq_ignore_ascii_case(HARDWARE_ID) {
            continue;
        }

        let key = match ffi::open_dev_reg_key(
            devinfo,
            &devinfo_data,
            DICS_FLAG_GLOBAL,
            0,
            DIREG_DRV,
            KEY_QUERY_VALUE | KEY_NOTIFY,
        ) {
            Ok(key) => RegKey::predef(key),
            Err(_) => continue,
        };

        let if_type: DWORD = match key.get_value("*IfType") {
            Ok(if_type) => if_type,
            Err(_) => continue,
        };

        let luid_index: DWORD = match key.get_value("NetLuidIndex") {
            Ok(luid_index) => luid_index,
            Err(_) => continue,
        };

        let mut luid2 = NET_LUID { Value: 0 };

        luid2.set_IfType(if_type as _);
        luid2.set_NetLuidIndex(luid_index as _);

        if luid.Value != luid2.Value {
            continue;
        }

        // Found it!
        return ffi::call_class_installer(devinfo, &devinfo_data, DIF_REMOVE);
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "TAP Device not found"))
}

/// Open an handle to an interface
pub fn open_interface(luid: &NET_LUID) -> io::Result<HANDLE> {
    let guid = ffi::luid_to_guid(luid)
        .and_then(|guid| ffi::string_from_guid(&guid))?;

    let path = format!(r"\\.\Global\{}.tap", &decode_utf16(&guid));

    ffi::create_file(
        &encode_utf16(&path),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,//FILE_ATTRIBUTE_SYSTEM,
    )
}
