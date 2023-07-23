
use std::process::Command;

#[cfg(target_os = "windows")]
pub fn get_unique_identifier() -> Option<String> {
    use std::os::windows::process::CommandExt;
    let output = match Command::new("wmic")
        .creation_flags(0x08000000)
        .args(&["csproduct", "get", "UUID"])
        .output() {
        Ok(output) => { output }
        Err(_) => {
            return None;
        }
    };

    let result = String::from_utf8_lossy(&output.stdout);
    let identifier = result.lines().nth(1).unwrap_or("").trim();
    if identifier.is_empty() {
        None
    } else {
        Some(identifier.to_string())
    }
}

#[cfg(target_os = "macos")]
pub fn get_unique_identifier() -> Option<String> {
    let output = match Command::new("ioreg")
        .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
        .output() {
        Ok(output) => { output }
        Err(_) => {
            return None;
        }
    };

    let result = String::from_utf8_lossy(&output.stdout);
    let identifier = result
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .unwrap_or("").trim();
    if identifier.is_empty() {
        None
    } else {
        Some(identifier.to_string())
    }
}

#[cfg(target_os = "linux")]
pub fn get_unique_identifier() -> Option<String> {
    let output = match Command::new("dmidecode")
        .arg("-s")
        .arg("system-uuid")
        .output() {
        Ok(output) => { output }
        Err(_) => {
            return None;
        }
    };

    let result = String::from_utf8_lossy(&output.stdout);
    let identifier = result.trim().to_string();
    if identifier.is_empty() {
        None
    } else {
        Some(identifier.to_string())
    }
}