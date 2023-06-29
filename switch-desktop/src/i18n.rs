#[cfg(target_os = "windows")]
fn get_default_language() -> Option<String> {
    use std::process::Command;
    use std::str;

    let output = Command::new("powershell")
        .arg("-Command")
        .arg("[System.Globalization.CultureInfo]::CurrentCulture.Name")
        .output()
        .ok()?;

    let language_code = str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .to_string();

    Some(language_code)
}

pub fn init() {
    #[cfg(target_os = "windows")]
    {
        if let Some(l) = get_default_language() {
            rust_i18n::set_locale(&l);
        }
    }
}

pub fn switch_about() -> String {
    rust_i18n::t!("switch_about")
}

pub fn switch_usage() -> String {
    rust_i18n::t!("switch_usage")
}

pub fn switch_start_about() -> String {
    rust_i18n::t!("switch_start_about")
}

pub fn switch_token_help() -> String {
    rust_i18n::t!("switch_token_help")
}

pub fn switch_name_help() -> String {
    rust_i18n::t!("switch_name_help")
}

pub fn switch_device_id_help() -> String {
    rust_i18n::t!("switch_device_id_help")
}

pub fn switch_server_help() -> String {
    rust_i18n::t!("switch_server_help")
}

pub fn switch_nat_test_server_help() -> String {
    rust_i18n::t!("switch_nat_test_server_help")
}

pub fn switch_log_help() -> String {
    rust_i18n::t!("switch_log_help")
}

pub fn switch_tap_help() -> String {
    rust_i18n::t!("switch_tap_help")
}

pub fn switch_in_ip_help() -> String {
    rust_i18n::t!("switch_in_ip_help")
}

pub fn switch_out_ip_help() -> String {
    rust_i18n::t!("switch_out_ip_help")
}
pub fn switch_password_help() -> String {
    rust_i18n::t!("switch_password_help")
}
pub fn switch_simulate_multicast_help() -> String {
    rust_i18n::t!("switch_simulate_multicast_help")
}

pub fn switch_config_help() -> String {
    rust_i18n::t!("switch_config_help")
}

pub fn switch_stop_about() -> String {
    rust_i18n::t!("switch_stop_about")
}

pub fn switch_route_about() -> String {
    rust_i18n::t!("switch_route_about")
}

pub fn switch_list_about() -> String {
    rust_i18n::t!("switch_list_about")
}

pub fn switch_list_all_help() -> String {
    rust_i18n::t!("switch_list_all_help")
}

pub fn switch_status_about() -> String {
    rust_i18n::t!("switch_status_about")
}

#[cfg(windows)]
pub fn switch_install_about() -> String {
    rust_i18n::t!("switch_install_about")
}

#[cfg(windows)]
pub fn switch_path_help() -> String {
    rust_i18n::t!("switch_path_help")
}

#[cfg(windows)]
pub fn switch_auto_help() -> String {
    rust_i18n::t!("switch_auto_help")
}

#[cfg(windows)]
pub fn switch_uninstall_about() -> String {
    rust_i18n::t!("switch_uninstall_about")
}

#[cfg(windows)]
pub fn switch_config_about() -> String {
    rust_i18n::t!("switch_config_about")
}

#[cfg(windows)]
pub fn switch_use_root_print() -> String {
    rust_i18n::t!("switch_use_admin_print")
}

#[cfg(unix)]
pub fn switch_use_root_print() -> String {
    rust_i18n::t!("switch_use_root_print")
}

#[cfg(windows)]
pub fn switch_service_not_start_print() -> String {
    rust_i18n::t!("switch_service_not_start_print")
}

pub fn switch_start_successfully_print() -> String {
    rust_i18n::t!("switch_start_successfully_print")
}

#[cfg(windows)]
pub fn switch_start_failed_print() -> String {
    rust_i18n::t!("switch_start_failed_print")
}

#[cfg(windows)]
pub fn switch_service_not_stopped_print() -> String {
    rust_i18n::t!("switch_service_not_stopped_print")
}

#[cfg(windows)]
pub fn switch_server_already_installed_print() -> String {
    rust_i18n::t!("switch_server_already_installed_print")
}

pub fn switch_repeated_start_print() -> String {
    rust_i18n::t!("switch_repeated_start_print")
}

pub fn switch_stopped_print() -> String {
    rust_i18n::t!("switch_stopped_print")
}

pub fn switch_token_not_found_print() -> String {
    rust_i18n::t!("switch_token_not_found_print")
}

pub fn switch_token_cannot_be_empty_print() -> String {
    rust_i18n::t!("switch_token_cannot_be_empty_print")
}

pub fn switch_token_cannot_exceed_64_print() -> String {
    rust_i18n::t!("switch_token_cannot_exceed_64_print")
}

pub fn switch_device_id_is_empty_print() -> String {
    rust_i18n::t!("switch_device_id_is_empty_print")
}

pub fn switch_in_ips_example_print() -> String {
    rust_i18n::t!("switch_in_ips_example_print")
}

pub fn switch_out_ips_example_print() -> String {
    rust_i18n::t!("switch_out_ips_example_print")
}

pub fn switch_relay_server_address_error() -> String {
    rust_i18n::t!("switch_relay_server_address_error")
}

pub fn switch_nat_test_server_address_error() -> String {
    rust_i18n::t!("switch_nat_test_server_address_error")
}

pub fn switch_press_any_key_to_exit() -> String {
    rust_i18n::t!("switch_press_any_key_to_exit")
}
pub fn switch_virtual_ip() -> String {
    rust_i18n::t!("switch_virtual_ip")
}
pub fn switch_virtual_gateway() -> String {
    rust_i18n::t!("switch_virtual_gateway")
}
pub fn switch_please_enter_the_command() -> String {
    rust_i18n::t!("switch_please_enter_the_command")
}