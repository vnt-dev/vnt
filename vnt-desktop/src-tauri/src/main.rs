#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if vnt_desktop_lib::run_service_control_from_args()? {
        return Ok(());
    }
    vnt_desktop_lib::run()?;
    Ok(())
}
