use std::path::PathBuf;

pub fn get_home() -> PathBuf {
    let home = dirs::home_dir().unwrap().join(".switch_desktop");
    if !home.exists() {
        std::fs::create_dir(&home).unwrap();
    }
    home
}