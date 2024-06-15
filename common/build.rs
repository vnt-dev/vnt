use rand::Rng;
use std::fs::File;
use std::io::Write;

fn main() {
    let now_time = chrono::Local::now();
    let serial_number = format!(
        "{}-{}",
        &now_time.format("%y%m%d%H%M").to_string(),
        rand::thread_rng().gen_range(100..1000)
    );
    let generated_code = format!(r#"pub const SERIAL_NUMBER: &str = "{}";"#, serial_number);
    let dest_path = "src/generated_serial_number.rs";
    let mut file = File::create(&dest_path).unwrap();
    file.write_all(generated_code.as_bytes()).unwrap();
}
