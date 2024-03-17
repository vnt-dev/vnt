use std::fs::File;
use std::io::Write;
use rand::Rng;

fn main() {
    // 生成随机序列号
    let serial_number = format!("{}-{}-{}",rand::thread_rng().gen_range(100..1000)
                                ,rand::thread_rng().gen_range(100..1000)
                                ,rand::thread_rng().gen_range(100..1000));
    let generated_code = format!(
        r#"pub const SERIAL_NUMBER: &str = "{}";"#,
        serial_number
    );
    let dest_path = "src/generated_serial_number.rs";
    let mut file = File::create(&dest_path).unwrap();
    file.write_all(generated_code.as_bytes()).unwrap();
}
