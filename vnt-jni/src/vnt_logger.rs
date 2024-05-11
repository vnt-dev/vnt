#[cfg(target_os = "android")]
pub fn init_log() {
    use android_logger::Config;
    use log::LevelFilter;
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info) // limit log level
            .with_tag("vnt_jni"), // logs will show under mytag tag
    );
}
#[cfg(not(target_os = "android"))]
pub fn init_log() {}
