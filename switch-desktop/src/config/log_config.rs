use std::io;
use crate::config::SWITCH_HOME_PATH;
#[cfg(target_os = "windows")]
pub fn log_service_init() -> io::Result<()> {
    log_init_("switch-service.log")
}
pub fn log_init() -> io::Result<()> {
    log_init_("switch.log")
}
pub fn log_init_(file_name:&str) -> io::Result<()> {
    let home = SWITCH_HOME_PATH.lock().clone();
    let home = if let Some(home) = home {
        home
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, "not found"));
    };
    let stderr = log4rs::append::console::ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stderr)
        .build();
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join(file_name))?;
    match log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .appender(
            log4rs::config::Appender::builder()
                .filter(Box::new(log4rs::filter::threshold::ThresholdFilter::new(
                    log::LevelFilter::Error,
                )))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(log::LevelFilter::Info),
        ) {
        Ok(config) => {
            let _ = log4rs::init_config(config);
        }
        Err(_) => {}
    }
    Ok(())
}