use std::io;
use std::path::PathBuf;

pub fn log_init_service(home: PathBuf) -> io::Result<()> {
    if !home.exists() {
        std::fs::create_dir(&home)?;
    }
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch-service.log"))?;
    match log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Info),
        ) {
        Ok(config) => {
            let _ = log4rs::init_config(config);
        }
        Err(_) => {}
    }
    Ok(())
}

pub fn log_init() -> io::Result<()> {
    let home = dirs::home_dir().unwrap().join(".switch");
    if !home.exists() {
        std::fs::create_dir(&home)?;
    }
    let stderr = log4rs::append::console::ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stderr)
        .build();
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch.log"))?;
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