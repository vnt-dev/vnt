use std::io::Write;
use std::path::PathBuf;
pub fn log_init(log_name: &str) {
    log_init0(log_name, None);
}
pub fn log_init0(log_name: &str, yaml: Option<&str>) {
    let path = PathBuf::from("logs");

    if !path.exists() {
        let _ = std::fs::create_dir(&path);
    }

    let log_config = path.join(yaml.unwrap_or("log4rs.yaml"));

    if !log_config.exists()
        && let Ok(mut f) = std::fs::File::create(&log_config)
    {
        let log_file = path.join(format!("{log_name}.log"));
        let mut string = String::new();
        string.push_str(log_name);
        string.push_str(".{}.log");
        let log_file_pattern = path.join(&string);

        let c = format!(
            r#"
refresh_rate: 30 seconds
appenders:
  rolling_file:
    kind: rolling_file
    path: {}
    append: true
    encoder:
      pattern: "{{d}} [{{f}}:{{L}}] {{h({{l}})}} {{M}}:{{m}}{{n}}"
    policy:
      kind: compound
      trigger:
        kind: size
        limit: 10 mb
      roller:
        kind: fixed_window
        pattern: {}
        base: 1
        count: 5
  console:
    kind: console
    encoder:
      pattern: "{{d}} {{h({{l}})}} {{m}}{{n}}"
root:
  level: info
  appenders:
    - rolling_file
    - console
"#,
            log_file.display(),
            log_file_pattern.display()
        );
        let _ = f.write_all(c.as_bytes());
    }

    let _ = log4rs::init_file(log_config, Default::default());
}
