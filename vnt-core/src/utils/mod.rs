pub mod device_id;
pub(crate) mod dns_query;
pub mod task_control;
pub(crate) mod time {
    pub fn now_ts_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }
}
