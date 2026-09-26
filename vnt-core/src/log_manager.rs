//! 实例日志管理器。
//!
//! 网络核心（`NetworkManager`）与统一监听器（`RuntimeChangeListener`）把运行期
//! 错误信息写入各自实例的 [`InstanceLog`]，宿主（web / JNI / CLI）通过
//! [`LogManager`] 按实例 id 查询。每个实例只保留最近
//! [`MAX_INSTANCE_LOG_ENTRIES`] 条，超出后淘汰最旧记录。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// 每个实例保留的日志条数上限
pub const MAX_INSTANCE_LOG_ENTRIES: usize = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
    /// 本地时间，格式 `HH:MM:SS`
    pub time: String,
}

fn now_time() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let format = time::macros::format_description!("[hour]:[minute]:[second]");
    now.format(&format)
        .unwrap_or_else(|_| "00:00:00".to_string())
}

/// 单个实例的日志环形缓冲：固定容量，写入超过上限时淘汰最旧记录。
#[derive(Debug)]
pub struct InstanceLog {
    id: String,
    entries: Mutex<VecDeque<LogEntry>>,
}

impl InstanceLog {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            entries: Mutex::new(VecDeque::with_capacity(MAX_INSTANCE_LOG_ENTRIES)),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn push(&self, level: LogLevel, message: impl Into<String>) {
        let mut entries = self.entries.lock();
        if entries.len() >= MAX_INSTANCE_LOG_ENTRIES {
            entries.pop_front();
        }
        entries.push_back(LogEntry {
            level,
            message: message.into(),
            time: now_time(),
        });
    }

    pub fn info(&self, message: impl Into<String>) {
        self.push(LogLevel::Info, message);
    }

    pub fn warn(&self, message: impl Into<String>) {
        self.push(LogLevel::Warn, message);
    }

    pub fn error(&self, message: impl Into<String>) {
        self.push(LogLevel::Error, message);
    }

    /// 按时间正序返回全部记录
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
    }
}

/// 按实例 id 管理 [`InstanceLog`]。`instance` 为 get-or-create，保证同一 id
/// 始终拿到同一个 `Arc`（重启时复用的监听器不会写进孤立缓冲）。
#[derive(Debug, Default)]
pub struct LogManager {
    instances: Mutex<HashMap<String, Arc<InstanceLog>>>,
}

impl LogManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn instance(&self, id: &str) -> Arc<InstanceLog> {
        let mut instances = self.instances.lock();
        Arc::clone(instances.entry(id.to_string()).or_insert_with(|| {
            log::debug!("创建实例日志: {id}");
            Arc::new(InstanceLog::new(id))
        }))
    }

    pub fn get(&self, id: &str) -> Option<Arc<InstanceLog>> {
        self.instances.lock().get(id).map(Arc::clone)
    }

    pub fn logs(&self, id: &str) -> Vec<LogEntry> {
        self.get(id).map(|log| log.entries()).unwrap_or_default()
    }

    pub fn remove(&self, id: &str) {
        self.instances.lock().remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_last_entries() {
        let log = InstanceLog::new("a.toml");
        for index in 0..(MAX_INSTANCE_LOG_ENTRIES + 7) {
            log.info(format!("msg-{index}"));
        }
        let entries = log.entries();
        assert_eq!(entries.len(), MAX_INSTANCE_LOG_ENTRIES);
        assert_eq!(entries.first().unwrap().message, "msg-7");
        assert_eq!(
            entries.last().unwrap().message,
            format!("msg-{}", MAX_INSTANCE_LOG_ENTRIES + 6)
        );
        assert!(entries.iter().all(|entry| entry.level == LogLevel::Info));
    }

    #[test]
    fn clear_empties_the_buffer() {
        let log = InstanceLog::new("a.toml");
        log.error("boom");
        assert_eq!(log.entries().len(), 1);
        log.clear();
        assert!(log.entries().is_empty());
    }

    #[test]
    fn manager_creates_and_removes_instances() {
        let manager = LogManager::new();
        assert!(manager.logs("missing").is_empty());

        let first = manager.instance("a.toml");
        first.warn("hello");
        // get-or-create 必须返回同一个 Arc
        assert!(Arc::ptr_eq(&first, &manager.instance("a.toml")));

        let entries = manager.logs("a.toml");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, LogLevel::Warn);
        assert_eq!(entries[0].message, "hello");

        manager.remove("a.toml");
        assert!(manager.get("a.toml").is_none());
        assert!(manager.logs("a.toml").is_empty());
    }
}
