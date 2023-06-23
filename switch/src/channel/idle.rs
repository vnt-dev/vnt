use std::io;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use crate::channel::channel::Context;
use crate::channel::RouteKey;


pub struct Idle {
    read_idle: i64,
    context: Context,
}

impl Idle {
    pub fn new(read_idle: i64,
               context: Context, ) -> Self {
        Self {
            read_idle,
            context,
        }
    }
}

impl Idle {
    /// 获取空闲路由
    pub async fn next_idle(&self) -> io::Result<(Ipv4Addr, RouteKey)> {
        loop {
            let now = chrono::Local::now().timestamp_millis();
            let last_read_idle = now - self.read_idle;
            let mut min = i64::MAX;
            for entry in self.context.route_table_time.iter() {
                let mut is_read_idle = false;
                if self.read_idle > 0 {
                    let last_read = entry.value().load(Ordering::Relaxed);
                    if last_read < last_read_idle {
                        is_read_idle = true;
                    } else {
                        if min > last_read {
                            min = last_read;
                        }
                    }
                }
                if is_read_idle {
                    return Ok((entry.key().1.clone(), entry.key().0.clone()));
                }
            }
            if self.context.route_table_time.is_empty() {
                self.context.notify.notified().await;
            } else {
                let sleep_time = chrono::Local::now().timestamp_millis() - min;
                if sleep_time > 0 {
                    tokio::time::sleep(Duration::from_millis(sleep_time as u64)).await;
                    // let _ =  tokio::time::timeout(Duration::from_millis(sleep_time as u64),  self.context.notify.notified()).await;
                }
            }
            if self.context.is_close() {
                return Err(Error::new(ErrorKind::Other, "closed"));
            }
        }
    }
}