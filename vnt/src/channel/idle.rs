use std::net::Ipv4Addr;
use std::time::Duration;

use crate::channel::context::Context;
use crate::channel::RouteKey;

pub struct Idle {
    read_idle: Duration,
    context: Context,
}

impl Idle {
    pub fn new(read_idle: Duration, context: Context) -> Self {
        Self { read_idle, context }
    }
}

pub enum IdleType {
    Timeout(Ipv4Addr, RouteKey),
    Sleep(Duration),
    None,
}

impl Idle {
    /// 获取空闲路由
    pub fn next_idle(&self) -> IdleType {
        let mut max = Duration::from_secs(0);
        let read_guard = self.context.route_table.route_table.read();
        if read_guard.is_empty() {
            return IdleType::None;
        }
        for (ip, (_, routes)) in read_guard.iter() {
            for (route, time) in routes {
                let last_read = time.load().elapsed();
                if last_read >= self.read_idle {
                    return IdleType::Timeout(*ip, route.route_key());
                } else if max < last_read {
                    max = last_read;
                }
            }
        }
        let sleep_time = self.read_idle - max;
        return IdleType::Sleep(sleep_time);
    }
}
