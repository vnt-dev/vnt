use std::net::Ipv4Addr;
use std::time::Duration;

use crate::channel::context::ChannelContext;
use crate::channel::Route;

pub struct Idle {
    read_idle: Duration,
    context: ChannelContext,
}

impl Idle {
    pub fn new(read_idle: Duration, context: ChannelContext) -> Self {
        Self { read_idle, context }
    }
}

pub enum IdleType {
    Timeout(Ipv4Addr, Route),
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
                    return IdleType::Timeout(*ip, *route);
                } else if max < last_read {
                    max = last_read;
                }
            }
        }
        let sleep_time = self.read_idle.checked_sub(max).unwrap_or_default();
        return IdleType::Sleep(sleep_time);
    }
}
