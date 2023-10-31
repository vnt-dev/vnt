use std::io;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::channel::channel::Context;
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

impl Idle {
    /// 获取空闲路由
    pub async fn next_idle(&self) -> io::Result<(Ipv4Addr, RouteKey)> {
        loop {
            let mut max = Duration::from_secs(0);
            {
                for (ip, routes) in self.context.inner.route_table.read().iter() {
                    for (route, time) in routes {
                        let last_read = time.load().elapsed();
                        if last_read >= self.read_idle {
                            return Ok((*ip, route.route_key()));
                        } else {
                            if max < last_read {
                                max = last_read;
                            }
                        }
                    }
                }
            }
            if self.read_idle > max {
                let sleep_time = self.read_idle - max;
                tokio::time::sleep(sleep_time).await;
            }
            if self.context.is_close() {
                return Err(Error::new(ErrorKind::Other, "closed"));
            }
        }
    }
}
