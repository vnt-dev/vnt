use crate::channel::context::Context;
use crate::channel::RouteKey;

pub trait RecvChannelHandler: Clone + Send + 'static {
    fn handle(&mut self, buf: &mut [u8], route_key: RouteKey, context: &Context);
}
