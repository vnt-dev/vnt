use crate::channel::context::ChannelContext;
use crate::channel::RouteKey;

pub trait RecvChannelHandler: Clone + Send + 'static {
    fn handle(
        &mut self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
        context: &ChannelContext,
    );
}
