use crate::channel::context::ChannelContext;
use crate::channel::RouteKey;

pub trait RecvChannelHandler: Clone + Send + Sync + 'static {
    fn handle(
        &self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
        context: &ChannelContext,
    );
}
