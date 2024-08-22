use crate::channel::context::ChannelContext;
use crate::channel::RouteKey;

use async_trait::async_trait;

#[async_trait]
pub trait RecvChannelHandler: Clone + Send + Sync + 'static {
    async fn handle(
        &self,
        buf: &mut [u8],
        extend: &mut [u8],
        route_key: RouteKey,
        context: &ChannelContext,
    );
}
