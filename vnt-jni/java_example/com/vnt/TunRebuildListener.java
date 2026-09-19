package com.vnt;

/** Java-owned handler for pull-delivered Android TUN rebuild requests. */
public interface TunRebuildListener {
    void onTunRebuildRequired(TunRebuildRequest request) throws Exception;
}
