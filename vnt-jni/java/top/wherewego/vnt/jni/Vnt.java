package top.wherewego.vnt.jni;

import java.io.Closeable;
import java.io.IOException;

/**
 * vnt的Java映射
 *
 * @author https://github.com/lbl8603/vnt
 */
public class Vnt implements Closeable {
    private final long raw;

    public Vnt(Config config, CallBack callBack) throws Exception{
        this.raw = new0(config, callBack);
    }

    public void stop() {
        stop0(raw);
    }

    public void await() {
        wait0(raw);
    }

    public PeerDeviceInfo[] list() {
        return list0(raw);
    }

    private native long new0(Config config, CallBack callBack) throws Exception;

    private native void stop0(long raw);

    private native void wait0(long raw);

    private native void drop0(long raw);

    private native PeerDeviceInfo[] list0(long raw);

    @Override
    public void close() throws IOException {
        drop0(raw);
    }
}
