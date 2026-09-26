package com.vnt;

import org.json.JSONObject;

/**
 * 一次运行期事件，{@link VntNetwork#nextEvent()} 的返回。
 *
 * 与 PC 端 cli/web 主循环的 nextEvent 分支一一对应：
 * <ul>
 *   <li>{@code instance_stopped} — 组网实例已停止（自行退出），宿主应
 *       结束变更循环并停止网络</li>
 *   <li>{@code changed} — 收到新的完整快照，宿主据此决定是否重建 VPN
 *       接口，再由 {@link VntNetwork#applyRuntimeChange(int)} 消费</li>
 * </ul>
 */
public final class RuntimeEvent {

    private final String event;
    private final RuntimeChange change;

    private RuntimeEvent(String event, RuntimeChange change) {
        this.event = event;
        this.change = change;
    }

    static RuntimeEvent fromJson(String json) throws VntException {
        try {
            JSONObject obj = new JSONObject(json);
            String event = obj.getString("event");
            RuntimeChange change = null;
            if (obj.has("change") && !obj.isNull("change")) {
                change = RuntimeChange.fromJson(obj.getJSONObject("change"));
            }
            return new RuntimeEvent(event, change);
        } catch (Exception error) {
            throw new VntException("Invalid runtime event payload", error);
        }
    }

    /** 组网实例已停止：宿主应结束变更循环。 */
    public boolean isInstanceStopped() {
        return "instance_stopped".equals(event);
    }

    /** 收到新的完整快照。 */
    public boolean isChanged() {
        return "changed".equals(event);
    }

    /** changed 事件携带的最新快照；instance_stopped 时为 null。 */
    public RuntimeChange getChange() {
        return change;
    }

    @Override
    public String toString() {
        return "RuntimeEvent{event='" + event + "', change=" + change + '}';
    }
}
