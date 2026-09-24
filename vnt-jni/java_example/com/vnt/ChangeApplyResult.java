package com.vnt;

import org.json.JSONObject;

/**
 * applyRuntimeChange 的应用结果。
 *
 * action 取值：
 * <ul>
 *   <li>{@code applied} — 快照已应用（纯策略/服务器变更原地生效，或网卡
 *       相关变更已按新接口重建）</li>
 *   <li>{@code need_fd} — 虚拟地址或 MTU 变化但未携带新 fd，宿主需要用
 *       快照里的 IP/MTU 重建 VPN 接口后携带新 fd 重试；error 说明原因</li>
 *   <li>{@code rebuild} — 快照包含只能重建实例生效的字段（密码/出口网卡
 *       等），宿主同样需要用快照参数重建 VPN 接口并携带新 fd 重试，组网
 *       实例由 native 内部重建</li>
 * </ul>
 */
public final class ChangeApplyResult {

    private final String action;
    private final String error;

    private ChangeApplyResult(String action, String error) {
        this.action = action;
        this.error = error;
    }

    static ChangeApplyResult fromJson(String json) throws VntException {
        try {
            JSONObject obj = new JSONObject(json);
            return new ChangeApplyResult(
                    obj.getString("action"),
                    obj.has("error") && !obj.isNull("error") ? obj.getString("error") : null);
        } catch (Exception error) {
            throw new VntException("Invalid runtime change result payload", error);
        }
    }

    /** applied / need_fd / rebuild */
    public String getAction() {
        return action;
    }

    /** action=need_fd 时的原因说明。 */
    public String getError() {
        return error;
    }

    public boolean isApplied() {
        return "applied".equals(action);
    }

    public boolean isNeedFd() {
        return "need_fd".equals(action);
    }

    public boolean isRebuild() {
        return "rebuild".equals(action);
    }

    @Override
    public String toString() {
        return "ChangeApplyResult{action='" + action + "', error='" + error + "'}";
    }
}
