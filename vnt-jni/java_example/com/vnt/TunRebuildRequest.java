package com.vnt;

import org.json.JSONArray;
import org.json.JSONObject;

/** Final virtual network parameters needed to recreate an Android VPN. */
public final class TunRebuildRequest {
    private final long requestId;
    private final String ip;
    private final int prefixLen;
    private final int mtu;
    private final String sessionName;
    private final JSONArray routes;

    private TunRebuildRequest(long requestId, String ip, int prefixLen, int mtu, String sessionName, JSONArray routes) {
        this.requestId = requestId;
        this.ip = ip;
        this.prefixLen = prefixLen;
        this.mtu = mtu;
        this.sessionName = sessionName;
        this.routes = routes;
    }

    static TunRebuildRequest fromJson(String json) throws VntException {
        try {
            JSONObject value = new JSONObject(json);
            return new TunRebuildRequest(
                    value.getLong("request_id"),
                    value.getString("ip"),
                    value.getInt("prefix_len"),
                    value.getInt("mtu"),
                    value.optString("session_name", null),
                    value.getJSONArray("routes"));
        } catch (Exception error) {
            throw new VntException("Invalid TUN rebuild request", error);
        }
    }

    public long getRequestId() { return requestId; }
    public String getIp() { return ip; }
    public int getPrefixLen() { return prefixLen; }
    public int getMtu() { return mtu; }
    public String getSessionName() { return sessionName; }
    public JSONArray getRoutes() { return routes; }
}
