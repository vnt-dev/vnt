package com.vnt;

/** The same deterministic mapping as vnt_core::virtual_ipv6. */
public final class VirtualIpv6 {
    public static final int PREFIX_LEN = 96;
    public static final String ROUTE = "fd76:6e74::/96";

    private VirtualIpv6() {}

    public static String address(String nodeIp) {
        String[] parts = nodeIp.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid node IPv4: " + nodeIp);
        int[] bytes = new int[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = Integer.parseInt(parts[i]);
            if (bytes[i] < 0 || bytes[i] > 255) throw new IllegalArgumentException("Invalid node IPv4: " + nodeIp);
        }
        return "fd76:6e74::" + Integer.toHexString((bytes[0] << 8) | bytes[1])
                + ":" + Integer.toHexString((bytes[2] << 8) | bytes[3]);
    }
}
