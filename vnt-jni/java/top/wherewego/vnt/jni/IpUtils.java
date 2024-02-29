package top.wherewego.vnt.jni;

/**
 * @author lubeilin
 * @date: 2024/02/27 18:31
 */
public class IpUtils {
    public static String intToIpAddress(int ipAddress) {

        return ((ipAddress & 0xFF000000) >>> 24) + "." +
                ((ipAddress & 0x00FF0000) >>> 16) + "." +
                ((ipAddress & 0x0000FF00) >>> 8) + "." +
                (ipAddress & 0x000000FF);
    }
    public static int subnetMaskToPrefixLength(int subnetMask) {
        int prefixLength = 0;
        int bit = 1 << 31;

        while (subnetMask != 0) {
            if ((subnetMask & bit) != bit) {
                break;
            }
            prefixLength++;
            subnetMask <<= 1;
        }

        return prefixLength;
    }
}
