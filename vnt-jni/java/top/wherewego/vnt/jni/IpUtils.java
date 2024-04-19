package top.wherewego.vnt.jni;

/**
 * ip转换
 *
 * @author https://github.com/lbl8603/vnt
 */
public class IpUtils {
    /**
     * 将整数的ip地址转成字符串，例如 0 转成 "0.0.0.0"
     *
     * @param ipAddress
     * @return
     */
    public static String intToIpAddress(int ipAddress) {

        return ((ipAddress & 0xFF000000) >>> 24) + "." +
                ((ipAddress & 0x00FF0000) >>> 16) + "." +
                ((ipAddress & 0x0000FF00) >>> 8) + "." +
                (ipAddress & 0x000000FF);
    }

    /**
     * 返回掩码的长度
     *
     * @param subnetMask
     * @return
     */
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
