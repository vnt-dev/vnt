package top.wherewego.vnt.jni.param;

/**
 * 异常回调信息
 *
 * @author https://github.com/lbl8603/vnt
 */
public class ErrorInfo {
    /**
     * 错误码
     */
    public final ErrorCodeEnum code;
    /**
     * 错误信息，可能为空
     */
    public final String msg;

    public ErrorInfo(int code, String msg) {
        this.code = switch (code) {
            case 1 -> ErrorCodeEnum.TokenError;
            case 2 -> ErrorCodeEnum.Disconnect;
            case 3 -> ErrorCodeEnum.AddressExhausted;
            case 4 -> ErrorCodeEnum.IpAlreadyExists;
            case 5 -> ErrorCodeEnum.InvalidIp;
            case 6 -> ErrorCodeEnum.Unknown;
            default -> null;
        };
        this.msg = msg;
    }

    public ErrorCodeEnum getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

    public enum ErrorCodeEnum {
        TokenError,
        Disconnect,
        AddressExhausted,
        IpAlreadyExists,
        InvalidIp,
        Unknown,
    }

    @Override
    public String toString() {
        return "ErrorInfo{" +
                "code=" + code +
                ", msg='" + msg + '\'' +
                '}';
    }
}
