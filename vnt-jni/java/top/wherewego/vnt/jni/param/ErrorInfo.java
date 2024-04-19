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
        switch (code) {
            case 1:
                this.code = ErrorCodeEnum.TokenError;
                break;
            case 2:
                this.code = ErrorCodeEnum.Disconnect;
                break;
            case 3:
                this.code = ErrorCodeEnum.AddressExhausted;
                break;
            case 4:
                this.code = ErrorCodeEnum.IpAlreadyExists;
                break;
            case 5:
                this.code = ErrorCodeEnum.InvalidIp;
                break;
            default:
                this.code = ErrorCodeEnum.Unknown;
        }
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
