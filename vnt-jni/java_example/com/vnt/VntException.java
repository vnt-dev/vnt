package com.vnt;

/**
 * VNT异常
 *
 * VNT操作失败时抛出的异常
 */
public class VntException extends Exception {

    public VntException(String message) {
        super(message);
    }

    public VntException(String message, Throwable cause) {
        super(message, cause);
    }

    public VntException(Throwable cause) {
        super(cause);
    }
}
