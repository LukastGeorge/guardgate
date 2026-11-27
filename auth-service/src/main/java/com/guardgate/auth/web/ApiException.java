package com.guardgate.auth.web;

import org.springframework.http.HttpStatus;

/**
 * Lỗi nghiệp vụ "dự kiến trước" (sai mật khẩu, email trùng...). Message là văn bản an toàn để trả
 * cho client. Không ghi stack trace vì đây không phải bug, giúp tiết kiệm CPU khi bị brute-force.
 */
public abstract class ApiException extends RuntimeException {

    private final HttpStatus status;

    protected ApiException(HttpStatus status, String clientMessage) {
        super(clientMessage, null, false, false);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
