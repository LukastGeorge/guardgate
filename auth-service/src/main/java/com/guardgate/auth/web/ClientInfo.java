package com.guardgate.auth.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

/**
 * IP + User-Agent của client cho audit log. getRemoteAddr() đã được Tomcat RemoteIpValve thay bằng
 * IP thật từ X-Forwarded-For, nhưng CHỈ khi request đi qua proxy nội bộ (server.forward-headers-strategy=native).
 */
public record ClientInfo(String ipAddress, String userAgent) {

    public static ClientInfo from(HttpServletRequest request) {
        return new ClientInfo(request.getRemoteAddr(), request.getHeader(HttpHeaders.USER_AGENT));
    }
}
