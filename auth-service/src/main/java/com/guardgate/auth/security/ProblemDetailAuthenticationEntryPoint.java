package com.guardgate.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

/**
 * 401: thiếu token hoặc token không hợp lệ. Không trả chi tiết lý do (hết hạn, sai chữ ký...)
 * để không giúp kẻ tấn công dò token; lý do cụ thể chỉ nằm trong log phía server.
 */
@Component
public class ProblemDetailAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ProblemDetailResponseWriter writer;

    public ProblemDetailAuthenticationEntryPoint(ProblemDetailResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        String challenge = authException instanceof InvalidBearerTokenException
                ? "Bearer error=\"invalid_token\""
                : "Bearer";
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge);
        writer.write(request, response, HttpStatus.UNAUTHORIZED, "Authentication is required");
    }
}
