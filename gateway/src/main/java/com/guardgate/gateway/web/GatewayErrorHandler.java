package com.guardgate.gateway.web;

import java.io.IOException;
import java.net.ConnectException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Bắt mọi lỗi chưa được xử lý và trả problem+json. Order -2: chạy trước handler mặc định của Boot (-1),
 * vốn trả JSON có field "trace"/"exception" tuỳ cấu hình.
 */
@Component
@Order(-2)
public class GatewayErrorHandler implements ErrorWebExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GatewayErrorHandler.class);

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }
        if (ex instanceof ResponseStatusException rse) {
            HttpStatus status = HttpStatus.resolve(rse.getStatusCode().value());
            if (status == null) {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
            }
            // Không dùng rse.getReason(): có thể chứa chi tiết nội bộ (tên resource, message của Netty)
            return ProblemResponses.write(exchange, status, status.getReasonPhrase());
        }
        if (hasCause(ex, AuthenticationServiceException.class)) {
            // Không tải được JWKS từ auth-service: lỗi hạ tầng, không phải lỗi của client
            log.warn("Authentication infrastructure unavailable: {}", ex.toString());
            return ProblemResponses.write(exchange, HttpStatus.SERVICE_UNAVAILABLE,
                    "Authentication service unavailable");
        }
        if (hasCause(ex, TimeoutException.class)) {
            return ProblemResponses.write(exchange, HttpStatus.GATEWAY_TIMEOUT, "Upstream service timed out");
        }
        if (hasCause(ex, ConnectException.class) || hasCause(ex, IOException.class)) {
            log.warn("Upstream unavailable for {}: {}", exchange.getRequest().getPath(), ex.toString());
            return ProblemResponses.write(exchange, HttpStatus.SERVICE_UNAVAILABLE, "Upstream service unavailable");
        }
        String errorId = UUID.randomUUID().toString();
        log.error("Unhandled exception errorId={}", errorId, ex);
        return ProblemResponses.write(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred",
                Map.of("errorId", errorId));
    }

    private static boolean hasCause(Throwable ex, Class<? extends Throwable> type) {
        for (Throwable current = ex; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
        }
        return false;
    }
}
