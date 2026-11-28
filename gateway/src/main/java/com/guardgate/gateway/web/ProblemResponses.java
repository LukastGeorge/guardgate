package com.guardgate.gateway.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.util.Map;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Ghi lỗi RFC 9457 (application/problem+json) trực tiếp vào response reactive. Dùng chung cho
 * Spring Security (401/403), error handler (404/5xx) và rate limiter (429), để mọi lỗi có cùng một định dạng.
 */
public final class ProblemResponses {

    /** Jackson2ObjectMapperBuilder tự đăng ký mixin để serialize ProblemDetail đúng chuẩn. */
    private static final ObjectMapper MAPPER = Jackson2ObjectMapperBuilder.json().build();

    private ProblemResponses() {
    }

    public static Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String detail) {
        return write(exchange, status, detail, Map.of());
    }

    public static Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String detail,
                                   Map<String, Object> extraProperties) {
        ServerHttpResponse response = exchange.getResponse();
        if (response.isCommitted()) {
            return Mono.empty();
        }
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setInstance(URI.create(exchange.getRequest().getPath().value()));
        extraProperties.forEach(problem::setProperty);

        byte[] body;
        try {
            body = MAPPER.writeValueAsBytes(problem);
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().setContentLength(body.length);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }
}
