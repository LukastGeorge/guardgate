package com.guardgate.gateway.web;

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Giới hạn kích thước body (D13) cho MỌI request, kể cả khi không có Content-Length (Transfer-Encoding: chunked).
 *
 * <p>Thay cho filter RequestSize có sẵn của Spring Cloud Gateway: filter đó chỉ đọc header Content-Length,
 * nên body chunked hàng trăm MB vẫn được stream nguyên vẹn tới auth-service (DoS bộ nhớ). Ở đây:
 * <ul>
 *   <li>Content-Length khai báo quá giới hạn → 413 ngay, không đọc body.</li>
 *   <li>Không có Content-Length → đếm byte khi body chảy qua; vượt giới hạn thì huỷ stream bằng 413.</li>
 * </ul>
 */
@Component
public class RequestBodySizeLimitFilter implements WebFilter, Ordered {

    private final long maxBytes;

    public RequestBodySizeLimitFilter(@Value("${guardgate.gateway.max-request-body-size:1MB}") DataSize maxSize) {
        this.maxBytes = maxSize.toBytes();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long declared = exchange.getRequest().getHeaders().getContentLength();
        if (declared > maxBytes) {
            return ProblemResponses.write(exchange, HttpStatus.PAYLOAD_TOO_LARGE, "Request body is too large");
        }
        ServerHttpRequestDecorator limited = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                AtomicLong total = new AtomicLong();
                return super.getBody().map(buffer -> {
                    if (total.addAndGet(buffer.readableByteCount()) > maxBytes) {
                        DataBufferUtils.release(buffer);
                        throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE);
                    }
                    return buffer;
                });
            }
        };
        return chain.filter(exchange.mutate().request(limited).build());
    }

    @Override
    public int getOrder() {
        return -250;
    }
}
