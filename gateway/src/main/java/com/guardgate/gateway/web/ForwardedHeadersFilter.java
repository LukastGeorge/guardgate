package com.guardgate.gateway.web;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Thay toàn bộ header Forwarded / X-Forwarded-* của client bằng giá trị gateway tự xác định.
 *
 * <p>auth-service tin X-Forwarded-For từ proxy nội bộ (gateway) để ghi IP vào audit log. Nếu gateway
 * chuyển nguyên header của client xuống, kẻ tấn công chỉ cần gửi "X-Forwarded-For: 6.6.6.6" là giả được IP.
 * Bộ lọc có sẵn của Spring Cloud Gateway được tắt (application.yml) để chỉ còn một nguồn sự thật.
 */
@Component
public class ForwardedHeadersFilter implements GlobalFilter, Ordered {

    private final ClientIpResolver clientIpResolver;

    public ForwardedHeadersFilter(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = clientIpResolver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest original = exchange.getRequest();
        HttpHeaders incoming = original.getHeaders();
        URI uri = original.getURI();
        boolean trustIncoming = clientIpResolver.behindTrustedProxy();

        String clientIp = clientIpResolver.resolve(exchange);
        String proto = firstOr(trustIncoming ? incoming.getFirst("X-Forwarded-Proto") : null, uri.getScheme());
        String host = firstOr(trustIncoming ? incoming.getFirst("X-Forwarded-Host") : null,
                firstOr(incoming.getFirst(HttpHeaders.HOST), uri.getHost()));

        ServerHttpRequest sanitized = original.mutate().headers(headers -> {
            List<String> toRemove = headers.keySet().stream()
                    .filter(name -> {
                        String lower = name.toLowerCase(Locale.ROOT);
                        return lower.equals("forwarded") || lower.startsWith("x-forwarded-") || lower.equals("x-real-ip");
                    })
                    .toList();
            toRemove.forEach(headers::remove);
            headers.set("X-Forwarded-For", clientIp);
            headers.set("X-Forwarded-Proto", proto);
            headers.set("X-Forwarded-Host", host);
        }).build();
        return chain.filter(exchange.mutate().request(sanitized).build());
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    private static String firstOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.split(",")[0].trim();
    }
}
