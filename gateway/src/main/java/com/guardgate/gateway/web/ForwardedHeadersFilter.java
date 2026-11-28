package com.guardgate.gateway.web;

import java.net.URI;
import java.util.Locale;
import org.springframework.cloud.gateway.filter.headers.HttpHeadersFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

/**
 * Thay toàn bộ header Forwarded / X-Forwarded-* của client bằng giá trị gateway tự xác định, NGAY TRƯỚC
 * khi gửi request xuống service.
 *
 * <p>auth-service tin X-Forwarded-For từ proxy nội bộ (gateway) để ghi IP vào audit log. Nếu gateway
 * chuyển nguyên header của client xuống, kẻ tấn công chỉ cần gửi "X-Forwarded-For: 6.6.6.6" là giả được IP.
 *
 * <p>Là {@link HttpHeadersFilter} (không phải GlobalFilter) với order thấp nhất: Spring Cloud Gateway 4.3.5+
 * có RemoveXForwardedHeadersFilter (order 0) xoá MỌI X-Forwarded-* khi chưa cấu hình trusted-proxies, kể cả
 * header ta đặt ở GlobalFilter. Chạy sau cùng trong chuỗi HttpHeadersFilter nên giá trị của ta là giá trị cuối.
 */
@Component
public class ForwardedHeadersFilter implements HttpHeadersFilter, Ordered {

    private final ClientIpResolver clientIpResolver;

    public ForwardedHeadersFilter(ClientIpResolver clientIpResolver) {
        this.clientIpResolver = clientIpResolver;
    }

    @Override
    public HttpHeaders filter(HttpHeaders input, ServerWebExchange exchange) {
        // Header GỐC của client (input có thể đã bị filter khác chỉnh sửa)
        HttpHeaders incoming = exchange.getRequest().getHeaders();
        URI uri = exchange.getRequest().getURI();
        boolean trustIncoming = clientIpResolver.behindTrustedProxy();

        String clientIp = clientIpResolver.resolve(exchange);
        String proto = firstOr(trustIncoming ? incoming.getFirst("X-Forwarded-Proto") : null, uri.getScheme());
        // Host header có dạng "host:port"; tách riêng vì Tomcat (auth-service) lấy port từ X-Forwarded-Port,
        // thiếu header này thì nó coi là cổng mặc định của scheme (80) → redirect_uri OAuth2 sai cổng (H4).
        String hostAndPort = firstOr(trustIncoming ? incoming.getFirst("X-Forwarded-Host") : null,
                firstOr(incoming.getFirst(HttpHeaders.HOST), uri.getHost()));
        String host = stripPort(hostAndPort);
        String port = firstOr(trustIncoming ? incoming.getFirst("X-Forwarded-Port") : null,
                portOf(hostAndPort, proto));

        HttpHeaders sanitized = new HttpHeaders();
        input.forEach((name, values) -> {
            if (!isForwardingHeader(name)) {
                sanitized.addAll(name, values);
            }
        });
        sanitized.set("X-Forwarded-For", clientIp);
        sanitized.set("X-Forwarded-Proto", proto);
        sanitized.set("X-Forwarded-Host", host);
        sanitized.set("X-Forwarded-Port", port);
        return sanitized;
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    private static boolean isForwardingHeader(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.equals("forwarded") || lower.startsWith("x-forwarded-") || lower.equals("x-real-ip");
    }

    /** "localhost:8080" → "localhost"; "[::1]:8080" → "[::1]"; "example.com" → "example.com". */
    static String stripPort(String hostAndPort) {
        int colon = hostAndPort.lastIndexOf(':');
        return colon > hostAndPort.lastIndexOf(']') ? hostAndPort.substring(0, colon) : hostAndPort;
    }

    static String portOf(String hostAndPort, String scheme) {
        int colon = hostAndPort.lastIndexOf(':');
        if (colon > hostAndPort.lastIndexOf(']')) {
            return hostAndPort.substring(colon + 1);
        }
        return "https".equalsIgnoreCase(scheme) ? "443" : "80";
    }

    private static String firstOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.split(",")[0].trim();
    }
}
