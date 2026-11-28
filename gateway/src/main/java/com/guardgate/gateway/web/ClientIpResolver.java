package com.guardgate.gateway.web;

import java.net.InetSocketAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.support.ipresolver.XForwardedRemoteAddressResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

/**
 * Xác định IP thật của client (D9). Dùng cho X-Forwarded-For gửi xuống service và cho rate limit.
 *
 * <ul>
 *   <li>{@code trustedProxies = 0} (chạy local, gateway là điểm vào): dùng địa chỉ TCP, bỏ qua mọi
 *       X-Forwarded-For do client gửi vì client có thể ghi bất kỳ giá trị nào.</li>
 *   <li>{@code trustedProxies = n} (sau ingress/load balancer): mỗi proxy NỐI IP nó thấy vào cuối header,
 *       nên chỉ tin phần tử thứ n tính từ bên phải; các giá trị bên trái có thể do client tự đặt.</li>
 * </ul>
 */
@Component
public class ClientIpResolver {

    private final int trustedProxies;

    public ClientIpResolver(@Value("${guardgate.gateway.trusted-proxies:0}") int trustedProxies) {
        if (trustedProxies < 0) {
            throw new IllegalArgumentException("trusted-proxies must be >= 0");
        }
        this.trustedProxies = trustedProxies;
    }

    public String resolve(ServerWebExchange exchange) {
        InetSocketAddress address = trustedProxies > 0
                ? XForwardedRemoteAddressResolver.maxTrustedIndex(trustedProxies).resolve(exchange)
                : exchange.getRequest().getRemoteAddress();
        if (address == null) {
            return "unknown";
        }
        return address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
    }

    public boolean behindTrustedProxy() {
        return trustedProxies > 0;
    }
}
