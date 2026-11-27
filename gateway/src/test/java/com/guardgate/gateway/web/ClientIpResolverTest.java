package com.guardgate.gateway.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetSocketAddress;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

class ClientIpResolverTest {

    @Test
    void withoutTrustedProxiesIgnoresForwardedForHeader() {
        // Review Focus #1: client tự gửi XFF để giả IP
        assertThat(new ClientIpResolver(0).resolve(exchange("10.0.0.5", "1.2.3.4"))).isEqualTo("10.0.0.5");
    }

    @Test
    void withOneTrustedProxyUsesAddressAddedByThatProxy() {
        assertThat(new ClientIpResolver(1).resolve(exchange("10.0.0.5", "1.2.3.4"))).isEqualTo("1.2.3.4");
    }

    @Test
    void withOneTrustedProxyIgnoresValuesSpoofedBeforeTheProxy() {
        // Client gửi "6.6.6.6", ingress nối thêm IP thật "1.2.3.4": chỉ tin phần tử do ingress thêm (bên phải)
        assertThat(new ClientIpResolver(1).resolve(exchange("10.0.0.5", "6.6.6.6, 1.2.3.4"))).isEqualTo("1.2.3.4");
    }

    @Test
    void withTrustedProxyButNoHeaderFallsBackToRemoteAddress() {
        assertThat(new ClientIpResolver(1).resolve(exchange("10.0.0.5", null))).isEqualTo("10.0.0.5");
    }

    private static MockServerWebExchange exchange(String remoteIp, String forwardedFor) {
        MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
                .remoteAddress(new InetSocketAddress(remoteIp, 40000));
        if (forwardedFor != null) {
            request.header("X-Forwarded-For", forwardedFor);
        }
        return MockServerWebExchange.from(request.build());
    }
}
