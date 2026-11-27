package com.guardgate.gateway.ratelimit;

import com.guardgate.gateway.web.ClientIpResolver;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Rate limit theo IP, chạy TRƯỚC Spring Security (order -200 &lt; -100): request bị chặn không tốn
 * công verify JWT hay gọi Redis denylist, nên flood không làm quá tải phần xác thực.
 */
@Component
public class IpRateLimitWebFilter implements WebFilter, Ordered {

    private static final Set<String> AUTH_PATHS = Set.of("/api/auth/login", "/api/auth/register", "/api/auth/refresh");

    private final RateLimiterService rateLimiter;
    private final RateLimitRejection rejection;
    private final ClientIpResolver clientIpResolver;

    public IpRateLimitWebFilter(RateLimiterService rateLimiter, RateLimitRejection rejection,
                                ClientIpResolver clientIpResolver) {
        this.rateLimiter = rateLimiter;
        this.rejection = rejection;
        this.clientIpResolver = clientIpResolver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String ip = clientIpResolver.resolve(exchange);
        Mono<Void> ipCheck = check(exchange, chain, RateLimitPolicy.IP, ip);
        if (!isAuthEndpoint(exchange)) {
            return ipCheck;
        }
        return rateLimiter.consume(RateLimitPolicy.AUTH_IP, ip)
                .flatMap(decision -> decision.allowed() ? ipCheck : rejection.reject(exchange, RateLimitPolicy.AUTH_IP));
    }

    private Mono<Void> check(ServerWebExchange exchange, WebFilterChain chain, RateLimitPolicy policy, String key) {
        return rateLimiter.consume(policy, key)
                .flatMap(decision -> decision.allowed() ? chain.filter(exchange) : rejection.reject(exchange, policy));
    }

    private static boolean isAuthEndpoint(ServerWebExchange exchange) {
        return HttpMethod.POST.equals(exchange.getRequest().getMethod())
                && AUTH_PATHS.contains(exchange.getRequest().getPath().pathWithinApplication().value());
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
