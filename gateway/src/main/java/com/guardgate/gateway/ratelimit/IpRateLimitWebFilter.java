package com.guardgate.gateway.ratelimit;

import com.guardgate.gateway.web.ClientIpResolver;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Rate limit theo IP, chạy TRƯỚC Spring Security (order -200 &lt; -100): request bị chặn không tốn
 * công verify JWT hay gọi Redis denylist, nên flood không làm quá tải phần xác thực.
 *
 * <p>Nhận diện endpoint đăng nhập bằng CÙNG cơ chế so khớp path với Spring Security và route predicate
 * (PathPattern, so trên segment ĐÃ giải mã). Trước đây so chuỗi thô nên "/api/auth/%6Cogin" lách được giới hạn
 * đăng nhập nhưng vẫn được route và giải mã thành /api/auth/login ở auth-service.
 */
@Component
public class IpRateLimitWebFilter implements WebFilter, Ordered {

    private static final ServerWebExchangeMatcher AUTH_ENDPOINTS = ServerWebExchangeMatchers.pathMatchers(
            HttpMethod.POST, "/api/auth/login", "/api/auth/register", "/api/auth/refresh");

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
        return AUTH_ENDPOINTS.matches(exchange)
                .flatMap(match -> match.isMatch()
                        ? rateLimiter.consume(RateLimitPolicy.AUTH_IP, ip)
                                .flatMap(decision -> decision.allowed()
                                        ? checkIp(exchange, chain, ip)
                                        : rejection.reject(exchange, RateLimitPolicy.AUTH_IP))
                        : checkIp(exchange, chain, ip));
    }

    private Mono<Void> checkIp(ServerWebExchange exchange, WebFilterChain chain, String ip) {
        return rateLimiter.consume(RateLimitPolicy.IP, ip)
                .flatMap(decision -> decision.allowed()
                        ? chain.filter(exchange)
                        : rejection.reject(exchange, RateLimitPolicy.IP));
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
