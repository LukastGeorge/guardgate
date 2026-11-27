package com.guardgate.gateway.ratelimit;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Rate limit theo user (claim "sub"). Chạy SAU Spring Security (là GlobalFilter của gateway) nên chỉ
 * tính cho token đã được verify; request ẩn danh chỉ bị giới hạn theo IP.
 */
@Component
public class UserRateLimitGlobalFilter implements GlobalFilter, Ordered {

    private final RateLimiterService rateLimiter;
    private final RateLimitRejection rejection;

    public UserRateLimitGlobalFilter(RateLimiterService rateLimiter, RateLimitRejection rejection) {
        this.rateLimiter = rateLimiter;
        this.rejection = rejection;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(principal -> ((JwtAuthenticationToken) principal).getName())
                .flatMap(subject -> rateLimiter.consume(RateLimitPolicy.USER, subject))
                .flatMap(decision -> decision.allowed()
                        ? chain.filter(exchange)
                        : rejection.reject(exchange, RateLimitPolicy.USER))
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
