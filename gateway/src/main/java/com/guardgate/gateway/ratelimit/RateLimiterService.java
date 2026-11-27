package com.guardgate.gateway.ratelimit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Dùng RedisRateLimiter của Spring Cloud Gateway (thuật toán token bucket chạy bằng Lua script trong Redis,
 * nên nhiều instance gateway dùng chung một bucket và thao tác là nguyên tử).
 */
@Service
public class RateLimiterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterService.class);
    private static final String REMAINING_HEADER = "X-RateLimit-Remaining";

    private final RedisRateLimiter redisRateLimiter;

    public RateLimiterService(RedisRateLimiter redisRateLimiter, RateLimitProperties properties) {
        this.redisRateLimiter = redisRateLimiter;
        for (RateLimitPolicy policy : RateLimitPolicy.values()) {
            RateLimitProperties.Policy config = properties.get(policy);
            redisRateLimiter.getConfig().put(policy.id(), new RedisRateLimiter.Config()
                    .setReplenishRate(config.replenishRate())
                    .setBurstCapacity(config.burstCapacity())
                    .setRequestedTokens(config.requestedTokens()));
        }
    }

    public Mono<RateLimitDecision> consume(RateLimitPolicy policy, String key) {
        // Key Redis của RedisRateLimiter chỉ dựa trên id ("request_rate_limiter.{id}"), không chứa tên policy:
        // thêm tiền tố để bucket "ip" và "auth-ip" của cùng một IP không dùng chung token.
        return redisRateLimiter.isAllowed(policy.id(), policy.id() + ":" + key)
                .map(response -> new RateLimitDecision(response.isAllowed(),
                        parseRemaining(response.getHeaders().get(REMAINING_HEADER))))
                .onErrorResume(e -> {
                    log.warn("Rate limiter unavailable, allowing request (fail-open): {}", e.toString());
                    return Mono.just(new RateLimitDecision(true, -1));
                });
    }

    private static long parseRemaining(String value) {
        try {
            return value == null ? -1 : Long.parseLong(value);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
