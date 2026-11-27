package com.guardgate.gateway.ratelimit;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.data.redis.RedisConnectionFailureException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class RateLimiterServiceTest {

    private final RedisRateLimiter redisRateLimiter = mock(RedisRateLimiter.class);
    private RateLimiterService service;

    @BeforeEach
    void setUp() {
        when(redisRateLimiter.getConfig()).thenReturn(new HashMap<>());
        RateLimitProperties properties = new RateLimitProperties(
                new RateLimitProperties.Policy(1, 60, 6),
                new RateLimitProperties.Policy(20, 40, 1),
                new RateLimitProperties.Policy(10, 20, 1));
        service = new RateLimiterService(redisRateLimiter, properties);
    }

    @Test
    void redisFailureFailsOpen() {
        // Review Focus #2 / D7: Redis chết thì vẫn phục vụ (lockout ở auth-service vẫn chặn brute-force)
        when(redisRateLimiter.isAllowed(anyString(), anyString()))
                .thenReturn(Mono.error(new RedisConnectionFailureException("down")));

        StepVerifier.create(service.consume(RateLimitPolicy.IP, "1.2.3.4"))
                .expectNext(new RateLimitDecision(true, -1))
                .verifyComplete();
    }

    @Test
    void mapsAllowedAndRemainingFromLimiterResponse() {
        when(redisRateLimiter.isAllowed(anyString(), anyString()))
                .thenReturn(Mono.just(new RateLimiter.Response(false, Map.of("X-RateLimit-Remaining", "0"))));

        StepVerifier.create(service.consume(RateLimitPolicy.AUTH_IP, "1.2.3.4"))
                .expectNext(new RateLimitDecision(false, 0))
                .verifyComplete();
    }

    @Test
    void bucketKeyIsNamespacedByPolicySoPoliciesDoNotShareTokens() {
        // RedisRateLimiter đặt key "request_rate_limiter.{id}" KHÔNG kèm tên policy → phải tự thêm tiền tố
        when(redisRateLimiter.isAllowed(anyString(), anyString()))
                .thenReturn(Mono.just(new RateLimiter.Response(true, Map.of("X-RateLimit-Remaining", "5"))));

        service.consume(RateLimitPolicy.AUTH_IP, "1.2.3.4").block();

        verify(redisRateLimiter).isAllowed(eq("auth-ip"), eq("auth-ip:1.2.3.4"));
    }
}
