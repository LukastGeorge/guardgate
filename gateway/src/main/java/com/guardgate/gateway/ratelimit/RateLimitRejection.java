package com.guardgate.gateway.ratelimit;

import com.guardgate.gateway.web.ProblemResponses;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Phản hồi 429 dùng chung cho cả rate limit theo IP và theo user. */
@Component
public class RateLimitRejection {

    private final RateLimitProperties properties;
    private final BlockedRequestMetrics metrics;

    public RateLimitRejection(RateLimitProperties properties, BlockedRequestMetrics metrics) {
        this.properties = properties;
        this.metrics = metrics;
    }

    public Mono<Void> reject(ServerWebExchange exchange, RateLimitPolicy policy) {
        metrics.increment(policy.metricReason());
        HttpHeaders headers = exchange.getResponse().getHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(properties.get(policy).retryAfterSeconds()));
        headers.set("X-RateLimit-Remaining", "0");
        return ProblemResponses.write(exchange, HttpStatus.TOO_MANY_REQUESTS, "Too many requests");
    }
}
