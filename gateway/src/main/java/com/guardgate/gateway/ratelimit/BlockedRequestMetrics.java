package com.guardgate.gateway.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Prometheus: guardgate_gateway_blocked_requests_total{reason="..."}; dashboard ở giai đoạn 6 dùng metric này.
 */
@Component
public class BlockedRequestMetrics {

    public static final String METRIC = "guardgate.gateway.blocked.requests";

    private final MeterRegistry registry;

    public BlockedRequestMetrics(MeterRegistry registry) {
        this.registry = registry;
    }

    public void increment(String reason) {
        Counter.builder(METRIC)
                .description("Requests rejected by the gateway before reaching a service")
                .tag("reason", reason)
                .register(registry)
                .increment();
    }
}
