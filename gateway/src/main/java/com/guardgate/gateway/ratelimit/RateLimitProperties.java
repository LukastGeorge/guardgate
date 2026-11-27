package com.guardgate.gateway.ratelimit;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Cấu hình token bucket (D8). Mỗi request tốn {@code requestedTokens} token; bucket nạp lại
 * {@code replenishRate} token/giây, chứa tối đa {@code burstCapacity} token.
 * Ví dụ auth-ip 1/60/6: tối đa 10 request liên tiếp, sau đó 1 request mỗi 6 giây (≈10 request/phút).
 */
@Validated
@ConfigurationProperties(prefix = "guardgate.gateway.rate-limits")
public record RateLimitProperties(@NotNull @Valid Policy authIp, @NotNull @Valid Policy ip,
                                  @NotNull @Valid Policy user) {

    public record Policy(@Min(1) int replenishRate, @Min(1) int burstCapacity, @Min(1) int requestedTokens) {

        /** Số giây cần chờ để bucket có lại đủ token cho MỘT request (giá trị header Retry-After). */
        public long retryAfterSeconds() {
            return Math.max(1, (requestedTokens + replenishRate - 1) / replenishRate);
        }
    }

    public Policy get(RateLimitPolicy policy) {
        return switch (policy) {
            case AUTH_IP -> authIp;
            case IP -> ip;
            case USER -> user;
        };
    }
}
