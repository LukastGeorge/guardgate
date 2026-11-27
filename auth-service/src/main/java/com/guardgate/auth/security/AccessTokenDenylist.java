package com.guardgate.auth.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Danh sách access token đã bị thu hồi (logout) trước khi hết hạn.
 *
 * <p>JWT là stateless nên không "xoá" được; thay vào đó lưu {@code jti} vào Redis với TTL đúng bằng
 * thời gian sống còn lại của token. Khi token tự hết hạn, key cũng tự biến mất => Redis không phình.
 * Gateway (giai đoạn 3) kiểm tra cùng key prefix này.
 */
@Component
public class AccessTokenDenylist {

    public static final String KEY_PREFIX = "guardgate:revoked-jti:";

    private final StringRedisTemplate redis;
    private final Clock clock;

    public AccessTokenDenylist(StringRedisTemplate redis, Clock clock) {
        this.redis = redis;
        this.clock = clock;
    }

    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || expiresAt == null) {
            return;
        }
        Duration ttl = Duration.between(clock.instant(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return; // đã hết hạn, không cần lưu
        }
        redis.opsForValue().set(KEY_PREFIX + jti, "1", ttl);
    }

    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(KEY_PREFIX + jti));
    }
}
