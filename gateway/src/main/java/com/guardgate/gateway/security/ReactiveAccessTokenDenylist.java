package com.guardgate.gateway.security;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Đọc danh sách access token đã logout. auth-service GHI key này (AccessTokenDenylist) khi user logout;
 * gateway chỉ ĐỌC. Hai bên phải dùng cùng KEY_PREFIX.
 */
@Component
public class ReactiveAccessTokenDenylist {

    public static final String KEY_PREFIX = "guardgate:revoked-jti:";

    private final ReactiveStringRedisTemplate redis;

    public ReactiveAccessTokenDenylist(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    public Mono<Boolean> isRevoked(String jti) {
        return redis.hasKey(KEY_PREFIX + jti);
    }
}
