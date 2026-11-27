package com.guardgate.gateway.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

/**
 * Bọc decoder chuẩn (chữ ký, iss, aud, exp) và kiểm tra thêm denylist trong Redis.
 *
 * <p>Vì sao không dùng OAuth2TokenValidator như ở auth-service? Validator là API đồng bộ (blocking);
 * trong gateway reactive, gọi Redis blocking sẽ chiếm event-loop thread. Bọc decoder cho phép
 * nối thêm một bước Mono non-blocking.
 *
 * <p>Fail-closed (quyết định D6): Redis lỗi → coi như token không hợp lệ → 401.
 */
public class RevocationCheckingJwtDecoder implements ReactiveJwtDecoder {

    private static final Logger log = LoggerFactory.getLogger(RevocationCheckingJwtDecoder.class);

    private final ReactiveJwtDecoder delegate;
    private final ReactiveAccessTokenDenylist denylist;

    public RevocationCheckingJwtDecoder(ReactiveJwtDecoder delegate, ReactiveAccessTokenDenylist denylist) {
        this.delegate = delegate;
        this.denylist = denylist;
    }

    @Override
    public Mono<Jwt> decode(String token) {
        return delegate.decode(token)
                // Lỗi hạ tầng (vd. không tải được JWKS) → JwtException thường (không phải BadJwtException):
                // Spring Security biến nó thành AuthenticationServiceException → GatewayErrorHandler trả 503
                // thay vì để IllegalStateException trần lọt ra thành 500.
                .onErrorMap(e -> !(e instanceof JwtException),
                        e -> new JwtException("Unable to verify token: signing keys unavailable", e))
                .flatMap(this::ensureNotRevoked);
    }

    private Mono<Jwt> ensureNotRevoked(Jwt jwt) {
        String jti = jwt.getId();
        if (jti == null || jti.isBlank()) {
            return Mono.error(new BadJwtException("Token has no jti"));
        }
        return denylist.isRevoked(jti)
                .onErrorMap(e -> {
                    log.error("Token revocation check failed, rejecting token (fail-closed)", e);
                    return new BadJwtException("Token revocation status unavailable", e);
                })
                .flatMap(revoked -> Boolean.TRUE.equals(revoked)
                        ? Mono.<Jwt>error(new BadJwtException("Token has been revoked"))
                        : Mono.just(jwt));
    }
}
