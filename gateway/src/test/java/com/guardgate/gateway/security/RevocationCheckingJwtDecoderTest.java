package com.guardgate.gateway.security;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

class RevocationCheckingJwtDecoderTest {

    private final ReactiveAccessTokenDenylist denylist = mock(ReactiveAccessTokenDenylist.class);

    @Test
    void validTokenPassesThrough() {
        Jwt jwt = jwt("j1");
        when(denylist.isRevoked("j1")).thenReturn(Mono.just(false));

        StepVerifier.create(decoderReturning(jwt).decode("token"))
                .expectNext(jwt)
                .verifyComplete();
    }

    @Test
    void revokedTokenFailsWithBadJwtException() {
        when(denylist.isRevoked("j1")).thenReturn(Mono.just(true));

        StepVerifier.create(decoderReturning(jwt("j1")).decode("token"))
                .expectError(BadJwtException.class)
                .verify();
    }

    @Test
    void missingJtiFails() {
        Jwt withoutJti = Jwt.withTokenValue("token").header("alg", "RS256").subject("u1").build();

        StepVerifier.create(decoderReturning(withoutJti).decode("token"))
                .expectError(BadJwtException.class)
                .verify();
    }

    @Test
    void redisErrorFailsClosed() {
        when(denylist.isRevoked("j1")).thenReturn(Mono.error(new RedisConnectionFailureException("down")));

        StepVerifier.create(decoderReturning(jwt("j1")).decode("token"))
                .expectError(BadJwtException.class)
                .verify();
    }

    private RevocationCheckingJwtDecoder decoderReturning(Jwt jwt) {
        ReactiveJwtDecoder delegate = token -> Mono.just(jwt);
        return new RevocationCheckingJwtDecoder(delegate, denylist);
    }

    private static Jwt jwt(String jti) {
        return Jwt.withTokenValue("token").header("alg", "RS256").subject("u1").jti(jti).build();
    }
}
