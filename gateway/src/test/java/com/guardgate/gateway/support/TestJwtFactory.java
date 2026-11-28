package com.guardgate.gateway.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Đóng vai auth-service trong test: giữ một khoá RSA, công bố JWKS (để WireMock trả về) và ký token
 * với các claim giống hệt token thật. Customizer cho phép tạo token sai cố ý (hết hạn, sai aud...).
 */
public final class TestJwtFactory {

    public static final String ISSUER = "guardgate-auth";
    public static final String AUDIENCE = "guardgate";

    private final RSAKey key;

    public TestJwtFactory() {
        try {
            this.key = new RSAKeyGenerator(2048).keyID("test-" + UUID.randomUUID()).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String jwksJson() {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    public String token(String subject, List<String> roles) {
        return token(claims -> claims.subject(subject).claim("roles", roles));
    }

    /** Token RS256 hợp lệ mặc định; customizer chạy SAU khi đặt claim mặc định nên có thể ghi đè. */
    public String token(Consumer<JWTClaimsSet.Builder> customizer) {
        JWTClaimsSet.Builder claims = defaultClaims();
        customizer.accept(claims);
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                    claims.build());
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Tấn công key confusion: ký HS256 dùng public key (ai cũng biết) làm secret. */
    public String hs256TokenSignedWithPublicKey() {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(key.getKeyID()).build(),
                    defaultClaims().claim("roles", List.of("ADMIN")).build());
            jwt.sign(new MACSigner(key.toRSAPublicKey().getEncoded()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWTClaimsSet.Builder defaultClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(15))))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", List.of("USER"));
    }
}
