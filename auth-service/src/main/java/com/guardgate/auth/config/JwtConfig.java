package com.guardgate.auth.config;

import com.guardgate.auth.security.AccessTokenDenylist;
import com.guardgate.auth.security.NotRevokedValidator;
import com.guardgate.auth.security.RsaKeyLoader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * Ký JWT bằng RS256 (bất đối xứng): auth-service giữ private key, các service khác (gateway)
 * chỉ cần public key lấy từ /.well-known/jwks.json để xác thực => private key không rời auth-service.
 */
@Configuration
public class JwtConfig {

    public static final String ROLES_CLAIM = "roles";

    @Bean
    public RSAKey jwtSigningKey(JwtProperties properties) {
        return RsaKeyLoader.load(properties.privateKey());
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey jwtSigningKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwtSigningKey)));
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey jwtSigningKey, JwtProperties properties, AccessTokenDenylist denylist)
            throws JOSEException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtSigningKey.toRSAPublicKey())
                // Chỉ chấp nhận RS256: chặn tấn công đổi "alg" sang "none" hoặc HS256
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();

        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(properties.audience()));

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()), // exp, nbf, iss
                audienceValidator,
                new NotRevokedValidator(denylist)));
        return decoder;
    }

    /** Map claim "roles": ["ADMIN"] => authority "ROLE_ADMIN" để dùng hasRole("ADMIN"). */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName(ROLES_CLAIM);
        authorities.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return converter;
    }
}
