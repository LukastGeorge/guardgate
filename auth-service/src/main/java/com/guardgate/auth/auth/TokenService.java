package com.guardgate.auth.auth;

import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.config.JwtConfig;
import com.guardgate.auth.config.JwtProperties;
import com.guardgate.auth.user.User;
import com.nimbusds.jose.jwk.RSAKey;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/**
 * Phát hành cặp token. Access token chứa tối thiểu thông tin: sub (user id), roles, jti.
 * Không đưa email hay dữ liệu cá nhân vào JWT vì payload chỉ được mã hoá Base64, ai cũng đọc được.
 */
@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties properties;
    private final RefreshTokenService refreshTokenService;
    private final String keyId;
    private final Clock clock;

    public TokenService(JwtEncoder jwtEncoder, JwtProperties properties, RefreshTokenService refreshTokenService,
                        RSAKey jwtSigningKey, Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
        this.refreshTokenService = refreshTokenService;
        this.keyId = jwtSigningKey.getKeyID();
        this.clock = clock;
    }

    /** Đăng nhập mới => family refresh token mới. */
    public TokenResponse issueFor(User user) {
        String refreshToken = refreshTokenService.issue(user, UUID.randomUUID());
        return withRefreshToken(user, refreshToken);
    }

    public TokenResponse withRefreshToken(User user, String refreshToken) {
        return TokenResponse.bearer(createAccessToken(user), refreshToken, properties.accessTokenTtl().toSeconds());
    }

    String createAccessToken(User user) {
        Instant now = clock.instant();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .audience(List.of(properties.audience()))
                .subject(user.getId().toString())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(now.plus(properties.accessTokenTtl()))
                .id(UUID.randomUUID().toString())
                .claim(JwtConfig.ROLES_CLAIM, List.of(user.getRole().name()))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(keyId).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
