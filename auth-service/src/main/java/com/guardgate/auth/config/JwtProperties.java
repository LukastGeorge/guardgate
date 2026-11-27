package com.guardgate.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Cấu hình JWT. {@code @Validated} khiến app KHÔNG khởi động nếu thiếu khoá ký (fail fast).
 */
@Validated
@ConfigurationProperties(prefix = "guardgate.jwt")
public record JwtProperties(
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotBlank(message = "JWT_PRIVATE_KEY must be set (see .env.example)") String privateKey,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration refreshTokenTtl) {

    @Override
    public String toString() {
        // Không bao giờ in khoá bí mật ra log
        return "JwtProperties[issuer=%s, audience=%s, accessTokenTtl=%s, refreshTokenTtl=%s]"
                .formatted(issuer, audience, accessTokenTtl, refreshTokenTtl);
    }
}
