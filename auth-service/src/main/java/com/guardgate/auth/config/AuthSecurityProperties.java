package com.guardgate.auth.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * @param maxFailedAttempts số lần đăng nhập sai liên tiếp trước khi khoá tài khoản
 * @param lockDuration      thời gian khoá tạm thời
 * @param bcryptStrength    cost factor của BCrypt (mỗi +1 là chậm gấp đôi); test dùng 4 cho nhanh
 */
@Validated
@ConfigurationProperties(prefix = "guardgate.security")
public record AuthSecurityProperties(
        @Min(1) int maxFailedAttempts,
        @NotNull Duration lockDuration,
        @Min(4) @Max(31) int bcryptStrength) {
}
