package com.guardgate.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tài khoản ADMIN đầu tiên, tạo lúc khởi động nếu chưa tồn tại. Để trống => bỏ qua.
 */
@ConfigurationProperties(prefix = "guardgate.bootstrap-admin")
public record BootstrapAdminProperties(String email, String password) {

    public boolean isConfigured() {
        return email != null && !email.isBlank() && password != null && !password.isBlank();
    }

    @Override
    public String toString() {
        return "BootstrapAdminProperties[email=%s, password=***]".formatted(email);
    }
}
