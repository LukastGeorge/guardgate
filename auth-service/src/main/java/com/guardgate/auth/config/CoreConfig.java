package com.guardgate.auth.config;

import java.time.Clock;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class CoreConfig {

    /** Inject Clock thay vì gọi Instant.now() trực tiếp => test điều khiển được thời gian. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * DelegatingPasswordEncoder lưu hash dạng "{bcrypt}$2a$12$...". Tiền tố cho phép đổi thuật toán
     * sau này (vd. sang Argon2) mà hash cũ vẫn kiểm tra được và được nâng cấp dần khi user đăng nhập.
     */
    @Bean
    public PasswordEncoder passwordEncoder(AuthSecurityProperties properties) {
        String defaultId = "bcrypt";
        return new DelegatingPasswordEncoder(defaultId,
                Map.of(defaultId, new BCryptPasswordEncoder(properties.bcryptStrength())));
    }
}
