package com.guardgate.auth.user;

import com.guardgate.auth.config.BootstrapAdminProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Tạo tài khoản ADMIN đầu tiên từ biến môi trường BOOTSTRAP_ADMIN_EMAIL/PASSWORD.
 * Không có tài khoản admin mặc định nào được hardcode trong code hay migration.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final BootstrapAdminProperties properties;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;

    public AdminBootstrap(BootstrapAdminProperties properties, UserRepository users, PasswordEncoder passwordEncoder) {
        this.properties = properties;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.isConfigured()) {
            return;
        }
        String email = EmailNormalizer.normalize(properties.email());
        if (users.existsByEmail(email)) {
            log.info("Bootstrap admin already exists, skipping");
            return;
        }
        int length = properties.password().length();
        if (length < PasswordPolicy.MIN_LENGTH || length > PasswordPolicy.MAX_LENGTH) {
            throw new IllegalStateException("BOOTSTRAP_ADMIN_PASSWORD must be %d-%d characters"
                    .formatted(PasswordPolicy.MIN_LENGTH, PasswordPolicy.MAX_LENGTH));
        }
        users.save(User.local(email, passwordEncoder.encode(properties.password()), Role.ADMIN));
        log.info("Bootstrap admin account created");
    }
}
