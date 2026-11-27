package com.guardgate.auth.auth;

import com.guardgate.auth.config.AuthSecurityProperties;
import com.guardgate.auth.user.UserRepository;
import java.time.Clock;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Đếm số lần đăng nhập sai và khoá tạm thời (chống brute-force / credential stuffing).
 * REQUIRES_NEW: bộ đếm phải được commit NGAY dù sau đó login ném exception và rollback.
 */
@Service
public class LoginAttemptService {

    private final UserRepository users;
    private final AuthSecurityProperties properties;
    private final Clock clock;

    public LoginAttemptService(UserRepository users, AuthSecurityProperties properties, Clock clock) {
        this.users = users;
        this.properties = properties;
        this.clock = clock;
    }

    /** @return true nếu lần sai này khiến tài khoản bị khoá */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean recordFailure(UUID userId) {
        users.incrementFailedAttempts(userId);
        return users.lockIfThresholdReached(userId, properties.maxFailedAttempts(),
                clock.instant().plus(properties.lockDuration())) == 1;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void reset(UUID userId) {
        users.resetLoginFailures(userId);
    }
}
