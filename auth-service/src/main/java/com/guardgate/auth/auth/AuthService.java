package com.guardgate.auth.auth;

import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.auth.dto.LoginRequest;
import com.guardgate.auth.auth.dto.RegisterRequest;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.security.AccessTokenDenylist;
import com.guardgate.auth.user.EmailNormalizer;
import com.guardgate.auth.user.Role;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import com.guardgate.auth.user.UserResponse;
import com.guardgate.auth.web.ClientInfo;
import com.guardgate.auth.web.ResourceNotFoundException;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttempts;
    private final TokenService tokenService;
    private final RefreshTokenService refreshTokenService;
    private final AccessTokenDenylist denylist;
    private final AuditService audit;
    private final Clock clock;
    /** Hash giả để so sánh khi email không tồn tại => thời gian phản hồi giống hệt (chống timing attack). */
    private final String dummyPasswordHash;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder, LoginAttemptService loginAttempts,
                       TokenService tokenService, RefreshTokenService refreshTokenService,
                       AccessTokenDenylist denylist, AuditService audit, Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.loginAttempts = loginAttempts;
        this.tokenService = tokenService;
        this.refreshTokenService = refreshTokenService;
        this.denylist = denylist;
        this.audit = audit;
        this.clock = clock;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public UserResponse register(RegisterRequest request, ClientInfo client) {
        String email = EmailNormalizer.normalize(request.email());
        if (request.password().equalsIgnoreCase(email)) {
            throw new InvalidPasswordException("Password must not be the same as the email");
        }
        if (users.existsByEmail(email)) {
            throw new EmailAlreadyRegisteredException();
        }
        User user = users.saveAndFlush(User.local(email, passwordEncoder.encode(request.password()), Role.USER));
        audit.record(AuditEventType.USER_REGISTERED, user.getId(), email, client, true, null);
        return UserResponse.from(user);
    }

    public TokenResponse login(LoginRequest request, ClientInfo client) {
        String email = EmailNormalizer.normalize(request.email());
        User user = users.findByEmail(email).orElse(null);

        if (user == null) {
            passwordEncoder.matches(request.password(), dummyPasswordHash);
            audit.record(AuditEventType.LOGIN_FAILURE, null, email, client, false, "unknown account");
            throw new InvalidCredentialsException();
        }

        Instant now = clock.instant();
        String hashToCheck = user.hasPassword() ? user.getPasswordHash() : dummyPasswordHash;
        boolean passwordMatches = passwordEncoder.matches(request.password(), hashToCheck) && user.hasPassword();

        if (user.isLockedAt(now)) {
            // Đang bị khoá: từ chối kể cả khi mật khẩu đúng, và không tăng bộ đếm
            audit.record(AuditEventType.LOGIN_FAILURE, user.getId(), email, client, false, "account locked");
            throw new InvalidCredentialsException();
        }
        if (!user.isEnabled() || !passwordMatches) {
            boolean lockedNow = loginAttempts.recordFailure(user.getId());
            audit.record(AuditEventType.LOGIN_FAILURE, user.getId(), email, client, false,
                    user.isEnabled() ? "bad credentials" : "account disabled");
            if (lockedNow) {
                audit.record(AuditEventType.ACCOUNT_LOCKED, user.getId(), email, client, false,
                        "too many failed attempts");
            }
            throw new InvalidCredentialsException();
        }

        if (user.getFailedLoginAttempts() > 0 || user.getLockedUntil() != null) {
            loginAttempts.reset(user.getId());
        }
        upgradePasswordHashIfNeeded(user, request.password());

        TokenResponse tokens = tokenService.issueFor(user);
        audit.record(AuditEventType.LOGIN_SUCCESS, user.getId(), email, client, true, null);
        return tokens;
    }

    public TokenResponse refresh(String refreshToken, ClientInfo client) {
        RefreshTokenService.Rotation rotation = refreshTokenService.rotate(refreshToken, client);
        User user = rotation.user();
        audit.record(AuditEventType.TOKEN_REFRESHED, user.getId(), user.getEmail(), client, true, null);
        return tokenService.withRefreshToken(user, rotation.refreshToken());
    }

    public void logout(Jwt accessToken, String refreshToken, ClientInfo client) {
        UUID userId = UUID.fromString(accessToken.getSubject());
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokenService.revokeFamily(refreshToken, userId);
        }
        denylist.revoke(accessToken.getId(), accessToken.getExpiresAt());
        audit.record(AuditEventType.LOGOUT, userId, null, client, true, null);
    }

    @Transactional
    public void unlockAccount(UUID userId, UUID adminId, ClientInfo client) {
        User user = users.findById(userId).orElseThrow(() -> new ResourceNotFoundException("User not found"));
        users.resetLoginFailures(user.getId());
        audit.record(AuditEventType.ACCOUNT_UNLOCKED, user.getId(), user.getEmail(), client, true,
                "unlocked by admin=" + adminId);
    }

    /** Nếu cost factor BCrypt được tăng lên, hash cũ được tính lại khi user đăng nhập đúng. */
    private void upgradePasswordHashIfNeeded(User user, String rawPassword) {
        if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
            users.findById(user.getId()).ifPresent(fresh -> {
                fresh.changePasswordHash(passwordEncoder.encode(rawPassword));
                users.save(fresh);
            });
        }
    }
}
