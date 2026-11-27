package com.guardgate.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.auth.dto.LoginRequest;
import com.guardgate.auth.auth.dto.RegisterRequest;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.security.AccessTokenDenylist;
import com.guardgate.auth.user.Role;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import com.guardgate.auth.web.ClientInfo;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String EMAIL = "alice@example.com";
    private static final String HASH = "{bcrypt}stored-hash";
    private static final String DUMMY_HASH = "{bcrypt}dummy-hash";

    @Mock
    private UserRepository users;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private LoginAttemptService loginAttempts;
    @Mock
    private TokenService tokenService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private AccessTokenDenylist denylist;
    @Mock
    private AuditService audit;

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final ClientInfo client = new ClientInfo("203.0.113.10", "junit");
    private AuthService service;

    @BeforeEach
    void setUp() {
        when(passwordEncoder.encode(anyString())).thenReturn(DUMMY_HASH);
        service = new AuthService(users, passwordEncoder, loginAttempts, tokenService, refreshTokenService,
                denylist, audit, clock);
    }

    @Test
    void loginWithCorrectPasswordIssuesTokensAndAuditsSuccess() {
        User user = existingUser();
        TokenResponse tokens = TokenResponse.bearer("access", "refresh", 900);
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", HASH)).thenReturn(true);
        when(tokenService.issueFor(user)).thenReturn(tokens);

        TokenResponse result = service.login(new LoginRequest("  Alice@Example.COM ", "correct-password"), client);

        assertThat(result).isSameAs(tokens);
        verify(audit).record(eq(AuditEventType.LOGIN_SUCCESS), eq(user.getId()), eq(EMAIL), eq(client), eq(true),
                isNull());
        verify(loginAttempts, never()).recordFailure(any());
    }

    @Test
    void wrongPasswordRecordsFailureAndAuditsLockWhenThresholdIsReached() {
        User user = existingUser();
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", HASH)).thenReturn(false);
        when(loginAttempts.recordFailure(user.getId())).thenReturn(true);

        assertThatThrownBy(() -> service.login(new LoginRequest(EMAIL, "wrong-password"), client))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(audit).record(eq(AuditEventType.LOGIN_FAILURE), eq(user.getId()), eq(EMAIL), eq(client), eq(false),
                anyString());
        verify(audit).record(eq(AuditEventType.ACCOUNT_LOCKED), eq(user.getId()), eq(EMAIL), eq(client), eq(false),
                anyString());
        verify(tokenService, never()).issueFor(any());
    }

    @Test
    void lockedAccountIsRejectedEvenWithCorrectPassword() {
        User user = existingUser();
        ReflectionTestUtils.setField(user, "lockedUntil", clock.instant().plusSeconds(600));
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", HASH)).thenReturn(true);

        assertThatThrownBy(() -> service.login(new LoginRequest(EMAIL, "correct-password"), client))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(tokenService, never()).issueFor(any());
        verify(loginAttempts, never()).recordFailure(any());
    }

    @Test
    void expiredLockIsClearedOnSuccessfulLogin() {
        User user = existingUser();
        ReflectionTestUtils.setField(user, "lockedUntil", clock.instant().minusSeconds(1));
        when(users.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", HASH)).thenReturn(true);
        when(tokenService.issueFor(user)).thenReturn(TokenResponse.bearer("a", "r", 900));

        service.login(new LoginRequest(EMAIL, "correct-password"), client);

        verify(loginAttempts).reset(user.getId());
    }

    @Test
    void unknownEmailStillPerformsPasswordHashToEqualiseTiming() {
        when(users.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.login(new LoginRequest(EMAIL, "any-password"), client))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid email or password");

        verify(passwordEncoder).matches("any-password", DUMMY_HASH);
    }

    @Test
    void registerRejectsPasswordEqualToEmail() {
        assertThatThrownBy(() -> service.register(new RegisterRequest(EMAIL, EMAIL.toUpperCase()), client))
                .isInstanceOf(InvalidPasswordException.class);
    }

    @Test
    void registerRejectsDuplicateEmailCaseInsensitively() {
        when(users.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> service.register(new RegisterRequest("ALICE@example.com", "long-enough-pass"),
                client)).isInstanceOf(EmailAlreadyRegisteredException.class);
    }

    private static User existingUser() {
        User user = User.local(EMAIL, HASH, Role.USER);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        return user;
    }
}
