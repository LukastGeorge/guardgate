package com.guardgate.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.config.JwtProperties;
import com.guardgate.auth.user.Role;
import com.guardgate.auth.user.User;
import com.guardgate.auth.web.ClientInfo;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final String OLD_TOKEN = "old-refresh-token";

    @Mock
    private RefreshTokenRepository repository;
    @Mock
    private AuditService audit;

    private final Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final Instant now = clock.instant();
    private final ClientInfo client = new ClientInfo("203.0.113.10", "junit");
    private final UUID familyId = UUID.randomUUID();
    private RefreshTokenService service;
    private User user;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties("issuer", "audience", "unused", Duration.ofMinutes(15),
                Duration.ofDays(7));
        service = new RefreshTokenService(repository, audit, properties, clock);
        user = User.local("alice@example.com", "{bcrypt}hash", Role.USER);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
    }

    @Test
    void rotateIssuesNewTokenInSameFamilyAndMarksOldOneRotated() {
        RefreshToken current = token(now.plus(Duration.ofDays(1)));
        UUID nextId = UUID.randomUUID();
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash(OLD_TOKEN))).thenReturn(Optional.of(current));
        when(repository.save(any(RefreshToken.class))).thenAnswer(invocation -> {
            RefreshToken saved = invocation.getArgument(0);
            ReflectionTestUtils.setField(saved, "id", nextId);
            return saved;
        });

        RefreshTokenService.Rotation rotation = service.rotate(OLD_TOKEN, client);

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(repository).save(captor.capture());
        RefreshToken next = captor.getValue();
        assertThat(rotation.refreshToken()).isNotEqualTo(OLD_TOKEN).hasSize(43);
        assertThat(next.getFamilyId()).isEqualTo(familyId);
        assertThat(next.getTokenHash()).isEqualTo(RefreshTokenService.hash(rotation.refreshToken()));
        assertThat(current.wasRotated()).isTrue();
        assertThat(current.getReplacedBy()).isEqualTo(nextId);
    }

    @Test
    void reusingRotatedTokenRevokesWholeFamily() {
        RefreshToken current = token(now.plus(Duration.ofDays(1)));
        current.markRotated(UUID.randomUUID(), now.minusSeconds(30));
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash(OLD_TOKEN))).thenReturn(Optional.of(current));

        assertThatThrownBy(() -> service.rotate(OLD_TOKEN, client)).isInstanceOf(InvalidRefreshTokenException.class);

        verify(repository).revokeFamily(familyId, now);
        verify(audit).record(eq(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED), eq(user.getId()), anyString(),
                eq(client), eq(false), anyString());
        verify(repository, never()).save(any());
    }

    @Test
    void expiredTokenIsRejectedWithoutRotation() {
        RefreshToken current = token(now.minusSeconds(1));
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash(OLD_TOKEN))).thenReturn(Optional.of(current));

        assertThatThrownBy(() -> service.rotate(OLD_TOKEN, client)).isInstanceOf(InvalidRefreshTokenException.class);

        verify(repository, never()).save(any());
        verify(repository, never()).revokeFamily(any(), any());
    }

    @Test
    void tokenOfLockedUserIsRejected() {
        ReflectionTestUtils.setField(user, "lockedUntil", now.plusSeconds(600));
        RefreshToken current = token(now.plus(Duration.ofDays(1)));
        when(repository.findByTokenHashForUpdate(RefreshTokenService.hash(OLD_TOKEN))).thenReturn(Optional.of(current));

        assertThatThrownBy(() -> service.rotate(OLD_TOKEN, client)).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void unknownTokenIsRejected() {
        when(repository.findByTokenHashForUpdate(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.rotate("does-not-exist", client))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void hashIsDeterministicSha256Hex() {
        assertThat(RefreshTokenService.hash("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    private RefreshToken token(Instant expiresAt) {
        return new RefreshToken(user, RefreshTokenService.hash(OLD_TOKEN), familyId, now.minusSeconds(60), expiresAt);
    }
}
