package com.guardgate.auth.auth;

import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditService;
import com.guardgate.auth.config.JwtProperties;
import com.guardgate.auth.user.User;
import com.guardgate.auth.web.ClientInfo;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Refresh token dạng chuỗi ngẫu nhiên 256-bit (opaque), KHÔNG phải JWT: server toàn quyền thu hồi.
 *
 * <p><b>Rotation:</b> mỗi lần refresh, token cũ bị vô hiệu và cấp token mới cùng "family".
 * <b>Reuse detection:</b> nếu một token đã rotate bị dùng lại, nghĩa là có 2 bên đang giữ nó
 * (user thật + kẻ trộm). Không biết ai là ai nên thu hồi CẢ family, buộc đăng nhập lại.
 */
@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository repository;
    private final AuditService auditService;
    private final JwtProperties jwtProperties;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository repository, AuditService auditService,
                               JwtProperties jwtProperties, Clock clock) {
        this.repository = repository;
        this.auditService = auditService;
        this.jwtProperties = jwtProperties;
        this.clock = clock;
    }

    public record Rotation(User user, String refreshToken) {
    }

    /** Cấp refresh token mới; familyId mới cho mỗi lần đăng nhập. */
    @Transactional
    public String issue(User user, UUID familyId) {
        String raw = generateToken();
        Instant now = clock.instant();
        repository.save(new RefreshToken(user, hash(raw), familyId, now, now.plus(jwtProperties.refreshTokenTtl())));
        return raw;
    }

    /** noRollbackFor: việc thu hồi family khi phát hiện reuse phải được commit dù ta ném exception. */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public Rotation rotate(String rawToken, ClientInfo client) {
        Instant now = clock.instant();
        RefreshToken current = repository.findByTokenHashForUpdate(hash(rawToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        User user = current.getUser();

        if (current.wasRotated()) {
            int revoked = repository.revokeFamily(current.getFamilyId(), now);
            log.warn("Refresh token reuse detected userId={} family={} revoked={}",
                    user.getId(), current.getFamilyId(), revoked);
            auditService.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED, user.getId(), user.getEmail(), client,
                    false, "family=" + current.getFamilyId());
            throw new InvalidRefreshTokenException();
        }
        if (current.isRevoked() || current.isExpiredAt(now) || !user.isEnabled() || user.isLockedAt(now)) {
            throw new InvalidRefreshTokenException();
        }

        String nextRaw = generateToken();
        RefreshToken next = repository.save(new RefreshToken(user, hash(nextRaw), current.getFamilyId(), now,
                now.plus(jwtProperties.refreshTokenTtl())));
        current.markRotated(next.getId(), now);
        return new Rotation(user, nextRaw);
    }

    /** Thu hồi family của token, chỉ khi token thuộc về đúng user đang logout. */
    @Transactional
    public void revokeFamily(String rawToken, UUID ownerId) {
        repository.findByTokenHash(hash(rawToken))
                .filter(token -> token.getUser().getId().equals(ownerId))
                .ifPresent(token -> repository.revokeFamily(token.getFamilyId(), clock.instant()));
    }

    /** Dọn token hết hạn mỗi đêm để bảng không phình to. */
    @Scheduled(cron = "${guardgate.jwt.refresh-token-cleanup-cron:0 0 3 * * *}")
    @Transactional
    public void purgeExpired() {
        int deleted = repository.deleteExpiredBefore(clock.instant().minus(Duration.ofDays(1)));
        log.info("Purged {} expired refresh tokens", deleted);
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * SHA-256 (không phải BCrypt) là đủ: token có 256 bit ngẫu nhiên nên không thể brute-force,
     * và hash tất định cho phép tra cứu theo index. Lộ DB cũng không dùng được token.
     */
    static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
