package com.guardgate.auth.audit;

import com.guardgate.auth.web.ClientInfo;
import java.time.Clock;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Ghi audit log vào DB và log riêng "AUDIT".
 *
 * <p>REQUIRES_NEW: bản ghi audit được commit trong transaction riêng, nên vẫn còn lại kể cả khi
 * transaction nghiệp vụ bị rollback (vd. đăng nhập thất bại ném exception).
 */
@Service
public class AuditService {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    private final AuditLogRepository repository;
    private final Clock clock;

    public AuditService(AuditLogRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType type, UUID userId, String email, ClientInfo client,
                       boolean success, String details) {
        String safeEmail = sanitize(email, 254);
        String safeIp = sanitize(client.ipAddress(), 45);
        String safeUserAgent = sanitize(client.userAgent(), 512);
        String safeDetails = sanitize(details, 1000);

        repository.save(new AuditLog(type, userId, safeEmail, safeIp, safeUserAgent, success, safeDetails,
                clock.instant()));
        auditLog.info("event={} success={} userId={} ip={} details={}", type, success, userId, safeIp, safeDetails);
    }

    /**
     * Chống log injection (OWASP A09): User-Agent/email do client gửi lên có thể chứa "\n" để giả mạo
     * một dòng log khác. Thay ký tự điều khiển bằng "_" và cắt theo độ dài cột.
     */
    static String sanitize(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String cleaned = value.replaceAll("\\p{Cntrl}", "_");
        return cleaned.length() > maxLength ? cleaned.substring(0, maxLength) : cleaned;
    }
}
