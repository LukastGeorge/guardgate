package com.guardgate.auth.audit;

import java.time.Instant;
import java.util.UUID;

public record AuditLogResponse(Long id, AuditEventType eventType, UUID userId, String email, String ipAddress,
                               String userAgent, boolean success, String details, Instant createdAt) {

    public static AuditLogResponse from(AuditLog log) {
        return new AuditLogResponse(log.getId(), log.getEventType(), log.getUserId(), log.getEmail(),
                log.getIpAddress(), log.getUserAgent(), log.isSuccess(), log.getDetails(), log.getCreatedAt());
    }
}
