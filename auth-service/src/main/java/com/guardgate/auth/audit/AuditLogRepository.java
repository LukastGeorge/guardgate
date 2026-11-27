package com.guardgate.auth.audit;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByEventType(AuditEventType eventType, Pageable pageable);

    List<AuditLog> findByUserIdAndEventType(UUID userId, AuditEventType eventType);
}
