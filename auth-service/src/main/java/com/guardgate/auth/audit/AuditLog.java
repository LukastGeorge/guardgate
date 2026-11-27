package com.guardgate.auth.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** Bản ghi audit: chỉ thêm mới, không có setter => không sửa được qua code ứng dụng. */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 64)
    private AuditEventType eventType;

    @Column(name = "user_id")
    private UUID userId;

    @Column(length = 254)
    private String email;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(nullable = false)
    private boolean success;

    @Column(length = 1000)
    private String details;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected AuditLog() {
        // JPA
    }

    public AuditLog(AuditEventType eventType, UUID userId, String email, String ipAddress, String userAgent,
                    boolean success, String details, Instant createdAt) {
        this.eventType = eventType;
        this.userId = userId;
        this.email = email;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.success = success;
        this.details = details;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public AuditEventType getEventType() {
        return eventType;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getDetails() {
        return details;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
