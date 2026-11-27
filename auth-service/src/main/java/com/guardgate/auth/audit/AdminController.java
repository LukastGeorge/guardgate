package com.guardgate.auth.audit;

import com.guardgate.auth.auth.AuthService;
import com.guardgate.auth.web.ClientInfo;
import com.guardgate.auth.web.PageResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * API quản trị. Được bảo vệ 2 lớp (defense in depth): rule "/api/admin/**" => ADMIN trong
 * SecurityConfig VÀ @PreAuthorize ở đây, phòng khi ai đó sửa nhầm rule URL.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AuditLogRepository auditLogs;
    private final AuthService authService;

    public AdminController(AuditLogRepository auditLogs, AuthService authService) {
        this.auditLogs = auditLogs;
        this.authService = authService;
    }

    @GetMapping("/audit-logs")
    public PageResponse<AuditLogResponse> auditLogs(
            @RequestParam(required = false) AuditEventType eventType,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<AuditLog> page = eventType == null
                ? auditLogs.findAll(pageable)
                : auditLogs.findByEventType(eventType, pageable);
        return PageResponse.of(page, AuditLogResponse::from);
    }

    @PostMapping("/users/{userId}/unlock")
    public ResponseEntity<Void> unlock(@PathVariable UUID userId, @AuthenticationPrincipal Jwt admin,
                                       HttpServletRequest http) {
        authService.unlockAccount(userId, UUID.fromString(admin.getSubject()), ClientInfo.from(http));
        return ResponseEntity.noContent().build();
    }
}
