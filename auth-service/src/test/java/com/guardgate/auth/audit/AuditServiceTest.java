package com.guardgate.auth.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuditServiceTest {

    @Test
    void sanitizeNeutralisesLogInjection() {
        String forged = "Mozilla/5.0\r\nevent=LOGIN_SUCCESS success=true userId=admin";

        String sanitized = AuditService.sanitize(forged, 512);

        assertThat(sanitized).doesNotContain("\r", "\n").startsWith("Mozilla/5.0__event=");
    }

    @Test
    void sanitizeTruncatesToColumnLength() {
        assertThat(AuditService.sanitize("a".repeat(600), 512)).hasSize(512);
    }

    @Test
    void sanitizeKeepsNull() {
        assertThat(AuditService.sanitize(null, 10)).isNull();
    }
}
