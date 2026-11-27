package com.guardgate.demo;

import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Ba mức quyền để minh hoạ RBAC từ đầu đến cuối: public, USER/ADMIN, chỉ ADMIN. */
@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "Hello from a public endpoint");
    }

    @GetMapping("/user")
    public Map<String, String> userEndpoint(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("message", "Hello, authenticated user", "subject", jwt.getSubject());
    }

    /** Bảo vệ 2 lớp: rule URL trong SecurityConfig + @PreAuthorize ở đây. */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> adminEndpoint(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("message", "Hello, admin", "subject", jwt.getSubject());
    }
}
