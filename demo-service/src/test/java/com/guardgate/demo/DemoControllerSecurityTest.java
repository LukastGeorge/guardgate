package com.guardgate.demo;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.guardgate.demo.security.JwtConfig;
import com.guardgate.demo.security.ProblemDetailAccessDeniedHandler;
import com.guardgate.demo.security.ProblemDetailAuthenticationEntryPoint;
import com.guardgate.demo.security.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

/**
 * jwt() của spring-security-test đặt sẵn Authentication, bỏ qua bước verify chữ ký: test này kiểm tra
 * RULE PHÂN QUYỀN và định dạng lỗi. Việc verify chữ ký dùng chung cấu hình đã được test ở auth-service/gateway.
 */
@WebMvcTest(DemoController.class)
@Import({SecurityConfig.class, JwtConfig.class, ProblemDetailAuthenticationEntryPoint.class,
        ProblemDetailAccessDeniedHandler.class})
class DemoControllerSecurityTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void publicNeedsNoToken() throws Exception {
        mvc.perform(get("/api/demo/public"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello from a public endpoint"));
    }

    @Test
    void userEndpointRequiresToken() throws Exception {
        mvc.perform(get("/api/demo/user"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void userCanReadUserEndpoint() throws Exception {
        mvc.perform(get("/api/demo/user").with(jwt().jwt(j -> j.subject("u1"))
                        .authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, authenticated user"))
                .andExpect(jsonPath("$.subject").value("u1"));
    }

    @Test
    void userCannotReadAdminEndpoint() throws Exception {
        mvc.perform(get("/api/demo/admin").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void adminCanReadAdminEndpoint() throws Exception {
        mvc.perform(get("/api/demo/admin").with(jwt().jwt(j -> j.subject("a1"))
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello, admin"))
                .andExpect(jsonPath("$.subject").value("a1"));
    }

    @Test
    void securityHeadersPresent() throws Exception {
        mvc.perform(get("/api/demo/public"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")));
    }
}
