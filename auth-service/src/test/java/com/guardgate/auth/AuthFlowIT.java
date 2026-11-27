package com.guardgate.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditLogRepository;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.support.AbstractIntegrationTest;
import com.guardgate.auth.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

class AuthFlowIT extends AbstractIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-1";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private UserRepository users;
    @Autowired
    private AuditLogRepository auditLogs;

    // ---------- Đăng ký & validation ----------

    @Test
    void registerLoginAndReadOwnProfile() throws Exception {
        String email = uniqueEmail();
        register(email);

        TokenResponse tokens = login(email, PASSWORD);

        assertThat(tokens.tokenType()).isEqualTo("Bearer");
        assertThat(tokens.expiresIn()).isEqualTo(900);
        mvc.perform(get("/api/users/me").header(HttpHeaders.AUTHORIZATION, bearer(tokens.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void registerIgnoresRoleInPayload() throws Exception {
        postJson("/api/auth/register", Map.of("email", uniqueEmail(), "password", PASSWORD, "role", "ADMIN"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void duplicateEmailIsRejectedCaseInsensitively() throws Exception {
        String email = uniqueEmail();
        register(email);

        postJson("/api/auth/register", Map.of("email", email.toUpperCase(), "password", PASSWORD))
                .andExpect(status().isConflict())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void invalidInputReturnsProblemDetailWithoutEchoingValues() throws Exception {
        String body = postJson("/api/auth/register", Map.of("email", "not-an-email", "password", "tiny-secret"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.errors[*].field", containsInAnyOrder("email", "password")))
                .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("tiny-secret", "trace", "Exception");
    }

    @Test
    void malformedJsonDoesNotLeakParserDetails() throws Exception {
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("com.fasterxml", "JsonParseException", "at ");
    }

    // ---------- Đăng nhập & khoá tài khoản ----------

    @Test
    void wrongPasswordAndUnknownEmailReturnIdenticalErrors() throws Exception {
        String email = uniqueEmail();
        register(email);

        String wrongPassword = postJson("/api/auth/login", Map.of("email", email, "password", "Wrong-Password-1"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String unknownEmail = postJson("/api/auth/login", Map.of("email", uniqueEmail(), "password", PASSWORD))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(json.readTree(wrongPassword).get("detail")).isEqualTo(json.readTree(unknownEmail).get("detail"));
    }

    @Test
    void accountIsLockedAfterFiveFailedAttempts() throws Exception {
        String email = uniqueEmail();
        register(email);

        failLogin(email, 5);

        // Mật khẩu ĐÚNG vẫn bị từ chối trong thời gian khoá
        postJson("/api/auth/login", Map.of("email", email, "password", PASSWORD))
                .andExpect(status().isUnauthorized());
        UUID userId = users.findByEmail(email).orElseThrow().getId();
        assertThat(auditLogs.findByUserIdAndEventType(userId, AuditEventType.ACCOUNT_LOCKED)).hasSize(1);
        assertThat(auditLogs.findByUserIdAndEventType(userId, AuditEventType.LOGIN_FAILURE)).hasSize(6);
    }

    @Test
    void adminCanUnlockAccount() throws Exception {
        String email = uniqueEmail();
        register(email);
        failLogin(email, 5);
        UUID userId = users.findByEmail(email).orElseThrow().getId();
        String adminToken = login(ADMIN_EMAIL, ADMIN_PASSWORD).accessToken();

        mvc.perform(post("/api/admin/users/{id}/unlock", userId).header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isNoContent());

        login(email, PASSWORD);
    }

    // ---------- Refresh token rotation ----------

    @Test
    void refreshRotatesTokenAndReuseRevokesWholeFamily() throws Exception {
        String email = uniqueEmail();
        register(email);
        TokenResponse first = login(email, PASSWORD);

        TokenResponse second = refresh(first.refreshToken());
        assertThat(second.refreshToken()).isNotEqualTo(first.refreshToken());

        // Kẻ tấn công dùng lại token cũ => bị từ chối và cả family bị thu hồi
        postJson("/api/auth/refresh", Map.of("refreshToken", first.refreshToken()))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", Map.of("refreshToken", second.refreshToken()))
                .andExpect(status().isUnauthorized());

        UUID userId = users.findByEmail(email).orElseThrow().getId();
        assertThat(auditLogs.findByUserIdAndEventType(userId, AuditEventType.REFRESH_TOKEN_REUSE_DETECTED)).hasSize(1);
    }

    // ---------- Logout ----------

    @Test
    void logoutRevokesAccessTokenAndRefreshToken() throws Exception {
        String email = uniqueEmail();
        register(email);
        TokenResponse tokens = login(email, PASSWORD);

        mvc.perform(post("/api/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(tokens.accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("refreshToken", tokens.refreshToken()))))
                .andExpect(status().isNoContent());

        mvc.perform(get("/api/users/me").header(HttpHeaders.AUTHORIZATION, bearer(tokens.accessToken())))
                .andExpect(status().isUnauthorized());
        postJson("/api/auth/refresh", Map.of("refreshToken", tokens.refreshToken()))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Phân quyền (RBAC) & token giả mạo ----------

    @Test
    void protectedEndpointWithoutTokenReturns401WithChallenge() throws Exception {
        mvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void userCannotAccessAdminEndpoints() throws Exception {
        String email = uniqueEmail();
        register(email);
        String token = login(email, PASSWORD).accessToken();

        mvc.perform(get("/api/admin/audit-logs").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void adminCanReadAuditLogsFilteredByType() throws Exception {
        String adminToken = login(ADMIN_EMAIL, ADMIN_PASSWORD).accessToken();

        mvc.perform(get("/api/admin/audit-logs").param("eventType", "LOGIN_SUCCESS")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[*].eventType", everyItem(is("LOGIN_SUCCESS"))))
                .andExpect(jsonPath("$.totalElements").isNumber());

        mvc.perform(get("/api/admin/audit-logs").param("sort", "doesNotExist")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void tokenWithForgedAdminRoleIsRejected() throws Exception {
        String email = uniqueEmail();
        register(email);
        String[] parts = login(email, PASSWORD).accessToken().split("\\.");

        ObjectNode payload = (ObjectNode) json.readTree(Base64.getUrlDecoder().decode(parts[1]));
        payload.putArray("roles").add("ADMIN");
        String forged = parts[0] + "." + base64Url(json.writeValueAsBytes(payload)) + "." + parts[2];

        mvc.perform(get("/api/admin/audit-logs").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unsignedAlgNoneTokenIsRejected() throws Exception {
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = base64Url(("{\"sub\":\"" + UUID.randomUUID() + "\",\"roles\":[\"ADMIN\"],"
                + "\"iss\":\"guardgate-auth\",\"aud\":\"guardgate\",\"exp\":4102444800}").getBytes(StandardCharsets.UTF_8));

        mvc.perform(get("/api/admin/audit-logs").header(HttpHeaders.AUTHORIZATION, bearer(header + "." + payload + ".")))
                .andExpect(status().isUnauthorized());
    }

    // ---------- Hạ tầng bảo mật ----------

    @Test
    void jwksExposesOnlyPublicKeyMaterial() throws Exception {
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist());
    }

    @Test
    void responsesCarrySecurityHeaders() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")));
    }

    @Test
    void sensitiveActuatorEndpointsAreNotExposed() throws Exception {
        String adminToken = login(ADMIN_EMAIL, ADMIN_PASSWORD).accessToken();
        for (String endpoint : new String[] {"/actuator/env", "/actuator/heapdump", "/actuator/configprops"}) {
            mvc.perform(get(endpoint).header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                    .andExpect(status().isNotFound());
        }
    }

    @Test
    void oauth2EndpointsAreDisabledWithoutGithubProfile() throws Exception {
        mvc.perform(get("/oauth2/authorization/github")).andExpect(status().isUnauthorized());
    }

    // ---------- Helpers ----------

    private ResultActions postJson(String url, Object body) throws Exception {
        return mvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body)));
    }

    private void register(String email) throws Exception {
        postJson("/api/auth/register", Map.of("email", email, "password", PASSWORD)).andExpect(status().isCreated());
    }

    private TokenResponse login(String email, String password) throws Exception {
        String body = postJson("/api/auth/login", Map.of("email", email, "password", password))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readValue(body, TokenResponse.class);
    }

    private TokenResponse refresh(String refreshToken) throws Exception {
        String body = postJson("/api/auth/refresh", Map.of("refreshToken", refreshToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readValue(body, TokenResponse.class);
    }

    private void failLogin(String email, int times) throws Exception {
        for (int i = 0; i < times; i++) {
            postJson("/api/auth/login", Map.of("email", email, "password", "Wrong-Password-" + i))
                    .andExpect(status().isUnauthorized());
        }
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
