package com.guardgate.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.guardgate.auth.audit.AuditEventType;
import com.guardgate.auth.audit.AuditLogRepository;
import com.guardgate.auth.auth.dto.TokenResponse;
import com.guardgate.auth.support.AbstractIntegrationTest;
import com.guardgate.auth.user.User;
import com.guardgate.auth.user.UserRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Kiểm chứng các cơ chế chống race condition của giai đoạn 2 khi nhiều request đến CÙNG LÚC:
 * UPDATE nguyên tử cho bộ đếm lockout và SELECT ... FOR UPDATE khi rotate refresh token.
 */
class ConcurrencyIT extends AbstractIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-1";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private UserRepository users;
    @Autowired
    private AuditLogRepository auditLogs;

    @Test
    void concurrentFailedLoginsLockExactlyOnce() throws Exception {
        String email = uniqueEmail();
        register(email);

        List<Integer> statuses = runConcurrently(20, i -> post("/api/auth/login", Map.of(
                "email", email, "password", "Wrong-Password-" + i)).getStatus());

        assertThat(statuses).containsOnly(401);
        User user = users.findByEmail(email).orElseThrow();
        assertThat(user.getLockedUntil()).isNotNull();
        assertThat(user.getFailedLoginAttempts()).isLessThan(5);
        assertThat(auditLogs.findByUserIdAndEventType(user.getId(), AuditEventType.ACCOUNT_LOCKED)).hasSize(1);
    }

    @Test
    void concurrentRefreshWithSameTokenSucceedsAtMostOnce() throws Exception {
        String email = uniqueEmail();
        register(email);
        String refreshToken = login(email).refreshToken();

        List<MockHttpServletResponse> responses = runConcurrently(10,
                i -> post("/api/auth/refresh", Map.of("refreshToken", refreshToken)));

        List<MockHttpServletResponse> successes = responses.stream().filter(r -> r.getStatus() == 200).toList();
        assertThat(successes).hasSize(1);
        assertThat(responses).extracting(MockHttpServletResponse::getStatus).containsOnly(200, 401);

        UUID userId = users.findByEmail(email).orElseThrow().getId();
        assertThat(auditLogs.findByUserIdAndEventType(userId, AuditEventType.REFRESH_TOKEN_REUSE_DETECTED))
                .isNotEmpty();
        String rotated = json.readValue(successes.getFirst().getContentAsString(), TokenResponse.class).refreshToken();
        assertThat(post("/api/auth/refresh", Map.of("refreshToken", rotated)).getStatus()).isEqualTo(401);
    }

    // ---------- Helpers ----------

    private interface Call<T> {
        T run(int index) throws Exception;
    }

    /** Chạy n lời gọi trên n thread, cùng xuất phát sau một CountDownLatch để tối đa hoá va chạm. */
    private static <T> List<T> runConcurrently(int n, Call<T> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                int index = i;
                Callable<T> task = () -> {
                    start.await();
                    return call.run(index);
                };
                futures.add(pool.submit(task));
            }
            start.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> future : futures) {
                results.add(future.get(60, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private MockHttpServletResponse post(String url, Object body) throws Exception {
        return mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn().getResponse();
    }

    private void register(String email) throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", PASSWORD))))
                .andExpect(status().isCreated());
    }

    private TokenResponse login(String email) throws Exception {
        MockHttpServletResponse response = post("/api/auth/login", Map.of("email", email, "password", PASSWORD));
        assertThat(response.getStatus()).isEqualTo(200);
        return json.readValue(response.getContentAsString(), TokenResponse.class);
    }

    private static String uniqueEmail() {
        return "race-" + UUID.randomUUID() + "@example.com";
    }
}
