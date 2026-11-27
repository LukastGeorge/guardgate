package com.guardgate.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.http.Fault;
import com.guardgate.gateway.security.ReactiveAccessTokenDenylist;
import com.guardgate.gateway.support.AbstractGatewayIT;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.EntityExchangeResult;

class GatewayRoutingSecurityIT extends AbstractGatewayIT {

    private static final String UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

    // ---------- Định tuyến & xác thực ----------

    @Test
    void publicLoginIsRoutedToAuthService() {
        DOWNSTREAM.stubFor(post("/api/auth/login").willReturn(okJson("{\"ok\":true}")));

        client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"email\":\"a@b.c\",\"password\":\"x\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"ok\":true}");

        DOWNSTREAM.verify(postRequestedFor(urlEqualTo("/api/auth/login"))
                .withHeader("X-Forwarded-For", matching(".+")));
    }

    @Test
    void forwardedForCarriesRealClientIpNotSpoofedValue() {
        DOWNSTREAM.stubFor(post("/api/auth/login").willReturn(okJson("{}")));

        client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .header("X-Forwarded-For", "6.6.6.6")
                .bodyValue("{}")
                .exchange()
                .expectStatus().isOk();

        // auth-service dùng header này cho lockout/audit: IP giả từ client không được lọt qua
        DOWNSTREAM.verify(postRequestedFor(urlEqualTo("/api/auth/login"))
                .withHeader("X-Forwarded-For", matching("^(127\\.0\\.0\\.1|0:0:0:0:0:0:0:1)$")));
    }

    @Test
    void protectedRouteWithoutTokenReturns401Problem() {
        client.get().uri("/api/users/me").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON);
        DOWNSTREAM.verify(0, getRequestedFor(urlEqualTo("/api/users/me")));
    }

    @Test
    void userTokenIsForwardedWithAuthorizationHeader() {
        DOWNSTREAM.stubFor(get("/api/demo/user").willReturn(okJson("{\"hello\":\"user\"}")));
        String token = JWT.token("user-1", List.of("USER"));

        client.get().uri("/api/demo/user").header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange()
                .expectStatus().isOk();

        DOWNSTREAM.verify(getRequestedFor(urlEqualTo("/api/demo/user"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo(bearer(token))));
    }

    @Test
    void userTokenCannotReachAdminRoutes() {
        String token = JWT.token("user-1", List.of("USER"));

        for (String path : List.of("/api/admin/audit-logs", "/api/demo/admin")) {
            client.get().uri(path).header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange()
                    .expectStatus().isForbidden()
                    .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON);
        }
        DOWNSTREAM.verify(0, anyRequestedFor(urlMatching("(?i).*admin.*")));
    }

    @Test
    void adminTokenReachesAdminRoutes() {
        DOWNSTREAM.stubFor(get("/api/demo/admin").willReturn(okJson("{}")));

        client.get().uri("/api/demo/admin")
                .header(HttpHeaders.AUTHORIZATION, bearer(JWT.token("admin-1", List.of("ADMIN")))).exchange()
                .expectStatus().isOk();
    }

    @Test
    void pathTricksDoNotBypassAdminRule() {
        String token = JWT.token("user-1", List.of("USER"));

        for (String path : List.of("/api/demo/admin/", "/api/demo//admin", "/API/demo/admin", "/api/demo/%61dmin")) {
            int status = client.get().uri(URI.create("http://localhost:" + port + path))
                    .header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange()
                    .returnResult(String.class).getStatus().value();
            assertThat(status).as(path).isIn(400, 403, 404);
        }
        DOWNSTREAM.verify(0, anyRequestedFor(urlMatching("(?i).*(admin|%61dmin).*")));
    }

    @Test
    void forgedTokensAreRejected() {
        List<String> forged = List.of(
                JWT.hs256TokenSignedWithPublicKey(),
                JWT.token(claims -> claims.audience("other")),
                JWT.token(claims -> claims.expirationTime(Date.from(Instant.now().minusSeconds(120)))),
                JWT.token(claims -> claims.jwtID(null)));

        for (String token : forged) {
            client.get().uri("/api/users/me").header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange()
                    .expectStatus().isUnauthorized();
        }
        DOWNSTREAM.verify(0, getRequestedFor(urlEqualTo("/api/users/me")));
    }

    @Test
    void revokedTokenIsRejected() {
        String jti = "revoked-" + UUID.randomUUID();
        String token = JWT.token(claims -> claims.jwtID(jti));
        redis.opsForValue().set(ReactiveAccessTokenDenylist.KEY_PREFIX + jti, "1", Duration.ofMinutes(5)).block();

        client.get().uri("/api/users/me").header(HttpHeaders.AUTHORIZATION, bearer(token)).exchange()
                .expectStatus().isUnauthorized();
    }

    // ---------- Lỗi chuẩn hoá ----------

    @Test
    void unknownRouteReturns404Problem() {
        client.get().uri("/nope").header(HttpHeaders.AUTHORIZATION, bearer(JWT.token("u", List.of("USER"))))
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody().jsonPath("$.status").isEqualTo(404);
    }

    @Test
    void downstreamConnectionResetReturns503() {
        DOWNSTREAM.stubFor(get("/api/demo/public").willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

        assertProblem(client.get().uri("/api/demo/public").exchange().expectStatus().isEqualTo(503)
                .expectBody(String.class).returnResult());
    }

    @Test
    void downstreamSlowReturns504() {
        DOWNSTREAM.stubFor(get("/api/demo/public").willReturn(okJson("{}").withFixedDelay(2_000)));

        assertProblem(client.get().uri("/api/demo/public").exchange().expectStatus().isEqualTo(504)
                .expectBody(String.class).returnResult());
    }

    @Test
    void oversizedBodyReturns413() {
        client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new byte[2 * 1024 * 1024])
                .exchange()
                .expectStatus().isEqualTo(413);
        DOWNSTREAM.verify(0, postRequestedFor(urlEqualTo("/api/auth/login")));
    }

    // ---------- Request id, CORS, header ----------

    @Test
    void requestIdIsGeneratedOrSanitisedAndForwarded() {
        DOWNSTREAM.stubFor(get("/api/demo/public").willReturn(okJson("{}")));

        client.get().uri("/api/demo/public").exchange()
                .expectHeader().valueMatches("X-Request-Id", UUID_REGEX);
        client.get().uri("/api/demo/public").header("X-Request-Id", "abc-123").exchange()
                .expectHeader().valueEquals("X-Request-Id", "abc-123");
        client.get().uri("/api/demo/public").header("X-Request-Id", "bad id!").exchange()
                .expectHeader().valueMatches("X-Request-Id", UUID_REGEX);

        DOWNSTREAM.verify(getRequestedFor(urlEqualTo("/api/demo/public"))
                .withHeader("X-Request-Id", equalTo("abc-123")));
    }

    @Test
    void corsAllowsOnlyConfiguredOrigin() {
        client.options().uri("/api/demo/public")
                .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN);

        client.options().uri("/api/demo/public")
                .header(HttpHeaders.ORIGIN, "https://evil.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
    }

    @Test
    void securityHeadersPresentExactlyOnce() {
        // Downstream cũng tự gửi header bảo mật: gateway không được nhân đôi chúng
        DOWNSTREAM.stubFor(get("/api/demo/public").willReturn(okJson("{}")
                .withHeader("X-Frame-Options", "DENY")
                .withHeader("X-Content-Type-Options", "nosniff")));

        HttpHeaders headers = client.get().uri("/api/demo/public").exchange()
                .expectStatus().isOk()
                .returnResult(String.class).getResponseHeaders();

        assertThat(headers.get("X-Frame-Options")).containsExactly("DENY");
        assertThat(headers.get("X-Content-Type-Options")).containsExactly("nosniff");
        assertThat(headers.getFirst("Content-Security-Policy")).contains("default-src 'none'");
        assertThat(headers.getFirst("Referrer-Policy")).isEqualTo("no-referrer");
        assertThat(headers.getFirst(HttpHeaders.CACHE_CONTROL)).contains("no-store");
    }

    static void assertProblem(EntityExchangeResult<String> result) {
        assertThat(result.getResponseHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(result.getResponseBody()).doesNotContain("trace", "Exception", "at ");
    }
}
