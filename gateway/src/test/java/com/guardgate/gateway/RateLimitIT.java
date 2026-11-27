package com.guardgate.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.unauthorized;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.guardgate.gateway.support.GatewayTestInfra;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Giá trị rate limit THẬT cho auth-ip và ip (spec D8); user được hạ xuống 1/2/1 để test nhanh.
 * Mọi request từ cùng 127.0.0.1 với trusted-proxies=0 → chung một bucket IP; mỗi test xoá bucket trước.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RateLimitIT {

    private static final String LOGIN_BODY = "{\"email\":\"a@b.c\",\"password\":\"wrong-password\"}";

    @Autowired
    private WebTestClient client;
    @Autowired
    private ReactiveStringRedisTemplate redis;
    @Autowired
    private MeterRegistry meterRegistry;

    @DynamicPropertySource
    static void rateLimits(DynamicPropertyRegistry registry) {
        GatewayTestInfra.register(registry, GatewayTestInfra.downstreamUrl());
        GatewayTestInfra.registerRateLimit(registry, "auth-ip", 1, 60, 6);
        GatewayTestInfra.registerRateLimit(registry, "ip", 20, 40, 1);
        GatewayTestInfra.registerRateLimit(registry, "user", 1, 2, 1);
        registry.add("GATEWAY_TRUSTED_PROXIES", () -> 0);
    }

    @BeforeEach
    void resetBucketsAndDownstream() {
        redis.scan(ScanOptions.scanOptions().match("request_rate_limiter.*").build())
                .flatMap(redis::delete)
                .blockLast();
        GatewayTestInfra.DOWNSTREAM.resetAll();
        GatewayTestInfra.DOWNSTREAM.stubFor(get("/.well-known/jwks.json")
                .willReturn(okJson(GatewayTestInfra.JWT.jwksJson())));
        GatewayTestInfra.DOWNSTREAM.stubFor(post("/api/auth/login").willReturn(unauthorized()));
        GatewayTestInfra.DOWNSTREAM.stubFor(get("/api/demo/user").willReturn(okJson("{}")));
    }

    @Test
    void eleventhLoginWithinAMinuteIsBlocked() {
        double blockedBefore = blockedCount("rate_limit_auth_ip");

        List<Integer> statuses = login(10);
        assertThat(statuses).doesNotContain(429);

        client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON).bodyValue(LOGIN_BODY)
                .exchange()
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "6")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody().jsonPath("$.detail").isEqualTo("Too many requests");

        assertThat(blockedCount("rate_limit_auth_ip")).isGreaterThan(blockedBefore);
    }

    @Test
    void spoofedForwardedForDoesNotResetBucket() {
        login(11);

        client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON).bodyValue(LOGIN_BODY)
                .header("X-Forwarded-For", "9.9.9.9")
                .exchange()
                .expectStatus().isEqualTo(429);
    }

    @Test
    void userBucketIsPerSubject() {
        String userA = GatewayTestInfra.JWT.token("user-a", List.of("USER"));
        String userB = GatewayTestInfra.JWT.token("user-b", List.of("USER"));

        List<Integer> statusesA = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            statusesA.add(getDemoUser(userA));
        }
        assertThat(statusesA).containsExactly(200, 200, 429);
        assertThat(getDemoUser(userB)).isEqualTo(200);
    }

    @Test
    void blockedRequestsNeverReachDownstream() {
        List<Integer> statuses = login(15);

        long forwarded = statuses.stream().filter(status -> status != 429).count();
        assertThat(statuses).contains(429);
        GatewayTestInfra.DOWNSTREAM.verify((int) forwarded, postRequestedFor(urlEqualTo("/api/auth/login")));
        GatewayTestInfra.DOWNSTREAM.verify(0, getRequestedFor(urlEqualTo("/api/demo/user")));
    }

    private List<Integer> login(int times) {
        List<Integer> statuses = new ArrayList<>();
        for (int i = 0; i < times; i++) {
            statuses.add(client.post().uri("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(LOGIN_BODY).exchange().returnResult(String.class).getStatus().value());
        }
        return statuses;
    }

    private int getDemoUser(String token) {
        return client.get().uri("/api/demo/user").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange().returnResult(String.class).getStatus().value();
    }

    private double blockedCount(String reason) {
        Counter counter = meterRegistry.find("guardgate.gateway.blocked.requests").tag("reason", reason).counter();
        return counter == null ? 0 : counter.count();
    }
}
