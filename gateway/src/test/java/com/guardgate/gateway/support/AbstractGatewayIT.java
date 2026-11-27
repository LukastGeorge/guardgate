package com.guardgate.gateway.support;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Gateway thật (cổng ngẫu nhiên) + Redis thật (Testcontainers) + WireMock đóng vai CẢ auth-service
 * (JWKS và các API) lẫn demo-service. Xem {@link GatewayTestInfra}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractGatewayIT {

    protected static final String ALLOWED_ORIGIN = GatewayTestInfra.ALLOWED_ORIGIN;
    protected static final TestJwtFactory JWT = GatewayTestInfra.JWT;
    protected static final WireMockServer DOWNSTREAM = GatewayTestInfra.DOWNSTREAM;

    @Autowired
    protected WebTestClient client;
    @Autowired
    protected ReactiveStringRedisTemplate redis;
    @LocalServerPort
    protected int port;

    @DynamicPropertySource
    static void gatewayProperties(DynamicPropertyRegistry registry) {
        GatewayTestInfra.register(registry, GatewayTestInfra.downstreamUrl());
    }

    @BeforeEach
    void resetDownstream() {
        DOWNSTREAM.resetAll();
        DOWNSTREAM.stubFor(get("/.well-known/jwks.json").willReturn(okJson(JWT.jwksJson())));
    }

    protected static String bearer(String token) {
        return "Bearer " + token;
    }
}
