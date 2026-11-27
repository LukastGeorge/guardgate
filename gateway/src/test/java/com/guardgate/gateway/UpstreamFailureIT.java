package com.guardgate.gateway;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.serverError;
import static org.assertj.core.api.Assertions.assertThat;

import com.guardgate.gateway.support.GatewayTestInfra;
import java.io.IOException;
import java.net.ServerSocket;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Context Spring RIÊNG (không kế thừa AbstractGatewayIT): JWKS chưa từng tải được, và demo-service
 * trỏ tới một cổng không có ai lắng nghe.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UpstreamFailureIT {

    private static final int CLOSED_PORT = findClosedPort();

    @Autowired
    private WebTestClient client;

    @DynamicPropertySource
    static void brokenUpstreams(DynamicPropertyRegistry registry) {
        GatewayTestInfra.register(registry, "http://localhost:" + CLOSED_PORT);
        GatewayTestInfra.registerRelaxedRateLimits(registry);
    }

    @BeforeEach
    void jwksIsDown() {
        GatewayTestInfra.DOWNSTREAM.resetAll();
        GatewayTestInfra.DOWNSTREAM.stubFor(get("/.well-known/jwks.json").willReturn(serverError()));
    }

    @Test
    void jwksUnavailableYieldsProblemNotStackTrace() {
        var result = client.get().uri("/api/users/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + GatewayTestInfra.JWT.token("u", List.of("USER")))
                .exchange()
                .expectBody(String.class).returnResult();

        assertThat(result.getStatus().value()).isIn(401, 503);
        GatewayRoutingSecurityIT.assertProblem(result);
    }

    @Test
    void downstreamDownReturns503() {
        GatewayRoutingSecurityIT.assertProblem(client.get().uri("/api/demo/public").exchange()
                .expectStatus().isEqualTo(503)
                .expectBody(String.class).returnResult());
    }

    private static int findClosedPort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
