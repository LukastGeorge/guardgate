package com.guardgate.gateway.support;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.GenericContainer;

/**
 * Hạ tầng dùng chung cho mọi integration test của gateway, khởi động MỘT lần cho cả JVM.
 *
 * <p>Mỗi class test tự gọi {@link #register} trong {@code @DynamicPropertySource} của nó, thay vì kế thừa:
 * {@code @DynamicPropertySource} của lớp con KHÔNG ghi đè được giá trị cùng tên do lớp cha đăng ký
 * (đã kiểm chứng: route demo vẫn trỏ vào WireMock thay vì cổng đóng).
 */
public final class GatewayTestInfra {

    public static final String ALLOWED_ORIGIN = "https://app.example";
    public static final TestJwtFactory JWT = new TestJwtFactory();
    public static final WireMockServer DOWNSTREAM = new WireMockServer(options().dynamicPort());
    public static final GenericContainer<?> REDIS =
            new GenericContainer<>("redis:7.4.6-alpine").withExposedPorts(6379);

    static {
        DOWNSTREAM.start();
        REDIS.start();
    }

    private GatewayTestInfra() {
    }

    public static String downstreamUrl() {
        return "http://localhost:" + DOWNSTREAM.port();
    }

    /** Đăng ký property chung; demo-service có thể trỏ đi nơi khác để mô phỏng sự cố. */
    public static void register(DynamicPropertyRegistry registry, String demoServiceUrl) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("AUTH_SERVICE_URL", GatewayTestInfra::downstreamUrl);
        registry.add("DEMO_SERVICE_URL", () -> demoServiceUrl);
        registry.add("JWT_JWK_SET_URI", () -> downstreamUrl() + "/.well-known/jwks.json");
        registry.add("GATEWAY_RESPONSE_TIMEOUT", () -> "1s");
        registry.add("CORS_ALLOWED_ORIGINS", () -> ALLOWED_ORIGIN);
    }

    /** Giới hạn rất cao: test chức năng (gửi hàng chục request từ cùng IP) không bị 429 ngoài ý muốn. */
    public static void registerRelaxedRateLimits(DynamicPropertyRegistry registry) {
        for (String policy : new String[] {"auth-ip", "ip", "user"}) {
            registerRateLimit(registry, policy, 1000, 2000, 1);
        }
    }

    public static void registerRateLimit(DynamicPropertyRegistry registry, String policy,
                                         int replenishRate, int burstCapacity, int requestedTokens) {
        String prefix = "guardgate.gateway.rate-limits." + policy + ".";
        registry.add(prefix + "replenish-rate", () -> replenishRate);
        registry.add(prefix + "burst-capacity", () -> burstCapacity);
        registry.add(prefix + "requested-tokens", () -> requestedTokens);
    }
}
