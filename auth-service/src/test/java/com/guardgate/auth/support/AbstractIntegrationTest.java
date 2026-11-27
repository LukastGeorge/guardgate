package com.guardgate.auth.support;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration test chạy với Postgres + Redis THẬT trong container (cùng image với docker-compose),
 * nên test cả Flyway migration, câu SQL khoá dòng (FOR UPDATE) và TTL của Redis.
 * {@code @ServiceConnection} tự trỏ datasource/redis của Spring vào container.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
public abstract class AbstractIntegrationTest {

    public static final String ADMIN_EMAIL = "admin@guardgate.test";
    public static final String ADMIN_PASSWORD = "Admin-Password-For-Tests-1";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17.6-alpine");

    @Container
    @ServiceConnection(name = "redis")
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4.6-alpine").withExposedPorts(6379);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("guardgate.jwt.private-key", () -> TestKeys.base64Pkcs8(TestKeys.rsa2048()));
        registry.add("guardgate.security.bcrypt-strength", () -> 4);
        registry.add("guardgate.bootstrap-admin.email", () -> ADMIN_EMAIL);
        registry.add("guardgate.bootstrap-admin.password", () -> ADMIN_PASSWORD);
    }
}
