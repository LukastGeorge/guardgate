# Giai đoạn 3: Gateway + Rate limiting + demo-service — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Đưa toàn bộ traffic đi qua một gateway có xác thực JWT, rate limit bằng Redis, lỗi chuẩn hoá; thêm demo-service có 3 mức quyền; vá các lỗ hổng tồn đọng của giai đoạn 2.

**Architecture:** Spring Cloud Gateway (WebFlux) là điểm vào duy nhất. JWT được verify bằng JWKS của auth-service và đối chiếu denylist trong Redis (fail-closed). Rate limit gồm 2 WebFilter/GlobalFilter dùng chung `RedisRateLimiter` (token bucket, fail-open). demo-service là resource server servlet tự verify lại JWT.

**Tech Stack:** Java 21, Spring Boot 3.5.12, Spring Cloud 2025.0.x (Gateway Server WebFlux), Spring Security 6.5 (reactive resource server), Redis 7.4 (reactive Lettuce), Micrometer, JUnit 5, Testcontainers, WireMock (`spring-cloud-contract-wiremock`).

**Spec:** `docs/superpowers/specs/2026-11-27-guardgate-design.md` (mục 3.1, 3.2, 4 [D5–D13], 6 [GĐ2 hardening, GĐ3])

## Global Constraints

- Spring Boot `3.5.12`; pgjdbc `42.7.12`; Java `21`; không thêm dependency ngoài BOM của Boot/Cloud, trừ khi task ghi rõ.
- Cổng: gateway `8080`, auth-service `8081`, demo-service `8082`.
- Mọi lỗi: `Content-Type: application/problem+json`, body có `status`, `title`, `detail`; không chứa `trace`, `exception`, tên class Java.
- JWT: `iss=guardgate-auth`, `aud` chứa `guardgate`, claim `roles` (mảng, ví dụ `["ADMIN"]`), `sub` = UUID user, `jti` bắt buộc, chỉ RS256.
- Redis key denylist: `guardgate:revoked-jti:{jti}` (giống `AccessTokenDenylist.KEY_PREFIX` của auth-service).
- Biến môi trường mới: `AUTH_SERVICE_URL` (mặc định `http://localhost:8081`), `DEMO_SERVICE_URL` (`http://localhost:8082`), `JWT_JWK_SET_URI` (`http://localhost:8081/.well-known/jwks.json`), `CORS_ALLOWED_ORIGINS` (mặc định rỗng = không cho origin nào), `GATEWAY_TRUSTED_PROXIES` (mặc định `0`).
- Rate limit (D8): `auth-ip` replenishRate=1, burstCapacity=60, requestedTokens=6 (≈10 req/phút); `ip` 20/40/1; `user` 10/20/1.
- Timeout (D13): connect `2000` ms, response `5s`; body tối đa `1MB`.
- Metric: `guardgate.gateway.blocked.requests` (Prometheus: `guardgate_gateway_blocked_requests_total`), tag `reason` ∈ {`rate_limit_auth_ip`, `rate_limit_ip`, `rate_limit_user`}.

## Review Focus

1. **Giả mạo `X-Forwarded-For` để né rate limit.** Với `GATEWAY_TRUSTED_PROXIES=0`, header này phải bị bỏ qua → test ở Task 5.
2. **Redis gặp sự cố.** Denylist phải trả 401 (fail-closed), rate limit phải cho qua (fail-open) → test ở Task 2 và Task 5.
3. **Lách rule theo path:** `/api/demo/admin/`, `/api/demo//admin`, `/API/demo/admin`, `/api/demo/%61dmin` không được tới demo-service khi không phải ADMIN → test ở Task 3.
4. **Token giả:** `alg=HS256` ký bằng public key (key confusion), sai `aud`, hết hạn, thiếu `jti` → tất cả phải 401 → test ở Task 2.
5. **JWKS không truy cập được** (auth-service chết): request có token phải nhận 401 hoặc 503 dạng problem+json, không được trả 500 kèm stack trace → test ở Task 3.

---

### Task 1: Hardening auth-service (H1–H6)

**Files:**
- Modify: `pom.xml` (parent version → `3.5.12`; thêm `<postgresql.version>42.7.12</postgresql.version>` vào properties)
- Create: `auth-service/src/main/java/com/guardgate/auth/user/MaxUtf8Bytes.java`, `MaxUtf8BytesValidator.java`
- Modify: `auth-service/src/main/java/com/guardgate/auth/auth/dto/RegisterRequest.java`, `LoginRequest.java`
- Modify: `auth-service/src/main/java/com/guardgate/auth/user/PasswordPolicy.java` (thêm `MAX_BYTES = 72`)
- Test: `auth-service/src/test/java/com/guardgate/auth/user/MaxUtf8BytesValidatorTest.java`, `auth-service/src/test/java/com/guardgate/auth/AuthFlowIT.java`
- Test (H5): `auth-service/src/test/java/com/guardgate/auth/ConcurrencyIT.java`
- Test (H6): `auth-service/src/test/java/com/guardgate/auth/oauth2/OAuth2AccountServiceTest.java`, `GitHubOAuth2UserServiceTest.java`

**Interfaces:**
- Produces: annotation `@MaxUtf8Bytes(int value)` (Bean Validation, message `"must be at most {value} bytes in UTF-8"`).

- [ ] **Step 1: Viết test thất bại**
  - `MaxUtf8BytesValidatorTest`: `"a".repeat(72)` hợp lệ; `"😀".repeat(19)` (76 byte) không hợp lệ; `null` hợp lệ (để `@NotBlank` xử lý).
  - `AuthFlowIT.passwordLongerThan72BytesIsRejectedWith400`: đăng ký với `"Mật-khẩu-😀".repeat(5)` (≤ 64 ký tự, > 72 byte) → `400`, `$.errors[*].field` chứa `"password"`.
  - `ConcurrencyIT.concurrentFailedLoginsLockExactlyOnce` (H5): 20 lần login sai gửi song song (`ExecutorService` 20 thread + `CountDownLatch` để cùng xuất phát) → tất cả 401; `failed_login_attempts` sau đó = 0 hoặc < 5 và `locked_until` khác null; đúng **1** audit `ACCOUNT_LOCKED`.
  - `ConcurrencyIT.concurrentRefreshWithSameTokenSucceedsAtMostOnce` (H5): 10 request refresh song song cùng một token → đúng 1 response 200; các response còn lại 401; có ≥ 1 audit `REFRESH_TOKEN_REUSE_DETECTED`; token mới từ response 200 cũng bị thu hồi (family revoked).
  - `OAuth2AccountServiceTest` (H6, Mockito): đã có `githubId` → trả user cũ, không gọi `save`; chưa có và email mới → `save(User.github(...))` với email đã chuẩn hoá; email đã thuộc tài khoản local → `OAuth2AuthenticationException` với error code `account_exists`.
  - `GitHubOAuth2UserServiceTest` (H6, `MockRestServiceServer` gắn vào `RestClient.Builder`): `[{email:a,primary:true,verified:true}]` → `"a"`; chỉ có email `primary:true,verified:false` → error `verified_email_required`; API trả 500 → error `github_api_error`; header `Authorization: Bearer <token>` được gửi đúng.
- [ ] **Step 2: Chạy test, xác nhận FAIL**: `./mvnw -pl auth-service verify -Dit.test=AuthFlowIT -Dtest=MaxUtf8BytesValidatorTest` → validator chưa tồn tại / IT nhận 500.
- [ ] **Step 3: Cài đặt** `MaxUtf8BytesValidator implements ConstraintValidator<MaxUtf8Bytes, String>` dùng `value.getBytes(StandardCharsets.UTF_8).length <= max`; gắn `@MaxUtf8Bytes(PasswordPolicy.MAX_BYTES)` vào `password` của `RegisterRequest` và `LoginRequest`; nâng version theo phần **Files**.
- [ ] **Step 4: Chạy toàn bộ**: `./mvnw verify` → BUILD SUCCESS (40+ test); và `docker run --rm -v "$PWD:/src:ro" aquasec/trivy:0.67.2 fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 /src` → exit 0.
- [ ] **Step 5: Commit**: `fix(auth-service): patch Spring Boot/pgjdbc CVEs, enforce 72-byte BCrypt limit, add concurrency and OAuth2 tests`

Ghi chú: nếu `ConcurrencyIT` FAIL thì đó là **bug thật** của giai đoạn 2. Khi đó dùng skill `systematic-debugging` để tìm nguyên nhân gốc trước khi sửa; không được nới lỏng assertion để test pass.

### Task 2: Gateway verify JWT + denylist

**Files:**
- Modify: `gateway/pom.xml` (thêm `spring-boot-starter-security`, `spring-boot-starter-oauth2-resource-server`, `spring-boot-starter-data-redis-reactive`, `spring-boot-starter-validation`; test: `spring-security-test`, `reactor-test`, `spring-boot-testcontainers`, `org.testcontainers:junit-jupiter`, `org.springframework.cloud:spring-cloud-contract-wiremock`; plugin `maven-failsafe-plugin` giống auth-service)
- Create: `gateway/src/main/java/com/guardgate/gateway/config/GatewayJwtProperties.java`
- Create: `gateway/src/main/java/com/guardgate/gateway/security/ReactiveAccessTokenDenylist.java`, `RevocationCheckingJwtDecoder.java`, `JwtConfig.java`
- Test: `gateway/src/test/java/com/guardgate/gateway/security/RevocationCheckingJwtDecoderTest.java`, `gateway/src/test/java/com/guardgate/gateway/support/TestJwtFactory.java`

**Interfaces:**
- Produces:
  - `record GatewayJwtProperties(@NotBlank String jwkSetUri, @NotBlank String issuer, @NotBlank String audience)`, prefix `guardgate.gateway.jwt`
  - `class ReactiveAccessTokenDenylist { static final String KEY_PREFIX = "guardgate:revoked-jti:"; Mono<Boolean> isRevoked(String jti) }`
  - `class RevocationCheckingJwtDecoder implements ReactiveJwtDecoder` — ctor `(ReactiveJwtDecoder delegate, ReactiveAccessTokenDenylist denylist)`
  - Bean `ReactiveJwtDecoder` (JWKS URI, chỉ RS256, validator issuer + audience + timestamp) được bọc bởi `RevocationCheckingJwtDecoder`
  - Bean `Converter<Jwt, Mono<AbstractAuthenticationToken>>`: claim `roles` → `ROLE_*`
  - Test helper `TestJwtFactory`: `String jwksJson()`, `String token(String sub, List<String> roles)`, `String token(Consumer<JWTClaimsSet.Builder> customizer)`, `String hs256TokenSignedWithPublicKey()`

- [ ] **Step 1: Viết test thất bại** `RevocationCheckingJwtDecoderTest` (mock delegate + denylist):
  - `validTokenPassesThrough`: delegate trả Jwt có jti `"j1"`, `isRevoked("j1")` → `false` ⇒ `StepVerifier` emit đúng Jwt đó.
  - `revokedTokenFailsWithBadJwtException`: `isRevoked` → `true` ⇒ lỗi `BadJwtException`.
  - `missingJtiFails`: Jwt không có jti ⇒ `BadJwtException`.
  - `redisErrorFailsClosed`: `isRevoked` → `Mono.error(new RedisConnectionFailureException("down"))` ⇒ `BadJwtException` (không được để lọt `RedisConnectionFailureException`).
- [ ] **Step 2: Chạy** `./mvnw -pl gateway test -Dtest=RevocationCheckingJwtDecoderTest` → FAIL (class chưa tồn tại).
- [ ] **Step 3: Cài đặt** các class ở phần **Interfaces**. Decoder gốc: `NimbusReactiveJwtDecoder.withJwkSetUri(uri).jwsAlgorithm(SignatureAlgorithm.RS256).build()`; dùng `JwtValidators.createDefaultWithIssuer` + `JwtClaimValidator<List<String>>(AUD, aud -> aud != null && aud.contains(audience))`. Thêm vào `application.yml` khối `guardgate.gateway.jwt` (`jwk-set-uri: ${JWT_JWK_SET_URI:http://localhost:8081/.well-known/jwks.json}`, `issuer: ${JWT_ISSUER:guardgate-auth}`, `audience: ${JWT_AUDIENCE:guardgate}`) và `spring.data.redis.*` giống auth-service.
- [ ] **Step 4: Chạy lại** → PASS.
- [ ] **Step 5: Commit**: `feat(gateway): verify JWT via JWKS with fail-closed revocation check`

### Task 3: Gateway routes + SecurityWebFilterChain + xử lý lỗi

**Files:**
- Create: `gateway/src/main/java/com/guardgate/gateway/web/ProblemResponses.java`, `GatewayErrorHandler.java`, `RequestIdFilter.java`
- Create: `gateway/src/main/java/com/guardgate/gateway/security/SecurityConfig.java`, `ProblemDetailServerAuthenticationEntryPoint.java`, `ProblemDetailServerAccessDeniedHandler.java`
- Create: `gateway/src/main/java/com/guardgate/gateway/config/CorsProperties.java`
- Modify: `gateway/src/main/resources/application.yml`
- Test: `gateway/src/test/java/com/guardgate/gateway/support/AbstractGatewayIT.java`, `gateway/src/test/java/com/guardgate/gateway/GatewayRoutingSecurityIT.java`
- Delete: `gateway/src/test/java/com/guardgate/gateway/GatewayApplicationTests.java`

**Interfaces:**
- Consumes: bean `ReactiveJwtDecoder` và converter từ Task 2; `TestJwtFactory`.
- Produces:
  - `final class ProblemResponses { static Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String detail) }` (Task 5 dùng)
  - `record CorsProperties(List<String> allowedOrigins)`, prefix `guardgate.gateway.cors`
  - `RequestIdFilter implements WebFilter, Ordered` (order `-300`): header `X-Request-Id` khớp `^[A-Za-z0-9-]{1,64}$` thì giữ, ngược lại sinh UUID mới; gắn vào cả request đi xuống lẫn response
  - `AbstractGatewayIT`: `@SpringBootTest(webEnvironment = RANDOM_PORT)`, `@AutoConfigureWireMock(port = 0)`, Redis Testcontainers `@ServiceConnection(name = "redis")`, các property `AUTH_SERVICE_URL`, `DEMO_SERVICE_URL`, `JWT_JWK_SET_URI` trỏ vào WireMock, stub `GET /.well-known/jwks.json` → `TestJwtFactory.jwksJson()`, `WebTestClient client`

**Cấu hình routes** (`spring.cloud.gateway.server.webflux`): route `auth-service` với `Path=/api/auth/**,/api/users/**,/api/admin/**,/oauth2/**,/login/oauth2/**` → `${AUTH_SERVICE_URL}`; route `demo-service` với `Path=/api/demo/**` → `${DEMO_SERVICE_URL}`. `default-filters`: `DedupeResponseHeader=Access-Control-Allow-Origin X-Content-Type-Options X-Frame-Options Cache-Control, RETAIN_FIRST`, `RequestSize=1MB`. `httpclient.connect-timeout: 2000`, `httpclient.response-timeout: 5s`.

**Rule bảo mật** (thứ tự quan trọng): `POST /api/auth/register|login|refresh`, `GET /api/demo/public`, `/oauth2/**`, `/login/oauth2/**`, `/actuator/health/**` → permitAll; `/api/admin/**`, `/api/demo/admin/**` → `hasRole("ADMIN")`; `anyExchange().authenticated()`. CSRF tắt, `NoOpServerSecurityContextRepository`, header theo Global Constraints, CORS từ `CorsProperties` (methods `GET,POST,PUT,DELETE`, headers `Authorization, Content-Type, X-Request-Id`, `allowCredentials=false`, `maxAge=3600`).

**Map lỗi trong `GatewayErrorHandler`** (order `-2`): `ResponseStatusException` → status của exception; `ConnectException` / `PrematureCloseException` → `503 "Upstream service unavailable"`; `TimeoutException` → `504 "Upstream service timed out"`; còn lại → `500 "An unexpected error occurred"` + `errorId` (log đầy đủ ở server).

- [ ] **Step 1: Viết test thất bại** trong `GatewayRoutingSecurityIT` (WireMock giả lập downstream):
  - `publicLoginIsRoutedToAuthService`: stub `POST /api/auth/login` → 200 `{"ok":true}`; gọi qua gateway → 200, body `{"ok":true}`, WireMock nhận header `X-Forwarded-For`.
  - `protectedRouteWithoutTokenReturns401Problem`: `GET /api/users/me` → 401, `WWW-Authenticate` chứa `Bearer`, content-type problem+json.
  - `userTokenIsForwardedWithAuthorizationHeader`: token USER → `GET /api/demo/user` → 200; WireMock nhận đúng header `Authorization`.
  - `userTokenCannotReachAdminRoutes`: token USER → `/api/admin/audit-logs` và `/api/demo/admin` → 403; WireMock không nhận request nào.
  - `pathTricksDoNotBypassAdminRule` (Review Focus #3): token USER với `/api/demo/admin/`, `/api/demo//admin`, `/API/demo/admin`, `/api/demo/%61dmin` → không có request nào tới WireMock tại path admin (`verify(0, ...)`), status ∈ {400, 403, 404}.
  - `forgedTokensAreRejected` (Review Focus #4): HS256 ký bằng public key, sai aud (`other`), hết hạn (exp = now − 120s), thiếu jti → đều 401.
  - `revokedTokenIsRejected`: SET `guardgate:revoked-jti:{jti}` trong Redis → 401.
  - `jwksUnavailableYieldsProblemNotStackTrace` (Review Focus #5): WireMock trả 500 cho JWKS (cache trống, dùng context riêng qua `@DirtiesContext`) → status ∈ {401, 503}, body không chứa `"trace"` hay `"Exception"`.
  - `unknownRouteReturns404Problem`: `GET /nope` (có token) → 404 problem+json.
  - `downstreamDownReturns503` (`DEMO_SERVICE_URL` trỏ tới cổng đóng) và `downstreamSlowReturns504` (WireMock `withFixedDelay(6000)`).
  - `oversizedBodyReturns413`: POST 2 MB → 413.
  - `requestIdIsGeneratedOrSanitised`: không gửi → response có UUID; gửi `"abc-123"` → giữ nguyên; gửi `"bad\r\nid"` → được thay bằng UUID.
  - `corsAllowsOnlyConfiguredOrigin`: `CORS_ALLOWED_ORIGINS=https://app.example`; preflight từ origin đó → 200 kèm `Access-Control-Allow-Origin`; từ `https://evil.example` → 403.
  - `securityHeadersPresent`: header như trong Global Constraints, và chỉ xuất hiện **một lần** (đã dedupe).
- [ ] **Step 2: Chạy** `./mvnw -pl gateway verify -Dit.test=GatewayRoutingSecurityIT` → FAIL.
- [ ] **Step 3: Cài đặt** các class và cấu hình ở trên.
- [ ] **Step 4: Chạy lại** → PASS; thêm `./mvnw -pl gateway test` → PASS.
- [ ] **Step 5: Commit**: `feat(gateway): routes, JWT security chain, CORS, request-id and problem+json errors`

### Task 4: demo-service resource server

**Files:**
- Modify: `demo-service/pom.xml` (thêm `spring-boot-starter-security`, `spring-boot-starter-oauth2-resource-server`; test: `spring-security-test`)
- Create: `demo-service/src/main/java/com/guardgate/demo/DemoController.java`, `security/SecurityConfig.java`, `security/JwtConfig.java`, `security/ProblemDetailAuthenticationEntryPoint.java`, `security/ProblemDetailAccessDeniedHandler.java`, `web/GlobalExceptionHandler.java`
- Modify: `demo-service/src/main/resources/application.yml` (khối `guardgate.demo.jwt` với `jwk-set-uri`, `issuer`, `audience` dùng chung biến môi trường như gateway)
- Test: `demo-service/src/test/java/com/guardgate/demo/DemoControllerSecurityTest.java`; xoá `DemoServiceApplicationTests.java`

**Interfaces:**
- Produces (HTTP):
  - `GET /api/demo/public` → `200 {"message":"Hello from a public endpoint"}`
  - `GET /api/demo/user` (USER hoặc ADMIN) → `200 {"message":"Hello, authenticated user","subject":"<sub>"}`
  - `GET /api/demo/admin` (ADMIN) → `200 {"message":"Hello, admin","subject":"<sub>"}`

- [ ] **Step 1: Viết test thất bại** `@WebMvcTest(DemoController.class)` + `@Import(SecurityConfig.class, JwtConfig.class)`, dùng `SecurityMockMvcRequestPostProcessors.jwt()`:
  - `publicNeedsNoToken` → 200; `userEndpointRequiresToken` → 401 problem+json;
  - `userCanReadUserEndpoint` (`jwt().jwt(j -> j.subject("u1")).authorities(ROLE_USER)`) → 200, `$.subject == "u1"`;
  - `userCannotReadAdminEndpoint` → 403 problem+json; `adminCanReadAdminEndpoint` → 200;
  - `securityHeadersPresent` → `X-Frame-Options: DENY`, `Content-Security-Policy` chứa `default-src 'none'`.
- [ ] **Step 2: Chạy** `./mvnw -pl demo-service test` → FAIL.
- [ ] **Step 3: Cài đặt.** `JwtDecoder` giống auth-service nhưng dùng `NimbusJwtDecoder.withJwkSetUri(...)` và **không** kiểm tra denylist (D10). `/api/demo/admin` dùng `@PreAuthorize("hasRole('ADMIN')")` cộng rule theo URL.
- [ ] **Step 4: Chạy lại** → PASS.
- [ ] **Step 5: Commit**: `feat(demo-service): JWT resource server with public/user/admin endpoints`

### Task 5: Rate limiting (IP, auth-IP, user)

**Files:**
- Create: `gateway/src/main/java/com/guardgate/gateway/ratelimit/RateLimitProperties.java`, `ClientIpResolver.java`, `RateLimiterService.java`, `IpRateLimitWebFilter.java`, `UserRateLimitGlobalFilter.java`, `BlockedRequestMetrics.java`
- Modify: `gateway/src/main/resources/application.yml` (khối `guardgate.gateway.rate-limits` và `guardgate.gateway.trusted-proxies: ${GATEWAY_TRUSTED_PROXIES:0}`)
- Test: `gateway/src/test/java/com/guardgate/gateway/ratelimit/ClientIpResolverTest.java`, `RateLimiterServiceTest.java`, `gateway/src/test/java/com/guardgate/gateway/RateLimitIT.java`

**Interfaces:**
- Consumes: `ProblemResponses.write` (Task 3); `AbstractGatewayIT`, `TestJwtFactory`.
- Produces:
  - `record RateLimitProperties(Policy authIp, Policy ip, Policy user)`, prefix `guardgate.gateway.rate-limits`; `record Policy(int replenishRate, int burstCapacity, int requestedTokens)`
  - `enum RateLimitPolicy { AUTH_IP("auth-ip","rate_limit_auth_ip"), IP("ip","rate_limit_ip"), USER("user","rate_limit_user") }` với `id()` và `metricReason()`
  - `record RateLimitDecision(boolean allowed, long remaining)`
  - `RateLimiterService.consume(RateLimitPolicy policy, String key): Mono<RateLimitDecision>`. Dùng một `RedisRateLimiter`; mỗi policy là một entry trong `getConfig()` với key `policy.id()`. Lỗi Redis → allowed=true, remaining=-1, log WARN (fail-open, D7).
  - `ClientIpResolver.resolve(ServerWebExchange): String`. `trustedProxies == 0` → `remoteAddress`; `> 0` → `XForwardedRemoteAddressResolver.maxTrustedIndex(trustedProxies)`.
  - `IpRateLimitWebFilter` (WebFilter, order `-200`, chạy trước Spring Security): request `POST /api/auth/{login,register,refresh}` tốn bucket `AUTH_IP`, mọi request tốn bucket `IP`.
  - `UserRateLimitGlobalFilter` (GlobalFilter, order `0`): nếu principal là `JwtAuthenticationToken` thì tốn bucket `USER` với key là `sub`.
  - Khi bị chặn: `429`, `Retry-After` (`AUTH_IP`: `6`, các policy khác: `1`), `X-RateLimit-Remaining: 0`, problem detail `"Too many requests"`, và tăng `BlockedRequestMetrics.increment(policy.metricReason())`.

- [ ] **Step 1: Viết test thất bại**
  - `ClientIpResolverTest`: trusted=0 + XFF `1.2.3.4` + remote `10.0.0.5` → `10.0.0.5` (Review Focus #1); trusted=1 + XFF `1.2.3.4` → `1.2.3.4`.
  - `RateLimiterServiceTest`: mock `RedisRateLimiter.isAllowed` trả `Mono.error(...)` → `allowed=true` (Review Focus #2).
  - `RateLimitIT` (Redis thật, WireMock downstream):
    - `eleventhLoginWithinAMinuteIsBlocked`: 10 lần `POST /api/auth/login` từ cùng IP → không có 429; lần 11 → 429, `Retry-After: 6`, problem+json; metric `guardgate.gateway.blocked.requests{reason=rate_limit_auth_ip}` ≥ 1.
    - `spoofedForwardedForDoesNotResetBucket`: sau khi bị 429, gửi kèm `X-Forwarded-For: 9.9.9.9` → vẫn 429.
    - `userBucketIsPerSubject`: dùng config test `user` = 1/2/1; user A gọi 3 lần liền → lần 3 bị 429; user B gọi ngay sau đó → 200.
    - `blockedRequestsNeverReachDownstream`: số request WireMock nhận đúng bằng số response không phải 429.
- [ ] **Step 2: Chạy** `./mvnw -pl gateway verify -Dtest='ClientIpResolverTest,RateLimiterServiceTest' -Dit.test=RateLimitIT` → FAIL.
- [ ] **Step 3: Cài đặt.** Trong `AbstractGatewayIT`, đặt mặc định cả 3 policy = `1000/2000/1` để `GatewayRoutingSecurityIT` (hơn 40 request từ cùng IP) không bị 429 ngoài ý muốn. `RateLimitIT` ghi đè qua `@DynamicPropertySource`: `auth-ip` và `ip` dùng đúng giá trị của Global Constraints, `user` = `1/2/1`, `trusted-proxies=0`. `@BeforeEach` xoá các key rate limit (`SCAN request_rate_limiter.*` rồi `DEL`) để các test không dính bucket của nhau.
- [ ] **Step 4: Chạy** `./mvnw -pl gateway verify` → PASS toàn bộ.
- [ ] **Step 5: Commit**: `feat(gateway): Redis token-bucket rate limiting per IP, login IP and user`

### Task 6: Smoke test end-to-end + tài liệu

**Files:**
- Create: `scripts/smoke-test.sh` (bash + curl + `jq`; tham số `BASE_URL` mặc định `http://localhost:8080`)
- Modify: `README.md` (mục "Chạy cả hệ thống", bảng route của gateway, cách chạy smoke test), `.env.example` (các biến mới trong Global Constraints)

**Interfaces:**
- Consumes: HTTP API của Task 3–5 và auth-service.
- Produces: `scripts/smoke-test.sh` với exit code `0` khi mọi bước pass, khác `0` kèm thông báo `FAIL: <bước>` (giai đoạn 4 tái sử dụng cho staging).

- [ ] **Step 1: Viết script.** Mỗi bước là một hàm `check <tên> <mã-mong-đợi> <lệnh curl>`. Các bước: register 201 → login 200 → `GET /api/demo/user` 200 → `GET /api/demo/admin` 403 → `GET /api/users/me` không có token 401 → logout 204 → `GET /api/demo/user` bằng token cũ 401 → 11 lần login sai liên tiếp, lần cuối 429 → lặp lại với `X-Forwarded-For` giả, vẫn 429.
- [ ] **Step 2: Chạy thật:** `docker compose up -d --wait`, chạy 3 service (`-Dspring-boot.run.profiles=local`), rồi `bash scripts/smoke-test.sh` → in `ALL CHECKS PASSED`, exit 0.
- [ ] **Step 3: Kiểm tra H4.** Với profile `github`, mở `http://localhost:8080/oauth2/authorization/github` → redirect sang GitHub với `redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fgithub` (cổng của gateway, không phải 8081). Bỏ qua bước này nếu chưa có OAuth App; ghi rõ trong README.
- [ ] **Step 4: Chạy lại** `./mvnw verify` (toàn bộ) → BUILD SUCCESS; Trivy fs không có HIGH/CRITICAL.
- [ ] **Step 5: Commit**: `docs: phase 3 smoke test and gateway usage`
