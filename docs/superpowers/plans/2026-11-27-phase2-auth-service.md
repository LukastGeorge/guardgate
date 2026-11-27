# Giai đoạn 2: auth-service — Implementation Plan (as-built)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Trạng thái: ĐÃ HOÀN THÀNH**, commit `0be924f`. Plan viết **sau** khi code (as-built). Các bước `[x]` đã làm và đã kiểm chứng. Hạng mục còn thiếu (H1–H6) chuyển sang Task 1 của plan giai đoạn 3.

**Goal:** Dịch vụ xác thực: đăng ký, đăng nhập JWT, refresh token rotation, logout có thu hồi, RBAC, khoá tài khoản, audit log, đăng nhập GitHub.

**Architecture:** Spring MVC + Spring Security với 2 filter chain (OAuth2 login có session ngắn hạn; REST API stateless dùng Bearer JWT). JWT ký RS256 bằng Nimbus, public key công bố qua JWKS. Postgres (JPA + Flyway) lưu user, refresh token, audit log; Redis lưu denylist `jti`.

**Tech Stack:** Spring Boot 3.5.7, Spring Security 6.5 (`oauth2-resource-server`, `oauth2-client`), Nimbus JOSE 9.37.4, Spring Data JPA, Flyway 11 (`flyway-database-postgresql`), Spring Data Redis (Lettuce), JUnit 5, Mockito, Testcontainers 1.21.4.

**Spec:** `docs/superpowers/specs/2026-11-27-guardgate-design.md`, mục 3.1, 3.3, 4 (D1–D4), 6 (Giai đoạn 2: R2.1–R2.9, S2.1–S2.9)

## Global Constraints

- Package gốc `com.guardgate.auth`, chia theo nghiệp vụ: `auth`, `user`, `audit`, `oauth2`, `security`, `config`, `web`.
- JWT: header `kid` = thumbprint; claims `iss`, `aud` (mảng), `sub` (UUID), `iat`, `nbf`, `exp`, `jti` (UUID), `roles` (mảng). **Không** đưa email hay dữ liệu cá nhân vào token.
- TTL: access `${JWT_ACCESS_TOKEN_TTL:15m}`, refresh `${JWT_REFRESH_TOKEN_TTL:7d}`; lockout `${LOGIN_MAX_FAILED_ATTEMPTS:5}` lần / `${LOGIN_LOCK_DURATION:15m}`; BCrypt `${BCRYPT_STRENGTH:12}` (test dùng 4).
- Redis key: `guardgate:revoked-jti:{jti}`, TTL = `exp − now`.
- Thông báo lỗi cố định: `Invalid email or password` (401), `Invalid or expired refresh token` (401), `Email is already registered` (409), `Authentication is required` (401), `You do not have permission to access this resource` (403), `Request validation failed` (400), `An unexpected error occurred` (500 + `errorId`).
- Test: unit `*Test` (Surefire), integration `*IT` (Failsafe, `postgres:17.6-alpine` + `redis:7.4.6-alpine` qua Testcontainers `@ServiceConnection`).

## Review Focus

1. **Brute-force song song:** 20 lần đăng nhập sai gửi cùng lúc phải bị đếm đủ và khoá đúng một lần. Code đã dùng UPDATE nguyên tử (Task 4), nhưng **chưa có test đồng thời** → H5, chuyển sang GĐ3 Task 1.
2. **Hai request refresh song song cùng một token:** chỉ một cái được thành công (`SELECT … FOR UPDATE`, Task 5) → **chưa có test đồng thời** → H5.
3. **Mật khẩu đa byte** (emoji, tiếng Việt có dấu) ≤ 64 ký tự nhưng > 72 byte → BCrypt lỗi → H3, chuyển sang GĐ3 Task 1.
4. **Email khác hoa/thường hoặc có khoảng trắng** phải là cùng một tài khoản → đã test (`duplicateEmailIsRejectedCaseInsensitively`, `loginWithCorrectPasswordIssuesTokens…` dùng `"  Alice@Example.COM "`).
5. **Luồng GitHub** (email chưa xác minh, email trùng tài khoản local, GitHub API lỗi) → **chưa có test tự động** → H6.

---

### Task 1: Dependency, cấu hình, schema

**Files:**
- Modify: `auth-service/pom.xml` (web, validation, security, oauth2-resource-server, oauth2-client, data-jpa, flyway-core, flyway-database-postgresql, postgresql, data-redis, actuator; test: spring-security-test, spring-boot-testcontainers, testcontainers junit-jupiter + postgresql; plugin failsafe), `pom.xml` (ghim `nimbus-jose-jwt` 9.37.4, `testcontainers.version` 1.21.4)
- Create: `config/JwtProperties.java`, `AuthSecurityProperties.java`, `BootstrapAdminProperties.java`, `GitHubProperties.java`, `CoreConfig.java`
- Create: `src/main/resources/application.yml`, `application-local.yml`, `application-github.yml`, `db/migration/V1__init_schema.sql`
- Modify: `AuthServiceApplication.java` (`@ConfigurationPropertiesScan`, `@EnableScheduling`)

**Interfaces:**
- Produces:
  - `record JwtProperties(@NotBlank String issuer, @NotBlank String audience, @NotBlank String privateKey, @NotNull Duration accessTokenTtl, @NotNull Duration refreshTokenTtl)`, prefix `guardgate.jwt`; `toString()` không in key
  - `record AuthSecurityProperties(@Min(1) int maxFailedAttempts, @NotNull Duration lockDuration, @Min(4) @Max(31) int bcryptStrength)`, prefix `guardgate.security`
  - `record BootstrapAdminProperties(String email, String password)` với `isConfigured()`; `record GitHubProperties(@NotBlank String apiBaseUrl)`
  - Bean `Clock` (UTC), `PasswordEncoder` = `DelegatingPasswordEncoder("bcrypt", {bcrypt: BCryptPasswordEncoder(strength)})`
  - Bảng `users`, `refresh_tokens`, `audit_logs` (xem sơ đồ ER trong spec), có constraint `ck_users_email_lowercase`, `ck_users_role`, `ck_users_failed_attempts`
  - Profile `local` import `optional:file:.env[.properties]` và `optional:file:../.env[.properties]`

- [x] **Step 1: Kiểm chứng bằng compile**: `./mvnw -pl auth-service -am compile` → lần đầu FAIL do enforcer `dependencyConvergence` (nimbus 9.37.3 và 9.37.4) → ghim version trong `dependencyManagement` → PASS.
- [x] **Step 2: Kiểm chứng schema**: `ddl-auto: validate` + Flyway chạy trong mọi IT (Task 7) → Hibernate xác nhận entity khớp bảng.

### Task 2: Khoá RSA, JWT encoder/decoder, JWKS

**Files:**
- Create: `security/RsaKeyLoader.java`, `config/JwtConfig.java`, `auth/JwksController.java`
- Test: `security/RsaKeyLoaderTest.java`, `support/TestKeys.java`

**Interfaces:**
- Produces:
  - `RsaKeyLoader.load(String encodedKey): RSAKey`: nhận Base64 PKCS#8 DER hoặc PEM (kể cả chuỗi `"\n"` dạng literal); từ chối khoá < 2048 bit, khoá không phải RSA, Base64 hỏng; thông báo lỗi không chứa nội dung khoá
  - Bean `RSAKey jwtSigningKey`, `JwtEncoder` (Nimbus, `ImmutableJWKSet`), `JwtDecoder` (chỉ RS256; validator: mặc định + issuer, audience, `NotRevokedValidator`), `JwtAuthenticationConverter` (claim `roles` → `ROLE_`)
  - Hằng `JwtConfig.ROLES_CLAIM = "roles"`
  - `GET /.well-known/jwks.json` → `JWKSet(key.toPublicJWK()).toJSONObject()`

- [x] **Step 1: Viết test** `RsaKeyLoaderTest`: `loadsBase64Pkcs8KeyAndDerivesPublicKey`, `loadsPemWithEscapedNewlines`, `rejectsKeysShorterThan2048Bits` (thông báo chứa `"too short"`), `rejectsNonRsaKeys` (khoá EC 256), `errorMessageNeverContainsKeyMaterial`.
- [x] **Step 2: Cài đặt** → `./mvnw -pl auth-service test` → 5/5 PASS.
- [x] **Step 3: Kiểm chứng IT**: `jwksExposesOnlyPublicKeyMaterial` (`kty=RSA`, `alg=RS256`, có `n`, không có `d`, `p`).

### Task 3: User, đăng ký, validation, xử lý lỗi tập trung

**Files:**
- Create: `user/Role.java`, `User.java`, `UserRepository.java`, `EmailNormalizer.java`, `PasswordPolicy.java`, `UserResponse.java`, `UserController.java`
- Create: `auth/dto/RegisterRequest.java`, `auth/EmailAlreadyRegisteredException.java`, `InvalidPasswordException.java`
- Create: `web/ApiException.java`, `ResourceNotFoundException.java`, `GlobalExceptionHandler.java`, `ClientInfo.java`, `PageResponse.java`

**Interfaces:**
- Produces:
  - `User.local(String normalizedEmail, String passwordHash, Role role)`, `User.github(String normalizedEmail, long githubId)`, `isLockedAt(Instant)`, `hasPassword()`, `changePasswordHash(String)`; `toString()` không có hash
  - `UserRepository`: `findByEmail`, `findByGithubId`, `existsByEmail`, `incrementFailedAttempts(UUID)`, `lockIfThresholdReached(UUID, int, Instant): int`, `resetLoginFailures(UUID)` (cả 3 là `@Modifying` JPQL nguyên tử)
  - `PasswordPolicy.MIN_LENGTH = 12`, `MAX_LENGTH = 64`
  - `abstract class ApiException(HttpStatus, String clientMessage)`: không ghi stack trace
  - `record ClientInfo(String ipAddress, String userAgent)` + `from(HttpServletRequest)`
  - `POST /api/auth/register` → 201 `UserResponse{id,email,role,createdAt}`; `GET /api/users/me` → lấy theo `sub`

- [x] **Step 1: Viết IT**: `registerLoginAndReadOwnProfile` (không có `passwordHash` trong response), `registerIgnoresRoleInPayload`, `duplicateEmailIsRejectedCaseInsensitively` (409), `invalidInputReturnsProblemDetailWithoutEchoingValues`, `malformedJsonDoesNotLeakParserDetails`.
- [x] **Step 2: Viết unit test** `AuthServiceTest.registerRejectsPasswordEqualToEmail`, `registerRejectsDuplicateEmailCaseInsensitively`.
- [x] **Step 3: Cài đặt** → PASS.

### Task 4: Đăng nhập, lockout, audit log

**Files:**
- Create: `auth/AuthService.java`, `LoginAttemptService.java`, `InvalidCredentialsException.java`, `auth/dto/LoginRequest.java`, `TokenResponse.java`
- Create: `audit/AuditEventType.java`, `AuditLog.java`, `AuditLogRepository.java`, `AuditService.java`
- Test: `auth/AuthServiceTest.java`, `audit/AuditServiceTest.java`

**Interfaces:**
- Produces:
  - `AuthService.login(LoginRequest, ClientInfo): TokenResponse` theo thứ tự: tìm user → (không có: BCrypt với hash giả, audit, 401) → BCrypt → (đang khoá: audit, 401, không tăng bộ đếm) → (sai/disabled: `recordFailure`, audit `LOGIN_FAILURE`, nếu bị khoá thì audit thêm `ACCOUNT_LOCKED`, 401) → `reset` nếu cần → nâng cấp hash → `issueFor` → audit `LOGIN_SUCCESS`
  - `LoginAttemptService.recordFailure(UUID): boolean` (true = vừa bị khoá), `reset(UUID)`; cả hai `REQUIRES_NEW`
  - `AuditService.record(AuditEventType, UUID userId, String email, ClientInfo, boolean success, String details)`, `REQUIRES_NEW`; `static sanitize(String, int)` thay ký tự điều khiển bằng `_` rồi cắt theo độ dài
  - `AuditEventType`: `USER_REGISTERED, LOGIN_SUCCESS, LOGIN_FAILURE, ACCOUNT_LOCKED, ACCOUNT_UNLOCKED, TOKEN_REFRESHED, REFRESH_TOKEN_REUSE_DETECTED, LOGOUT, OAUTH2_LOGIN_SUCCESS, OAUTH2_LOGIN_FAILURE`

- [x] **Step 1: Viết unit test** `AuthServiceTest`: `loginWithCorrectPasswordIssuesTokensAndAuditsSuccess`, `wrongPasswordRecordsFailureAndAuditsLockWhenThresholdIsReached`, `lockedAccountIsRejectedEvenWithCorrectPassword`, `expiredLockIsClearedOnSuccessfulLogin`, `unknownEmailStillPerformsPasswordHashToEqualiseTiming`; `AuditServiceTest`: `sanitizeNeutralisesLogInjection`, `sanitizeTruncatesToColumnLength`, `sanitizeKeepsNull`.
- [x] **Step 2: Viết IT**: `wrongPasswordAndUnknownEmailReturnIdenticalErrors`, `accountIsLockedAfterFiveFailedAttempts` (đúng 1 `ACCOUNT_LOCKED`, 6 `LOGIN_FAILURE`).
- [x] **Step 3: Cài đặt** → PASS.

### Task 5: Refresh token rotation + phát hiện dùng lại

**Files:**
- Create: `auth/RefreshToken.java`, `RefreshTokenRepository.java`, `RefreshTokenService.java`, `TokenService.java`, `InvalidRefreshTokenException.java`, `auth/dto/RefreshRequest.java`
- Test: `auth/RefreshTokenServiceTest.java`

**Interfaces:**
- Produces:
  - `RefreshTokenService.issue(User, UUID familyId): String` (32 byte `SecureRandom`, Base64url không padding = 43 ký tự)
  - `RefreshTokenService.rotate(String raw, ClientInfo): Rotation(User user, String refreshToken)`: `@Transactional(noRollbackFor = InvalidRefreshTokenException.class)`; token đã rotate → `revokeFamily` + audit + 401; đã thu hồi / hết hạn / user disabled hoặc bị khoá → 401
  - `RefreshTokenService.revokeFamily(String raw, UUID ownerId)`; `purgeExpired()` (`@Scheduled` lúc 03:00, xoá token hết hạn quá 1 ngày); `static hash(String)` = SHA-256 hex
  - `RefreshTokenRepository.findByTokenHashForUpdate` (`PESSIMISTIC_WRITE`, join fetch user), `revokeFamily(UUID, Instant): int`, `deleteExpiredBefore(Instant): int`
  - `TokenService.issueFor(User): TokenResponse` (family mới), `withRefreshToken(User, String): TokenResponse`

- [x] **Step 1: Viết unit test** `RefreshTokenServiceTest`: `rotateIssuesNewTokenInSameFamilyAndMarksOldOneRotated`, `reusingRotatedTokenRevokesWholeFamily`, `expiredTokenIsRejectedWithoutRotation`, `tokenOfLockedUserIsRejected`, `unknownTokenIsRejected`, `hashIsDeterministicSha256Hex` (`"abc"` → `ba7816bf…15ad`).
- [x] **Step 2: Viết IT** `refreshRotatesTokenAndReuseRevokesWholeFamily` (R1 → R2; dùng lại R1 → 401; R2 → 401; đúng 1 audit reuse).
- [x] **Step 3: Cài đặt** → PASS.

### Task 6: Logout + thu hồi access token

**Files:**
- Create: `security/AccessTokenDenylist.java`, `NotRevokedValidator.java`, `auth/dto/LogoutRequest.java`
- Modify: `AuthService.java` (`logout`), `auth/AuthController.java`

**Interfaces:**
- Produces: `AccessTokenDenylist.KEY_PREFIX = "guardgate:revoked-jti:"`, `revoke(String jti, Instant expiresAt)`, `isRevoked(String jti)`; `NotRevokedValidator` thiếu jti → lỗi; Redis lỗi → lỗi (fail-closed); `POST /api/auth/logout` → 204.

- [x] **Step 1: Viết IT** `logoutRevokesAccessTokenAndRefreshToken` (sau logout, `/me` → 401 và refresh → 401).
- [x] **Step 2: Cài đặt** → PASS. Smoke test thật: sau logout có đúng 1 key `guardgate:revoked-jti:*` trong Redis.

### Task 7: Security filter chain, RBAC, API admin, header

**Files:**
- Create: `config/SecurityConfig.java`, `security/ProblemDetailResponseWriter.java`, `ProblemDetailAuthenticationEntryPoint.java`, `ProblemDetailAccessDeniedHandler.java`
- Create: `audit/AdminController.java`, `AuditLogResponse.java`, `user/AdminBootstrap.java`
- Test: `AuthFlowIT.java`, `support/AbstractIntegrationTest.java`

**Interfaces:**
- Produces:
  - Chain `@Order(1)` `oauth2LoginChain` (matcher `/oauth2/**`, `/login/oauth2/**`): không có `ClientRegistrationRepository` thì `denyAll`
  - Chain `@Order(2)` `apiChain`: CSRF tắt, `STATELESS`, permitAll `POST /api/auth/{register,login,refresh}`, `GET /.well-known/jwks.json`, `/actuator/health/**`, `/actuator/info`, `/error`; `/api/admin/**` → ADMIN; còn lại `authenticated()`
  - Header: CSP `default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, HSTS `max-age=31536000; includeSubDomains`
  - `GET /api/admin/audit-logs?eventType=&page=&size=&sort=` → `PageResponse<AuditLogResponse>` (mặc định 20 bản ghi, `createdAt DESC`, tối đa 100); `POST /api/admin/users/{id}/unlock` → 204
  - `AbstractIntegrationTest`: hằng `ADMIN_EMAIL = "admin@guardgate.test"`, `ADMIN_PASSWORD`; khoá RSA sinh ngẫu nhiên cho mỗi lần chạy test

- [x] **Step 1: Viết IT**: `protectedEndpointWithoutTokenReturns401WithChallenge`, `userCannotAccessAdminEndpoints`, `adminCanReadAuditLogsFilteredByType` (+ sort sai → 400), `adminCanUnlockAccount`, `tokenWithForgedAdminRoleIsRejected` (sửa payload), `unsignedAlgNoneTokenIsRejected`, `responsesCarrySecurityHeaders`, `sensitiveActuatorEndpointsAreNotExposed` (`env`, `heapdump`, `configprops` → 404).
- [x] **Step 2: Cài đặt** → PASS.

### Task 8: Đăng nhập GitHub (profile `github`)

**Files:**
- Create: `oauth2/OAuth2AccountService.java`, `GitHubOAuth2UserService.java`, `OAuth2LoginSuccessHandler.java`, `OAuth2LoginFailureHandler.java`

**Interfaces:**
- Produces:
  - `OAuth2AccountService.findOrCreateGithubUser(long githubId, String verifiedEmail): User`: email đã thuộc tài khoản local → `OAuth2AuthenticationException("account_exists")`
  - `GitHubOAuth2UserService` gọi `GET {apiBaseUrl}/user/emails`, chọn email `primary && verified`; attribute `guardgate_user_id`
  - Success handler: huỷ session, trả `TokenResponse` (JSON, `Cache-Control: no-store`); failure handler: 401 problem + audit

- [x] **Step 1: Viết IT** `oauth2EndpointsAreDisabledWithoutGithubProfile` (401).
- [x] **Step 2: Cài đặt** → PASS.
- [ ] **Step 3 (còn nợ → H6):** unit test cho `OAuth2AccountService` (tìm theo githubId; tạo mới; email trùng → `account_exists`) và `GitHubOAuth2UserService.fetchVerifiedPrimaryEmail` (mock server: chỉ có email chưa xác minh → `verified_email_required`; API 500 → `github_api_error`).

### Task 9: Chạy local và kiểm chứng end-to-end

**Files:**
- Modify: `.env.example` (khối JWT, lockout, bootstrap admin, GitHub), `README.md` (cách chạy, bảng API)

- [x] **Step 1:** `./mvnw verify` → 21 unit + 19 IT (`AuthFlowIT` chạy 61 giây) + module khác → BUILD SUCCESS.
- [x] **Step 2:** `docker compose up -d --wait` → `./mvnw -pl auth-service spring-boot:run -Dspring-boot.run.profiles=local` → `Started AuthServiceApplication`.
- [x] **Step 3: Smoke test bằng curl**: register 201 (gửi kèm `role: ADMIN` nhưng nhận `USER`) → login 200 → payload JWT `{sub, aud, nbf, roles, iss, exp, iat, jti}` không có email → `/me` 200 → admin 403 → refresh 200 → dùng lại refresh cũ 401 → logout 204, token cũ 401 → validation 400 → đủ 4 security header.
- [x] **Step 4: Commit** `0be924f feat(auth-service): JWT auth with refresh rotation, RBAC, lockout and audit log`.

---

## Lệch so với dự kiến & bài học

| # | Hiện tượng | Nguyên nhân | Cách xử lý / Bài học |
|---|---|---|---|
| L2.1 | Enforcer FAIL `dependencyConvergence` | `oauth2-resource-server` kéo nimbus 9.37.4, `oauth2-client` (qua oidc-sdk) kéo 9.37.3 | Ghim 9.37.4 trong `dependencyManagement`. Rule này phát hiện sớm loại xung đột âm thầm gây lỗi lúc chạy |
| L2.2 | App không khởi động: "not a valid PKCS#8 RSA key" | OpenSSL 3.5: `genpkey -outform DER` xuất **PKCS#1**, không phải PKCS#8 | Thêm `openssl pkcs8 -topk8 -nocrypt -outform DER`; thông báo lỗi giờ có gợi ý cách chuyển. **Bài học:** kiểm chứng pipeline sinh khoá bằng một khoá dùng một lần, không đụng tới secret thật |
| L2.3 | Testcontainers có thể không chạy với Docker 29 | Docker 29 nâng API tối thiểu lên 1.44 | Ghim Testcontainers 1.21.4 |
| L2.4 | Kế hoạch ban đầu dùng `AuthServiceApplicationTests.contextLoads` | Context cần DB + key | Xoá file đó, thay bằng `AuthFlowIT` (Testcontainers) |
| L2.5 | Rà soát sau khi xong phát hiện H1–H6 | Chưa chạy Trivy và chưa rà soát thủ công trước khi commit | Từ giai đoạn 3: chạy Trivy/Semgrep **trong** quy trình của mỗi task, không đợi tới cuối; giai đoạn 4 tự động hoá việc này trong CI |
