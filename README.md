# GuardGate

API Gateway + Auth Service với pipeline DevSecOps hoàn chỉnh (Java 21, Spring Boot 3).

> README đầy đủ (sơ đồ kiến trúc, bảng OWASP Top 10) sẽ được viết ở giai đoạn 7.

## Cấu trúc

```
guardgate/
├── pom.xml                  # Parent POM (multi-module, Spring Boot + Spring Cloud BOM)
├── auth-service/            # :8081 – đăng ký, đăng nhập, JWT, refresh rotation, RBAC, lockout, audit
├── gateway/                 # :8080 – Spring Cloud Gateway, xác thực JWT, rate limit
├── demo-service/            # :8082 – service mẫu (public / user / admin)
├── infra/postgres/init/     # Script tạo DB + user riêng cho auth-service
├── docker-compose.yml       # Postgres + Redis cho môi trường local
└── .env.example             # Mẫu biến môi trường (copy thành .env)
```

## Chạy local

Yêu cầu: JDK 21+, Docker Desktop, OpenSSL (có sẵn trong Git Bash).

```bash
cp .env.example .env
# Đổi toàn bộ mật khẩu, rồi sinh khoá ký JWT và dán vào JWT_PRIVATE_KEY:
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | openssl pkcs8 -topk8 -nocrypt -outform DER | openssl base64 -A

docker compose up -d --wait                       # Postgres + Redis
./mvnw test                                       # unit test (không cần Docker)
./mvnw verify                                     # + integration test (Testcontainers, cần Docker)
```

Trên Windows PowerShell dùng `.\mvnw.cmd` và đặt tham số `-D...` trong dấu nháy kép.
Nếu cổng 5432 đã bị Postgres cài sẵn trên máy chiếm, đặt `POSTGRES_PORT=5433` trong `.env`.

### Chạy cả hệ thống

Mỗi service một terminal; profile `local` đọc `.env` ở thư mục gốc:

```bash
./mvnw -pl auth-service spring-boot:run -Dspring-boot.run.profiles=local   # :8081
./mvnw -pl demo-service spring-boot:run -Dspring-boot.run.profiles=local   # :8082
./mvnw -pl gateway      spring-boot:run -Dspring-boot.run.profiles=local   # :8080 (điểm vào duy nhất)
bash scripts/smoke-test.sh                                                 # kiểm tra end-to-end qua gateway
```

Smoke test kiểm tra: đăng ký, đăng nhập, phân quyền USER/ADMIN, thu hồi token khi logout, rate limit đăng nhập
(lần thứ 11 trong một phút bị 429) và việc giả mạo `X-Forwarded-For` không có tác dụng. Rate limit tính theo phút,
nên nếu chạy lại script ngay lập tức thì bước đăng ký có thể bị 429: chờ khoảng 1 phút rồi chạy lại.

**Đăng nhập GitHub:** tạo OAuth App với callback **qua gateway** `http://localhost:8080/login/oauth2/code/github`,
điền `GITHUB_CLIENT_ID/SECRET` vào `.env`, chạy auth-service với `-Dspring-boot.run.profiles=local,github`
rồi mở `http://localhost:8080/oauth2/authorization/github`.

## Gateway (:8080)

| Route | Đích | Quyền tại gateway |
|---|---|---|
| `POST /api/auth/{register,login,refresh}` | auth-service | public, rate limit ≈10 request/phút/IP |
| `/api/auth/**` khác (logout) | auth-service | cần token |
| `/api/users/**` | auth-service | cần token |
| `/api/admin/**` | auth-service | ADMIN |
| `/oauth2/**`, `/login/oauth2/**` | auth-service | public (luồng GitHub) |
| `GET /api/demo/public` | demo-service | public |
| `/api/demo/admin/**` | demo-service | ADMIN |
| `/api/demo/**` khác | demo-service | cần token |
| mọi path khác | không có route | 401 (không token) / 404 |

Gateway xác thực JWT (JWKS của auth-service + denylist Redis), rate limit bằng token bucket trong Redis
(theo IP, theo IP cho các endpoint đăng nhập, theo user), thay `X-Forwarded-*` của client bằng giá trị thật,
áp CORS allow-list, giới hạn body 1 MB, timeout 5 giây, và trả mọi lỗi dạng `application/problem+json`.
Các service phía sau vẫn tự xác thực lại JWT (defense in depth).

## Auth Service API

| Method | Path | Quyền | Mô tả |
|---|---|---|---|
| POST | `/api/auth/register` | public | Đăng ký (`email`, `password` 12–64 ký tự) |
| POST | `/api/auth/login` | public | Trả `accessToken` (JWT RS256, 15 phút) + `refreshToken` (7 ngày) |
| POST | `/api/auth/refresh` | public | Đổi refresh token lấy cặp token mới (rotation) |
| POST | `/api/auth/logout` | USER | Thu hồi access token (Redis) + family của refresh token |
| GET | `/api/users/me` | USER | Thông tin tài khoản hiện tại |
| GET | `/api/admin/audit-logs` | ADMIN | Audit log, lọc `?eventType=`, phân trang `?page=&size=` |
| POST | `/api/admin/users/{id}/unlock` | ADMIN | Mở khoá tài khoản |
| GET | `/.well-known/jwks.json` | public | Public key để gateway xác thực JWT |
| GET | `/oauth2/authorization/github` | public | Đăng nhập GitHub (profile `github`) |

Mọi lỗi trả về dạng [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) (`application/problem+json`).

```bash
curl -X POST localhost:8081/api/auth/register -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"Correct-Horse-Battery-1"}'
curl -X POST localhost:8081/api/auth/login -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"Correct-Horse-Battery-1"}'
curl localhost:8081/api/users/me -H "Authorization: Bearer <accessToken>"
```
