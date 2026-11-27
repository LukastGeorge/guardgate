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
./mvnw -pl auth-service spring-boot:run -Dspring-boot.run.profiles=local
```

Trên Windows PowerShell dùng `.\mvnw.cmd` và đặt tham số `-D...` trong dấu nháy kép.
Nếu cổng 5432 đã bị Postgres cài sẵn trên máy chiếm, đặt `POSTGRES_PORT=5433` trong `.env`.

Bật đăng nhập GitHub: tạo OAuth App (callback `http://localhost:8081/login/oauth2/code/github`),
điền `GITHUB_CLIENT_ID/SECRET` vào `.env`, chạy với `-Dspring-boot.run.profiles=local,github`
rồi mở `http://localhost:8081/oauth2/authorization/github`.

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
