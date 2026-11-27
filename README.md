# GuardGate

API Gateway + Auth Service với pipeline DevSecOps hoàn chỉnh (Java 21, Spring Boot 3).

> README đầy đủ (sơ đồ kiến trúc, bảng OWASP Top 10) sẽ được viết ở giai đoạn 7.

## Cấu trúc

```
guardgate/
├── pom.xml                  # Parent POM (multi-module, Spring Boot + Spring Cloud BOM)
├── auth-service/            # :8081 – đăng ký, đăng nhập, JWT, RBAC
├── gateway/                 # :8080 – Spring Cloud Gateway, xác thực JWT, rate limit
├── demo-service/            # :8082 – service mẫu (public / user / admin)
├── infra/postgres/init/     # Script tạo DB + user riêng cho auth-service
├── docker-compose.yml       # Postgres + Redis cho môi trường local
└── .env.example             # Mẫu biến môi trường (copy thành .env)
```

## Chạy local

Yêu cầu: JDK 21+, Docker Desktop.

```bash
cp .env.example .env            # rồi đổi toàn bộ mật khẩu
docker compose up -d --wait     # Postgres + Redis, đợi đến khi healthy
./mvnw verify                   # build + test tất cả module (Windows: mvnw.cmd verify)
./mvnw -pl auth-service spring-boot:run
```
