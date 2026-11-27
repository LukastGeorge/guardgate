# Giai đoạn 1: Khởi tạo dự án + hạ tầng local — Implementation Plan (as-built)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Trạng thái: ĐÃ HOÀN THÀNH**, commit `27338ca`. Plan này được viết **sau** khi code (as-built) để hồ sơ dự án đầy đủ. Mỗi bước ghi đúng những gì đã làm và đã kiểm chứng; các điểm lệch so với dự kiến nằm ở cuối file.

**Goal:** Tạo khung Maven multi-module build được, và hạ tầng local (Postgres + Redis) an toàn theo mặc định.

**Architecture:** Parent POM kế thừa `spring-boot-starter-parent` và import BOM của Spring Cloud. Ba module, mỗi module là một app Spring Boot tối thiểu. docker-compose chạy Postgres và Redis, secret lấy từ `.env`, có script init tạo DB user riêng.

**Tech Stack:** Java 21, Spring Boot 3.5.7, Spring Cloud 2025.0.0, Maven 3.9 (wrapper 3.9.11), Docker Compose, PostgreSQL 17.6-alpine, Redis 7.4.6-alpine.

**Spec:** `docs/superpowers/specs/2026-11-27-guardgate-design.md`, mục 6 (Giai đoạn 1, R1.1–R1.8)

## Global Constraints

- groupId `com.guardgate`, version `0.1.0-SNAPSHOT`; package gốc `com.guardgate.{auth,gateway,demo}`.
- Cổng: gateway `8080`, auth-service `8081`, demo-service `8082`; Postgres `${POSTGRES_PORT:-5432}`, Redis `${REDIS_PORT:-6379}`, chỉ bind `127.0.0.1`.
- Mọi secret qua `.env`; biến bắt buộc dùng cú pháp `${VAR:?VAR is required}`.
- Mọi module: `server.error.include-stacktrace: never`, `include-message: never`, `include-binding-errors: never`, `include-exception: false`; Actuator chỉ mở `health,info`, `show-details: never`, bật `probes`.

## Review Focus

1. **`.env` bị commit nhầm.** `.gitignore` phải chặn `.env` và `.env.*`, nhưng vẫn cho phép `.env.example` → kiểm tra bằng `git ls-files` (Task 3).
2. **Script init có line ending CRLF khi clone trên Windows**, khiến container báo "bad interpreter" → `.gitattributes` ép LF (Task 2).
3. **Mật khẩu có ký tự đặc biệt** (`'`, `"`, `;`) làm hỏng câu SQL trong script init (SQL injection) → dùng biến psql `:'var'` / `:"var"` (Task 2).
4. **Thiếu biến môi trường** khiến compose chạy với mật khẩu rỗng → `${VAR:?}` dừng ngay (Task 2).
5. **Cổng 5432 đã bị chiếm** bởi Postgres cài sẵn trên máy → đổi bằng `POSTGRES_PORT` (Task 2, xem mục Lệch).

---

### Task 1: Khung Maven multi-module

**Files:**
- Create: `pom.xml`, `{auth-service,gateway,demo-service}/pom.xml`
- Create: `auth-service/src/main/java/com/guardgate/auth/AuthServiceApplication.java`, `gateway/.../GatewayApplication.java`, `demo-service/.../DemoServiceApplication.java`
- Create: `{module}/src/main/resources/application.yml` (cổng qua biến `*_PORT`, cấu hình lỗi và Actuator theo Global Constraints)
- Test: `{module}/src/test/java/.../*ApplicationTests.java` (`@SpringBootTest contextLoads`)

**Interfaces:**
- Produces: artifact `guardgate-parent` (packaging `pom`) với `<modules>` gồm 3 module; property `spring-cloud.version=2025.0.0`; `maven-enforcer-plugin` execution `enforce-environment` với các rule `requireJavaVersion [21,)`, `requireMavenVersion [3.9,)`, `dependencyConvergence`.
- Dependency từng module: auth-service và demo-service dùng `spring-boot-starter-web` + `actuator`; gateway dùng `spring-cloud-starter-gateway-server-webflux` + `actuator` (**không** dùng starter-web).

- [x] **Step 1: Viết smoke test** `contextLoads()` cho từng module.
- [x] **Step 2: Chạy** `mvn -B -q verify` khi chưa có class Application → FAIL (thiếu `@SpringBootConfiguration`).
- [x] **Step 3: Tạo** parent POM, POM của 3 module, class `*Application` (`@SpringBootApplication`), `application.yml`.
- [x] **Step 4: Chạy** `mvn -B -q verify` → `EXIT=0`, 3 test PASS. Kết quả này cũng xác nhận Boot 3.5.7 và Cloud 2025.0.0 tồn tại trên Maven Central, và artifact `spring-cloud-starter-gateway-server-webflux` hợp lệ.
- [x] **Step 5: Commit** (gộp vào commit `27338ca` ở Task 3).

### Task 2: Hạ tầng local an toàn (docker-compose)

**Files:**
- Create: `docker-compose.yml`, `infra/postgres/init/01-create-auth-db.sh`, `.env.example`, `.gitignore`, `.gitattributes`, `.editorconfig`

**Interfaces:**
- Produces (dùng cho các giai đoạn sau):
  - Service `postgres` (container `guardgate-postgres`, image `postgres:17.6-alpine`), DB `${AUTH_DB_NAME}` thuộc sở hữu của `${AUTH_DB_USER}`; `POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256"`.
  - Service `redis` (container `guardgate-redis`, image `redis:7.4.6-alpine`) với `--requirepass`, `--appendonly yes`, `--protected-mode yes`, và rename các lệnh `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG` thành `""`; mật khẩu nằm trong biến `REDISCLI_AUTH`.
  - Network `guardgate-backend`; volume `postgres-data`, `redis-data`.
  - Biến `.env`: `POSTGRES_ADMIN_USER`, `POSTGRES_ADMIN_PASSWORD`, `POSTGRES_PORT`, `AUTH_DB_NAME`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD`, `REDIS_PASSWORD`, `REDIS_PORT`, `GATEWAY_PORT`, `AUTH_SERVICE_PORT`, `DEMO_SERVICE_PORT`.

- [x] **Step 1: Viết tiêu chí kiểm tra** (hạ tầng không có unit test, nên dùng lệnh kiểm chứng):
  - `docker compose config --quiet` → exit 0
  - `docker compose up -d --wait` → 2 container `healthy`
  - `docker compose logs postgres | grep "Created database"` → có dòng `Created database 'guardgate_auth' owned by 'auth_service'`
  - `psql -U auth_service -d postgres -c "create database x;"` → bị từ chối
  - `REDISCLI_AUTH= redis-cli ping` → `NOAUTH`
- [x] **Step 2: Viết** `docker-compose.yml` (healthcheck `pg_isready` và `redis-cli ping`, interval 5s; ports `127.0.0.1:…`; `security_opt: no-new-privileges:true`).
- [x] **Step 3: Viết** `01-create-auth-db.sh`: `set -eu`; `psql -v ON_ERROR_STOP=1 -v app_db=… -v app_user=… -v app_password=…` + heredoc `<<'EOSQL'` (có nháy, để shell không thay biến); role `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION`; `REVOKE ALL ON DATABASE … FROM PUBLIC`.
- [x] **Step 4: Viết** `.gitattributes` (`* text=auto eol=lf`, `*.cmd`/`*.bat` dùng CRLF, `*.jar binary`), `.gitignore` (`.env`, `.env.*`, `!.env.example`, `*.pem`, `*.key`, `*.p12`, `*.jks`, `target/`, IDE, report của các công cụ quét), `.editorconfig`.
- [x] **Step 5: Chạy kiểm tra Step 1.** `config --quiet` → exit 0. `up --wait` chạy được sau khi đổi `POSTGRES_PORT=5433` (xem mục Lệch) → cả 2 healthy, có log `Created database`.

### Task 3: Maven Wrapper, README, git

**Files:**
- Create: `mvnw`, `mvnw.cmd`, `.mvn/wrapper/maven-wrapper.properties` (Maven 3.9.11), `README.md`

- [x] **Step 1: Sinh wrapper**: `mvn -N wrapper:wrapper -Dmaven=3.9.11`.
- [x] **Step 2: Bật quyền thực thi** trong git (Windows không giữ bit này): `git update-index --chmod=+x mvnw infra/postgres/init/01-create-auth-db.sh`.
- [x] **Step 3: Kiểm tra** `git ls-files | grep .env` → chỉ có `.env.example`.
- [x] **Step 4: Commit** `27338ca chore: bootstrap multi-module project and local infrastructure`; tạo repo public `LukastGeorge/guardgate` và push.

---

## Lệch so với dự kiến & bài học

| # | Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|---|
| L1.1 | `docker compose up` lỗi "ports are not available: 5432" | Máy dev đã có sẵn một PostgreSQL chiếm cổng 5432 | Đặt `POSTGRES_PORT=5433` trong `.env`; mọi chỗ (compose, datasource) đều đọc biến này nên không phải sửa code |
| L1.2 | Lệnh `java` trên PATH là Java 8 | Máy có nhiều JDK | Maven chạy bằng JDK 25 và `release=21` vẫn build đúng; khuyến nghị cài JDK 21 cho khớp image Docker |
| L1.3 | Docker Desktop chưa chạy khi kiểm tra lần đầu | | Kiểm tra cú pháp bằng `docker compose config` trước, chạy thật sau |
