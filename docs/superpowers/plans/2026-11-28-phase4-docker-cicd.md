# Giai đoạn 4: Docker + CI/CD DevSecOps — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Trạng thái: CHỜ DUYỆT.** Dùng các quyết định D14, D15, D18 đang ở trạng thái 🟡 trong spec; cần được chốt trước khi code.

**Goal:** Mọi service chạy trong container non-root tối giản; mỗi push/PR đi qua pipeline build → test → SAST → secret scan → dependency scan → image scan → (main) push + ký → staging → DAST. Pipeline FAIL khi có lỗ hổng HIGH/CRITICAL.

**Architecture:** Một `Dockerfile` dùng chung ở thư mục gốc, nhận `ARG MODULE` (multi-stage: Maven build → tách layered jar → JRE alpine, uid 10001). docker-compose chạy đủ 5 container, chỉ publish cổng của gateway. GitHub Actions có một workflow `ci.yml` gồm các job với quyền tối thiểu, mọi action được pin theo commit SHA. Staging là docker compose chạy ngay trong runner (D15, chưa có Helm); ZAP baseline quét gateway.

**Tech Stack:** Docker (BuildKit), `eclipse-temurin:21-jre-alpine`, `maven:3.9-eclipse-temurin-21`, GitHub Actions, Semgrep, Gitleaks, Trivy, OWASP ZAP (`ghcr.io/zaproxy/zaproxy:stable`), GHCR, Syft/Trivy SBOM (CycloneDX), cosign keyless, Dependabot.

**Spec:** `docs/superpowers/specs/2026-11-27-guardgate-design.md`, mục 4 (D14, D15, D18) và mục 6 (Giai đoạn 4)

## Global Constraints

- Image: `ghcr.io/lukastgeorge/guardgate-{auth-service,gateway,demo-service}`, tag = commit SHA đầy đủ (thêm `latest` chỉ trên `main`).
- Runtime: user `10001:10001`, không có shell trong ENTRYPOINT (exec form), `-XX:MaxRAMPercentage=75`, không có Maven, source hay `.env` trong image.
- Cổng container: gateway 8080, auth-service 8081, demo-service 8082. Compose chỉ publish `127.0.0.1:8080`.
- Ngưỡng chặn: Trivy `--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1`; Semgrep `--error --severity ERROR`; Gitleaks có bất kỳ leak nào; ZAP có alert `riskcode == 3` (High).
- Workflow: `permissions: contents: read` ở mức top-level, mỗi job chỉ xin thêm quyền nó cần; **không** dùng `pull_request_target`; mọi `uses:` pin theo SHA 40 ký tự hex kèm comment ghi tag.
- Không có `|| true` hay `continue-on-error: true` trên bước quét bảo mật.

## Review Focus

1. **Secret lọt vào image** (`COPY . .` kéo theo `.env`, khoá, thư mục `target/`) → `.dockerignore` + test trong Task 1 tìm `.env`/`*.pem` trong image.
2. **Container chạy root hoặc filesystem ghi được** → Task 1 kiểm tra `id -u`; Task 2 chạy với `read_only: true` + `tmpfs /tmp` và smoke test vẫn pass.
3. **Scanner bị crash nhưng job vẫn xanh** (ví dụ ZAP không tạo được report, hoặc jq đọc file rỗng) → gate trong Task 4 phải FAIL khi thiếu report; Task 3 chạy thử một nhánh có lỗ hổng cố ý để thấy pipeline đỏ.
4. **Chuỗi cung ứng của chính pipeline:** action dùng tag (có thể bị đổi), quyền `GITHUB_TOKEN` quá rộng, PR từ fork đọc được secret → bước kiểm tra trong Task 3 grep mọi `uses:` không có SHA thì fail.
5. **Staging dùng secret cố định hoặc cổng DB public** → Task 4 sinh secret ngẫu nhiên cho mỗi lần chạy, và kiểm tra từ runner rằng `5432`/`6379` không mở ra ngoài (chỉ trên mạng compose).

---

### Task 1: Dockerfile dùng chung (multi-stage, non-root, layered)

**Files:**
- Create: `Dockerfile`, `.dockerignore`
- Create: `scripts/verify-image.sh` (tham số: tên image; kiểm tra uid, không có `.env`/`*.pem`/`mvn`/`src`, healthcheck có khai báo)

**Interfaces:**
- Produces: `docker build --build-arg MODULE=<module> --build-arg PORT=<port> -t <image> .` cho ra image chạy được; label OCI `org.opencontainers.image.source`, `.revision`.
- `scripts/verify-image.sh <image>`: exit 0 khi đạt, in `FAIL: <lý do>` khi không đạt (CI dùng lại).

- [ ] **Step 1: Viết `scripts/verify-image.sh`** với các kiểm tra: `docker run --rm --entrypoint id <image> -u` = `10001`; `docker run --rm --entrypoint sh <image> -c 'find / -xdev \( -name .env -o -name "*.pem" -o -name mvn -o -path "*/src/main" \) 2>/dev/null'` rỗng; `docker inspect` có `Healthcheck` và `User` = `10001:10001`.
- [ ] **Step 2: Chạy script với một image chưa tồn tại** → FAIL (RED).
- [ ] **Step 3: Viết `Dockerfile`.**
  - Stage `build` (`maven:3.9-eclipse-temurin-21`): copy `pom.xml`, `*/pom.xml`, `.mvn`, `mvnw` trước → `./mvnw -B -q -pl ${MODULE} -am dependency:go-offline` (cache layer) → copy source → `./mvnw -B -q -pl ${MODULE} -am package -DskipTests`.
  - Stage `extract`: `java -Djarmode=tools -jar app.jar extract --layers --launcher --destination /layers`.
  - Stage `runtime` (`eclipse-temurin:21-jre-alpine`): `addgroup -S -g 10001 app && adduser -S -u 10001 -G app app`; copy 4 layer (`dependencies`, `spring-boot-loader`, `snapshot-dependencies`, `application`) theo thứ tự ít thay đổi nhất trước; `ENV PORT=${PORT}` (ARG không còn tồn tại lúc chạy, HEALTHCHECK cần ENV); `USER 10001:10001`; `EXPOSE ${PORT}`; `HEALTHCHECK CMD wget -qO- http://127.0.0.1:${PORT}/actuator/health/readiness || exit 1`; `ENTRYPOINT ["java","-XX:MaxRAMPercentage=75","-Djava.security.egd=file:/dev/urandom","org.springframework.boot.loader.launch.JarLauncher"]`.
  - `.dockerignore`: `.git`, `.env`, `.env.*` (trừ `.env.example`), `**/target`, `.superpowers`, `.idea`, `.vscode`, `*.pem`, `*.key`, `docs`.
- [ ] **Step 4: Build 3 image và chạy kiểm tra**: với mỗi module, `docker build ... && bash scripts/verify-image.sh guardgate-<module>:dev` → exit 0; `trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 guardgate-<module>:dev` → exit 0; kích thước image < 250 MB.
- [ ] **Step 5: Commit**: `build: multi-stage non-root Dockerfile shared by all services`

### Task 2: docker-compose chạy đủ hệ thống, cứng hoá container

**Files:**
- Modify: `docker-compose.yml` (thêm `auth-service`, `demo-service`, `gateway`)
- Modify: `README.md` (mục "Chạy bằng Docker")

**Interfaces:**
- Consumes: Dockerfile của Task 1.
- Produces: `docker compose up -d --build --wait` → 5 container healthy, gateway ở `http://127.0.0.1:8080`; `bash scripts/smoke-test.sh` pass (Task 4 dùng lại cho staging, với `image:` lấy từ biến `IMAGE_TAG`).

- [ ] **Step 1: Định nghĩa kiểm tra** (hạ tầng không có unit test): sau `up --wait`, `docker compose ps` có 5 service `healthy`; `curl 127.0.0.1:8081` từ host → connection refused (không publish); `bash scripts/smoke-test.sh` → `ALL CHECKS PASSED`.
- [ ] **Step 2: Thêm service** dùng `build: {context: ., args: {MODULE, PORT}}` và `image: ${IMAGE_REGISTRY:-guardgate}/guardgate-<module>:${IMAGE_TAG:-dev}`; `env_file: .env` + biến riêng (`DB_HOST=postgres`, `REDIS_HOST=redis`, `AUTH_SERVICE_URL=http://auth-service:8081`, `JWT_JWK_SET_URI=http://auth-service:8081/.well-known/jwks.json`...); `depends_on: {condition: service_healthy}`; `read_only: true`; `tmpfs: [/tmp]`; `cap_drop: [ALL]`; `security_opt: [no-new-privileges:true]`; `mem_limit: 512m`; chỉ `gateway` có `ports: ["127.0.0.1:${GATEWAY_PORT:-8080}:8080"]`.
- [ ] **Step 3: Chạy kiểm tra Step 1** → đạt. Nếu `read_only` làm app lỗi (Tomcat cần thư mục tạm), sửa bằng `tmpfs` hoặc `-Djava.io.tmpdir`, không được bỏ `read_only`.
- [ ] **Step 4: Commit**: `build: run the full stack in hardened containers with docker compose`

### Task 3: GitHub Actions: build, test và các cổng quét bảo mật

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/dependabot.yml`
- Create: `scripts/security-scan.sh [THƯ_MỤC]` (mặc định `.`; chạy Semgrep + Gitleaks + Trivy fs bằng Docker với đúng tham số như CI để dev chạy trước khi push; exit khác 0 nếu bất kỳ công cụ nào bắt được lỗi hoặc tự crash)
- Create: `.semgrepignore`, `.gitleaks.toml` (chỉ allowlist file test chứa khoá giả nếu Gitleaks bắt nhầm, có comment lý do)

**Interfaces:**
- Produces: workflow `CI` với các job `build-test`, `semgrep`, `gitleaks`, `trivy-fs`, `pin-check`, `image` (matrix 3 module); Task 4 thêm `publish`, `staging`, `zap` phía sau `image`.

**Các job:**
- `build-test`: `actions/setup-java` (temurin 21, `cache: maven`) → `./mvnw -B verify` (Testcontainers dùng Docker có sẵn trên `ubuntu-latest`) → upload báo cáo surefire/failsafe khi fail.
- `semgrep`: container `semgrep/semgrep:<pinned>`; `semgrep scan --config p/java --config p/owasp-top-ten --config p/secrets --metrics=off --error --severity ERROR --sarif -o semgrep.sarif` → upload SARIF (`github/codeql-action/upload-sarif`, cần `security-events: write`).
- `gitleaks`: checkout `fetch-depth: 0` → `docker run zricethezav/gitleaks:<pinned> git /repo --redact --exit-code 1`.
- `trivy-fs`: `aquasecurity/trivy-action` `scan-type: fs`, `severity: HIGH,CRITICAL`, `ignore-unfixed: true`, `exit-code: 1`, kèm một lượt SARIF upload.
- `pin-check`: `grep -nE 'uses: [^@]+@' .github/workflows/*.yml | grep -vE '@[0-9a-f]{40}( |$)'` có kết quả → FAIL.
- `image` (needs: build-test, semgrep, gitleaks, trivy-fs, pin-check): matrix module; `docker/build-push-action` (`push: false`, `load: true`) → `scripts/verify-image.sh` → Trivy image (`exit-code: 1`).

- [ ] **Step 1: Viết `scripts/security-scan.sh`** và chạy local → exit 0 trên code hiện tại.
- [ ] **Step 2: Kiểm chứng cổng chặn hoạt động (RED có chủ đích), chỉ ở local, KHÔNG push** (repo public). Tạo bản sao tạm bằng `git worktree add` trong scratchpad: thêm một dependency có CVE HIGH (ví dụ `commons-text:1.9`), commit một chuỗi theo mẫu khoá AWS → `scripts/security-scan.sh <đường-dẫn-bản-sao>` phải exit khác 0 và chỉ rõ Trivy + Gitleaks bắt được. Xoá worktree ngay sau đó.
- [ ] **Step 3: Viết `ci.yml`** theo danh sách job; lấy SHA cho từng action bằng `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha` và ghi tag trong comment.
- [ ] **Step 4: Push nhánh tính năng** → mọi job xanh; `pin-check` xanh.
- [ ] **Step 5: Viết `dependabot.yml`** (ecosystem `maven`, `docker`, `github-actions`; lịch weekly; gom nhóm bản vá Spring).
- [ ] **Step 6: Commit**: `ci: build, test and security gates with Semgrep, Gitleaks and Trivy`

### Task 4: Publish, staging, OWASP ZAP

**Files:**
- Modify: `.github/workflows/ci.yml` (job `publish`, `staging`, `zap`, chỉ chạy khi `github.ref == 'refs/heads/main'` và event là `push`)
- Create: `scripts/ci-staging-env.sh` (sinh `.env` với mật khẩu ngẫu nhiên và khoá RSA mới cho mỗi lần chạy), `scripts/zap-gate.sh` (đọc `zap-report.json`, FAIL nếu có `riskcode == "3"` hoặc thiếu file)
- Create: `.zap/rules.tsv` (chỉ dùng để IGNORE alert đã được phân tích, mỗi dòng có lý do)

**Interfaces:**
- Consumes: job `image` (Task 3); `scripts/smoke-test.sh`; compose của Task 2.
- Produces: image trên GHCR gắn tag SHA + `latest`, có SBOM CycloneDX và chữ ký cosign; artifact `zap-report.html`/`.json`.

**Các job:**
- `publish` (needs: image; quyền `packages: write`, `id-token: write`): login GHCR bằng `GITHUB_TOKEN` → build + push → `trivy image --format cyclonedx` làm SBOM → `cosign sign --yes <image>@<digest>` (keyless OIDC) → `cosign attest --type cyclonedx`.
- `staging` (needs: publish): `bash scripts/ci-staging-env.sh > .env` → `IMAGE_TAG=${{ github.sha }} docker compose pull && docker compose up -d --wait` → kiểm tra `nc -z localhost 5432` phải **thất bại** ở staging (compose override bỏ publish cổng DB/Redis) → `bash scripts/smoke-test.sh`.
- `zap` (cùng job với `staging` để dùng chung stack đang chạy): `docker run --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:8080 -c .zap/rules.tsv -J zap-report.json -r zap-report.html -I` → `bash scripts/zap-gate.sh zap-report.json` → upload report.

- [ ] **Step 1: Viết `scripts/zap-gate.sh`** và test nó với 3 file mẫu trong `scripts/testdata/`: report không có High → exit 0; có một alert `riskcode "3"` → exit 1; file thiếu hoặc rỗng → exit 1 (Review Focus #3).
- [ ] **Step 2: Viết `ci-staging-env.sh`**; chạy local → `.env` sinh ra có đủ biến như `.env.example`, không có giá trị `change-me`.
- [ ] **Step 3: Thêm 3 job** vào `ci.yml`; thêm `docker-compose.staging.yml` (override: bỏ `ports` của postgres/redis).
- [ ] **Step 4: Merge vào `main` (hỏi user trước)** → run trên `main`: `publish` có image + chữ ký (`cosign verify` chạy được), `staging` smoke pass, `zap` xanh; tải report về xem.
- [ ] **Step 5: Commit**: `ci: publish signed images, staging deploy and OWASP ZAP baseline gate`

### Task 5: Tài liệu pipeline

**Files:**
- Modify: `README.md` (badge CI; sơ đồ pipeline; cách đọc kết quả trong tab Security; cách chạy `scripts/security-scan.sh`; cách `cosign verify` image)
- Create: `SECURITY.md` (cách báo cáo lỗ hổng, phiên bản được hỗ trợ)
- Modify: spec: D14/D15/D18 → ✅, tiêu chí nghiệm thu GĐ4 → trạng thái thực tế

- [ ] **Step 1: Viết tài liệu**; kiểm tra mọi lệnh trong README chạy được đúng như ghi.
- [ ] **Step 2: Commit**: `docs: CI/CD pipeline, image verification and security policy`
