# Giai đoạn 5: Helm + Kubernetes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Trạng thái: ĐÃ DUYỆT 2026-11-28** (D16 k3d local + CI, D17, D20 Traefik, D21 Secret theo component).

**Goal:** Deploy GuardGate lên Kubernetes bằng một Helm chart an toàn theo mặc định (Pod Security "restricted", NetworkPolicy deny-all, mỗi pod chỉ thấy secret của nó), chạy được trên k3d ở máy dev và trong CI làm staging cho ZAP.

**Architecture:** Chart `charts/guardgate` gồm 3 Deployment ứng dụng, 2 StatefulSet (Postgres, Redis), Service nội bộ, một Ingress Traefik duy nhất trỏ vào gateway, NetworkPolicy theo đồ thị gọi nhau, và tham chiếu tới các Secret có sẵn (chart không bao giờ chứa giá trị secret). Script `scripts/k8s/*.sh` dựng cluster k3d, tạo Secret từ `.env`, cài chart và chạy smoke test qua ingress. CI thay staging compose bằng k3d + Helm.

**Tech Stack:** Kubernetes 1.3x (k3s qua k3d), Helm 4, Traefik (đi kèm k3s), kubeconform, Trivy config, jq.

**Spec:** `docs/superpowers/specs/2026-11-27-guardgate-design.md`, mục 4 (D15–D17, D20, D21) và mục 6 (Giai đoạn 5)

## Global Constraints

- Namespace `guardgate`, gắn nhãn Pod Security Admission `pod-security.kubernetes.io/enforce: restricted` (+ `audit`, `warn`).
- Mọi container: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true` (thư mục cần ghi dùng `emptyDir`), có `resources.requests` và `limits`, `automountServiceAccountToken: false`.
- Image ứng dụng lấy từ `values.image.registry` + `values.image.tag` (mặc định là SHA commit; local dùng image build bằng Dockerfile của GĐ4 rồi `k3d image import`).
- Secret (D21): `guardgate-auth` (JWT_PRIVATE_KEY, AUTH_DB_PASSWORD, REDIS_PASSWORD — auth ghi denylist khi logout, BOOTSTRAP_ADMIN_PASSWORD), `guardgate-gateway` (REDIS_PASSWORD), `guardgate-postgres` (POSTGRES_ADMIN_PASSWORD, AUTH_DB_PASSWORD), `guardgate-redis` (REDIS_PASSWORD). Gateway và demo-service **không** mount `guardgate-auth`.
- Ingress host mặc định `guardgate.localhost`; gateway chạy với `GATEWAY_TRUSTED_PROXIES=1` (Traefik là proxy duy nhất phía trước).
- Probe: `startupProbe` `/actuator/health/liveness` (tối đa 120 giây), `readinessProbe` `/actuator/health/readiness`, `livenessProbe` `/actuator/health/liveness`.
- Cổng chặn mới: `helm lint`, `helm template | kubeconform -strict`, `trivy config` (HIGH/CRITICAL), `scripts/tests/helm-policy.test.sh`.

## Review Focus

1. **Secret lọt vào manifest hoặc sai pod:** `helm template` không được chứa giá trị secret nào; pod gateway/demo không được tham chiếu `guardgate-auth` → kiểm tra trong `helm-policy.test.sh` (Task 1, Task 2).
2. **Postgres/Redis chạy root hoặc ghi lên root FS:** image chính thức cần thư mục ghi được (`/var/run/postgresql`, `/tmp`) → `emptyDir` + `fsGroup`; kiểm tra pod chạy được dưới PSA restricted (Task 2, Task 4).
3. **NetworkPolicy có lỗ hoặc chặn nhầm:** thiếu egress DNS làm mọi thứ hỏng; quên mở demo→auth (JWKS) thì demo trả 401; mở quá rộng (`podSelector: {}`) thì vô nghĩa → test runtime bằng pod debug trong Task 4.
4. **Probe sai** khiến pod restart liên tục khi JVM khởi động chậm, hoặc nhận traffic trước khi sẵn sàng → `startupProbe` + kiểm tra `kubectl rollout status` (Task 4).
5. **Trusted proxies lệch với Traefik:** đặt 0 thì mọi client dùng chung bucket IP của Traefik; đặt sai số hop thì XFF giả của client lọt vào rate limit → smoke test bước "spoofed X-Forwarded-For" chạy qua ingress (Task 4).

---

### Task 1: Chart khung + 3 workload ứng dụng + cổng chặn tĩnh

**Files:**
- Create: `charts/guardgate/Chart.yaml`, `values.yaml`, `templates/_helpers.tpl`, `templates/namespace.yaml`, `templates/app-deployment.yaml` (một template lặp qua `.Values.apps`), `templates/app-service.yaml`, `templates/serviceaccount.yaml`
- Create: `scripts/tests/helm-policy.test.sh` (render bằng `helm template`, chuyển YAML → JSON bằng `yq -o=json` chạy trong image `mikefarah/yq` pin digest, rồi kiểm tra bằng `jq`; không cần cluster)
- Test: `scripts/tests/helm-policy.test.sh`

**Interfaces:**
- Produces: `helm template gg charts/guardgate` render ra Deployment `auth-service`, `gateway`, `demo-service` và Service ClusterIP cùng tên (cổng 8081/8080/8082).
- `values.apps.<name>`: `{enabled, port, replicas, resources, env: {}, secretRefs: []}`.

- [ ] **Step 1: Viết `helm-policy.test.sh`** với các assertion trên manifest đã render: mọi container có đủ securityContext như Global Constraints; có requests/limits; `automountServiceAccountToken: false`; không có `hostPath`, `hostNetwork`, `privileged`; image không dùng tag `latest`; gateway và demo không tham chiếu Secret `guardgate-auth`; không có object `kind: Secret` nào trong output.
- [ ] **Step 2: Chạy** → FAIL (chart chưa tồn tại).
- [x] **Step 3: Viết chart** đến khi test pass; thêm `helm lint` và `kubeconform -strict -summary` (chạy bằng image pin digest).
- [ ] **Step 4: `trivy config charts/guardgate`** (HIGH/CRITICAL, exit 1) → exit 0.
- [ ] **Step 5: Commit**: `feat(helm): chart with hardened workloads for the three services`

### Task 2: Postgres + Redis (StatefulSet) và Secret theo component

**Files:**
- Create: `charts/guardgate/templates/postgres-statefulset.yaml`, `postgres-service.yaml`, `postgres-init-configmap.yaml` (dùng lại `infra/postgres/init/01-create-auth-db.sh`), `redis-statefulset.yaml`, `redis-service.yaml`
- Create: `scripts/k8s/create-secrets.sh` (đọc `.env` → `kubectl create secret generic ... --dry-run=client -o yaml | kubectl apply -f -` cho 4 Secret; không in giá trị ra màn hình)
- Modify: `scripts/tests/helm-policy.test.sh` (thêm StatefulSet vào kiểm tra)

**Interfaces:**
- Produces: Service `postgres:5432`, `redis:6379`; PVC 1Gi mỗi StatefulSet; Redis chạy với `--requirepass` từ Secret và rename lệnh nguy hiểm như compose.

- [ ] **Step 1: Mở rộng test**: StatefulSet cũng phải qua toàn bộ kiểm tra securityContext; Postgres `runAsUser: 70` (alpine postgres), Redis `runAsUser: 999`; root FS read-only với `emptyDir` cho thư mục runtime.
- [ ] **Step 2: Chạy** → FAIL.
- [x] **Step 3: Viết template + `create-secrets.sh`** → test pass, `helm lint` + kubeconform + trivy config xanh.
- [ ] **Step 4: Commit**: `feat(helm): postgres and redis statefulsets with per-component secrets`

### Task 3: NetworkPolicy, Pod Security, Ingress

**Files:**
- Create: `charts/guardgate/templates/networkpolicy.yaml`, `ingress.yaml`
- Modify: `templates/namespace.yaml` (nhãn PSA), `values.yaml` (`ingress.host`, `gateway.env.GATEWAY_TRUSTED_PROXIES: "1"`)
- Modify: `scripts/tests/helm-policy.test.sh`

**Interfaces:**
- NetworkPolicy: `default-deny` (ingress + egress mọi pod); cho phép egress DNS (kube-system:53 UDP/TCP); `ingress → gateway:8080` từ namespace `kube-system` (Traefik); `gateway → auth-service:8081, demo-service:8082, redis:6379`; `auth-service → postgres:5432, redis:6379`; `demo-service → auth-service:8081`.

- [ ] **Step 1: Mở rộng test**: có policy default-deny chọn mọi pod (`podSelector: {}`, cả hai `policyTypes`); không policy nào cho phép ingress từ mọi nơi (`from: []`); namespace có nhãn `enforce: restricted`; Ingress chỉ có một backend là `gateway`.
- [ ] **Step 2: Chạy** → FAIL.
- [ ] **Step 3: Viết template** → test pass.
- [ ] **Step 4: Commit**: `feat(helm): default-deny network policies, restricted pod security, traefik ingress`

### Task 4: Deploy thật lên k3d + kiểm tra runtime

**Files:**
- Create: `scripts/k8s/up.sh` (tạo cluster `guardgate` bằng k3d với port `8443:443`, `8088:80` qua loadbalancer; build 3 image từ Dockerfile GĐ4; `k3d image import`; `create-secrets.sh`; `helm upgrade --install --wait`), `scripts/k8s/down.sh`
- Create: `scripts/tests/k8s-netpol.test.sh` (chạy pod debug `busybox` trong namespace, kiểm tra: tới `postgres:5432` → chặn; từ pod có nhãn `app=auth-service` giả lập → mở; gateway → auth OK; demo → postgres chặn)
- Modify: `scripts/smoke-test.sh` (nhận BASE_URL `http://guardgate.localhost:8088`)

- [ ] **Step 1: Cài k3d** (binary chính thức, kiểm tra checksum SHA256 từ release) — cần user đồng ý.
- [ ] **Step 2: `bash scripts/k8s/up.sh`** → mọi pod `Running`/`Ready`, không có restart; PSA không chặn pod nào (`kubectl get events` không có `violates PodSecurity`).
- [ ] **Step 3: `bash scripts/smoke-test.sh http://guardgate.localhost:8088`** → `ALL CHECKS PASSED` (gồm bước XFF giả qua ingress — Review Focus #5).
- [ ] **Step 4: `bash scripts/tests/k8s-netpol.test.sh`** → mọi kết nối bị cấm đều bị chặn, mọi kết nối cần thiết đều thông.
- [ ] **Step 5: Commit**: `feat(k8s): local k3d deployment with runtime network policy checks`

### Task 5: CI — cổng chặn chart + staging trên k3d

**Files:**
- Modify: `.github/workflows/ci.yml` (job `helm` chạy trên mọi nhánh: lint, kubeconform, trivy config, helm-policy test; job `staging-dast` chuyển từ compose sang k3d + Helm, kéo image đã ký theo **digest** từ GHCR — xử lý luôn minor #5 của GĐ4)
- Modify: `scripts/tests/workflow-policy.test.sh` (staging dùng k3d, deploy theo digest đã cosign verify)

- [ ] **Step 1: Mở rộng `workflow-policy.test.sh`** → FAIL.
- [ ] **Step 2: Sửa workflow** → policy test + actionlint xanh.
- [ ] **Step 3: Push nhánh** → job `helm` xanh; merge vào main (hỏi user) → `staging-dast` trên k3d xanh (cosign verify, smoke qua ingress, netpol test, ZAP).
- [ ] **Step 4: Commit**: `ci: helm gates and k3d staging with digest-pinned signed images`

### Task 6: Tài liệu

- [ ] README: sơ đồ K8s (Ingress → gateway → services, NetworkPolicy), cách chạy `scripts/k8s/up.sh`, cách kiểm tra PSA/NetworkPolicy; spec GĐ5 → trạng thái thực tế, D16/D17/D20/D21 → ✅.
- [ ] Commit: `docs: kubernetes deployment guide`
