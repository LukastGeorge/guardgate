#!/usr/bin/env bash
# Dựng GuardGate trên k3d (k3s trong Docker) ở máy dev:
#   cluster -> build + import image -> namespace (PSA restricted) -> Secret từ .env -> helm upgrade --install --wait
# Dùng: bash scripts/k8s/up.sh [env-file]          (mặc định .env)
# Sau đó: bash scripts/smoke-test.sh http://guardgate.localhost:8088
#
# Kubeconfig của cluster nằm riêng ở .tools/kubeconfig (gitignored): KHÔNG sửa ~/.kube/config của bạn.
#   export KUBECONFIG=.tools/kubeconfig   # để dùng kubectl với cluster này
set -euo pipefail
cd "$(dirname "$0")/../.."

ENV_FILE=${1:-.env}
CLUSTER=guardgate
NS=guardgate
RELEASE=gg
HTTP_PORT=${K8S_HTTP_PORT:-8088}
# k3s pin theo digest (supply chain: tag có thể bị trỏ sang image khác)
K3S_IMAGE=rancher/k3s:v1.35.5-k3s1@sha256:2074403abe1bded11ef3dde09d457e13be8e0b64c218b1c4f8269b4565cfbc65
APPS=(auth-service demo-service gateway)

if [[ -x .tools/k3d.exe ]]; then K3D=.tools/k3d.exe; elif [[ -x .tools/k3d ]]; then K3D=.tools/k3d; else K3D=k3d; fi
command -v "$K3D" >/dev/null || { echo "FAIL: k3d not found (.tools/k3d[.exe] or PATH)"; exit 1; }
for tool in docker kubectl helm; do command -v "$tool" >/dev/null || { echo "FAIL: missing tool '$tool'"; exit 1; }; done
[[ -f "$ENV_FILE" ]] || { echo "FAIL: $ENV_FILE not found (cp .env.example .env)"; exit 1; }

mkdir -p .tools
# pwd -W: đường dẫn dạng Windows cho kubectl.exe/helm.exe khi chạy trong Git Bash (Linux/macOS: pwd thường)
export KUBECONFIG="$(pwd -W 2>/dev/null || pwd)/.tools/kubeconfig"

# 1. Cluster: chỉ bind 127.0.0.1 (máy khác trong LAN không vào được)
if ! "$K3D" cluster list "$CLUSTER" >/dev/null 2>&1; then
  echo "==> creating k3d cluster '$CLUSTER'"
  "$K3D" cluster create "$CLUSTER" \
    --image "$K3S_IMAGE" \
    --servers 1 --agents 0 \
    --port "127.0.0.1:${HTTP_PORT}:80@loadbalancer" \
    --kubeconfig-update-default=false \
    --kubeconfig-switch-context=false \
    --wait --timeout 180s
fi
"$K3D" kubeconfig get "$CLUSTER" > "$KUBECONFIG"
chmod 600 "$KUBECONFIG" 2>/dev/null || true
kubectl wait --for=condition=Ready node --all --timeout=120s >/dev/null

# 2. Image: tag = SHA commit (thêm -dirty nếu có thay đổi chưa commit) -> đổi code là đổi tag -> pod được tạo lại
TAG=$(git rev-parse --short=12 HEAD)
[[ -n "$(git status --porcelain)" ]] && TAG="$TAG-dirty"
echo "==> building images (tag $TAG)"
images=()
for app in "${APPS[@]}"; do
  case $app in auth-service) port=8081;; demo-service) port=8082;; gateway) port=8080;; esac
  docker build -q -t "guardgate/guardgate-$app:$TAG" \
    --build-arg MODULE="$app" --build-arg PORT="$port" --build-arg REVISION="$(git rev-parse HEAD)" . >/dev/null
  images+=("guardgate/guardgate-$app:$TAG")
done
echo "==> importing images into k3d"
"$K3D" image import -c "$CLUSTER" "${images[@]}"

# 3. Namespace từ CHÍNH template của chart (một nguồn sự thật cho nhãn Pod Security "restricted")
helm template "$RELEASE" charts/guardgate --namespace "$NS" --set namespace.create=true \
  --show-only templates/namespace.yaml | kubectl apply -f - >/dev/null

# 4. Secret theo component (không in giá trị)
bash scripts/k8s/create-secrets.sh "$ENV_FILE" "$NS"

# 5. Cấu hình không bí mật lấy từ .env (email admin bootstrap) — đọc đúng một key, không source file
admin_email=$(sed -n 's/^BOOTSTRAP_ADMIN_EMAIL=//p' "$ENV_FILE" | tail -1 | tr -d '\r"'"'")

echo "==> helm upgrade --install"
helm upgrade --install "$RELEASE" charts/guardgate --namespace "$NS" \
  --set image.tag="$TAG" \
  --set-string "apps.auth-service.env.BOOTSTRAP_ADMIN_EMAIL=$admin_email" \
  --wait --timeout 6m

kubectl -n "$NS" get pods -o wide
echo "GuardGate is up: http://guardgate.localhost:${HTTP_PORT}  (KUBECONFIG=.tools/kubeconfig)"
