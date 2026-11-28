#!/usr/bin/env bash
# Kiểm tra NetworkPolicy TRÊN CLUSTER THẬT (sau scripts/k8s/up.sh): mọi kết nối cần thiết thông,
# mọi kết nối không có trong đồ thị gọi nhau bị chặn.
# Thử từ chính các pod đang chạy (đều có busybox nc) + một pod "người lạ" không nhãn trong cùng namespace.
# Dùng: bash scripts/tests/k8s-netpol.test.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
[[ -z "${KUBECONFIG:-}" && -f .tools/kubeconfig ]] && export KUBECONFIG="$(pwd -W 2>/dev/null || pwd)/.tools/kubeconfig"
export MSYS_NO_PATHCONV=1
NS=guardgate
fails=0; checks=0

pod_of() { kubectl -n "$NS" get pod -l "app.kubernetes.io/name=$1" -o jsonpath='{.items[0].metadata.name}'; }

# expect <OPEN|BLOCKED> <pod> <host> <port>
expect() {
  local want=$1 pod=$2 host=$3 port=$4 got
  if kubectl -n "$NS" exec "$pod" -- nc -z -w 3 "$host" "$port" >/dev/null 2>&1; then got=OPEN; else got=BLOCKED; fi
  checks=$((checks + 1))
  if [[ "$got" == "$want" ]]; then
    printf '  ok  %-30s -> %-20s %s\n' "$pod" "$host:$port" "$got"
  else
    printf 'FAIL  %-30s -> %-20s expected %s, got %s\n' "$pod" "$host:$port" "$want" "$got"; fails=$((fails + 1))
  fi
}

# DNS phải chạy trong mọi pod, nếu không "BLOCKED" bên dưới có thể chỉ là lỗi resolve
dns_ok() {
  checks=$((checks + 1))
  # getent dùng resolver của libc (giống app); busybox nslookup trả lỗi khi gặp NXDOMAIN ở search domain
  if kubectl -n "$NS" exec "$1" -- getent hosts postgres >/dev/null 2>&1; then printf '  ok  %-30s DNS resolves\n' "$1"
  else echo "FAIL  $1: DNS does not resolve (allow-dns-egress broken?)"; fails=$((fails + 1)); fi
}

# Pod "người lạ": không nhãn ứng dụng -> chỉ default-deny + DNS áp lên nó. Tuân thủ PSA restricted.
STRANGER=netpol-stranger
image=$(kubectl -n "$NS" get deploy auth-service -o jsonpath='{.spec.template.spec.containers[0].image}')
kubectl -n "$NS" delete pod "$STRANGER" --ignore-not-found --wait=true >/dev/null
kubectl -n "$NS" run "$STRANGER" --image="$image" --restart=Never --labels=role=netpol-test \
  --overrides='{"spec":{"automountServiceAccountToken":false,"enableServiceLinks":false,
     "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},
     "containers":[{"name":"netpol-stranger","image":"'"$image"'","command":["sleep","300"],
       "resources":{"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"memory":"32Mi"}},
       "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}' \
  >/dev/null
trap 'kubectl -n "$NS" delete pod "$STRANGER" --ignore-not-found --wait=false >/dev/null 2>&1' EXIT
kubectl -n "$NS" wait --for=condition=Ready "pod/$STRANGER" --timeout=60s >/dev/null || { echo "FAIL: stranger pod not ready"; exit 1; }

AUTH=$(pod_of auth-service); GW=$(pod_of gateway); DEMO=$(pod_of demo-service); PG=$(pod_of postgres); RD=$(pod_of redis)

echo "NetworkPolicy runtime checks (namespace $NS)"
for p in "$STRANGER" "$AUTH" "$GW" "$DEMO"; do dns_ok "$p"; done

# Người lạ trong namespace: không tới được bất cứ thứ gì (kể cả gateway — chỉ Traefik được gọi gateway)
for target in postgres:5432 redis:6379 auth-service:8081 demo-service:8082 gateway:8080; do
  expect BLOCKED "$STRANGER" "${target%:*}" "${target#*:}"
done
expect BLOCKED "$STRANGER" 1.1.1.1 443        # không ra Internet

# gateway -> auth, demo, redis; KHÔNG tới postgres
expect OPEN    "$GW" auth-service 8081
expect OPEN    "$GW" demo-service 8082
expect OPEN    "$GW" redis 6379
expect BLOCKED "$GW" postgres 5432
expect BLOCKED "$GW" 1.1.1.1 443

# auth-service -> postgres, redis; KHÔNG gọi ngược demo/gateway
expect OPEN    "$AUTH" postgres 5432
expect OPEN    "$AUTH" redis 6379
expect BLOCKED "$AUTH" demo-service 8082
expect BLOCKED "$AUTH" gateway 8080
expect BLOCKED "$AUTH" 1.1.1.1 443

# demo-service -> chỉ auth-service (JWKS)
expect OPEN    "$DEMO" auth-service 8081
expect BLOCKED "$DEMO" postgres 5432
expect BLOCKED "$DEMO" redis 6379

# Kho dữ liệu không gọi ra ngoài
expect BLOCKED "$PG" redis 6379
expect BLOCKED "$PG" 1.1.1.1 443
expect BLOCKED "$RD" postgres 5432

if (( fails )); then echo "$fails/$checks network policy check(s) failed"; exit 1; fi
echo "network policy runtime checks passed ($checks)"
