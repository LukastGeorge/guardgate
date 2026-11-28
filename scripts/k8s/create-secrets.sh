#!/usr/bin/env bash
# Tạo/cập nhật 4 Secret theo component (D21) từ file .env — chart Helm KHÔNG chứa secret nào.
#   guardgate-auth     : JWT_PRIVATE_KEY, AUTH_DB_PASSWORD, REDIS_PASSWORD, BOOTSTRAP_ADMIN_PASSWORD
#   guardgate-gateway  : REDIS_PASSWORD
#   guardgate-postgres : POSTGRES_ADMIN_PASSWORD, AUTH_DB_PASSWORD
#   guardgate-redis    : REDIS_PASSWORD
# Dùng: bash scripts/k8s/create-secrets.sh [env-file] [namespace]
#
# An toàn: KHÔNG in giá trị nào; KHÔNG đặt giá trị vào tham số dòng lệnh (ps/history thấy được) —
# mỗi giá trị được ghi vào một file tạm quyền 600 rồi đưa cho kubectl bằng --from-file, xoá ngay sau đó.
set -euo pipefail

ENV_FILE=${1:-.env}
NS=${2:-guardgate}
[[ -f "$ENV_FILE" ]] || { echo "FAIL: env file '$ENV_FILE' not found (copy .env.example)"; exit 1; }

# Đọc KEY=VALUE mà KHÔNG source file (source sẽ thực thi mọi lệnh nằm trong .env)
declare -A env=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
  key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
  if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val=${BASH_REMATCH[1]}; fi
  env[$key]=$val
done < "$ENV_FILE"

tmp=$(mktemp -d)
chmod 700 "$tmp"
trap 'rm -rf "$tmp"' EXIT

# make_secret <name> <KEY>... ; KEY kết thúc bằng "?" là tuỳ chọn (cho phép rỗng)
make_secret() {
  local name=$1; shift
  local args=() key optional
  for key in "$@"; do
    optional=false
    [[ "$key" == *\? ]] && { optional=true; key=${key%\?}; }
    if [[ -z "${env[$key]:-}" && "$optional" == false ]]; then
      echo "FAIL: $key is missing or empty in $ENV_FILE (needed by Secret $name)"; exit 1
    fi
    ( umask 077; printf '%s' "${env[$key]:-}" > "$tmp/$name.$key" )
    args+=(--from-file="$key=$tmp/$name.$key")
  done
  kubectl create secret generic "$name" --namespace "$NS" "${args[@]}" \
      --dry-run=client -o yaml \
    | kubectl label --local -f - -o yaml app.kubernetes.io/part-of=guardgate \
    | kubectl apply -f - >/dev/null
  echo "secret/$name applied ($# keys)"
}

make_secret guardgate-auth     JWT_PRIVATE_KEY AUTH_DB_PASSWORD REDIS_PASSWORD 'BOOTSTRAP_ADMIN_PASSWORD?'
make_secret guardgate-gateway  REDIS_PASSWORD
make_secret guardgate-postgres POSTGRES_ADMIN_PASSWORD AUTH_DB_PASSWORD
make_secret guardgate-redis    REDIS_PASSWORD
