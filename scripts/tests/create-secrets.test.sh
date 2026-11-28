#!/usr/bin/env bash
# Test scripts/k8s/create-secrets.sh bằng kubectl giả (không cần cluster):
#  - mỗi Secret chỉ chứa đúng các key của component đó (D21), giá trị đúng (kể cả dấu nháy, '=' và CRLF)
#  - không giá trị nào bị in ra stdout/stderr hay nằm trong tham số dòng lệnh
#  - thiếu key bắt buộc -> exit khác 0 và chỉ nêu TÊN key
set -uo pipefail
cd "$(dirname "$0")/../.."

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/out"
fails=0; fail() { echo "FAIL: $*"; fails=$((fails+1)); }

# kubectl giả: ghi lại argv; "create secret" in YAML tối giản (base64 của từng --from-file); "apply" lưu theo tên
cat > "$work/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$OUT/argv.log"
if [[ "$1" == create && "$2" == secret ]]; then
  echo "name: $4"
  for a in "$@"; do
    [[ "$a" == --from-file=* ]] || continue
    kv=${a#--from-file=}; k=${kv%%=*}; f=${kv#*=}
    echo "$k: $(base64 -w0 < "$f")"
  done
elif [[ "$1" == label ]]; then cat
elif [[ "$1" == apply ]]; then
  doc=$(cat); n=$(sed -n 's/^name: //p' <<<"$doc"); printf '%s\n' "$doc" > "$OUT/$n"
fi
EOF
chmod +x "$work/bin/kubectl"
export OUT="$work/out" PATH="$work/bin:$PATH"

# Giá trị giả sinh NGẪU NHIÊN lúc chạy: không chuỗi giống secret nào nằm trong repo (Gitleaks quét toàn lịch sử)
rnd() { od -An -N12 -tx1 /dev/urandom | tr -d ' \n'; }
PG_ADMIN="pg-$(rnd)"; AUTH_DB="auth=$(rnd) pass"; REDIS_PW="rd-$(rnd)"; JWT="jwt$(rnd)$(rnd)"; OTHER="other-$(rnd)"

printf '%s\r\n' \
  '# comment' '' \
  "POSTGRES_ADMIN_PASSWORD=$PG_ADMIN" \
  "AUTH_DB_PASSWORD=\"$AUTH_DB\"" \
  "REDIS_PASSWORD='$REDIS_PW'" \
  "JWT_PRIVATE_KEY=$JWT" \
  'BOOTSTRAP_ADMIN_PASSWORD=' \
  "GITHUB_CLIENT_SECRET=$OTHER" > "$work/test.env"

log=$(bash scripts/k8s/create-secrets.sh "$work/test.env" guardgate 2>&1); rc=$?
[[ $rc -eq 0 ]] || fail "create-secrets exited $rc: $log"

val() { sed -n "s/^$2: //p" "$OUT/$1" | base64 -d; }
keys() { sed -n '2,$s/:.*//p' "$OUT/$1" | sort | tr '\n' ' '; }

[[ "$(keys guardgate-auth)" == "AUTH_DB_PASSWORD BOOTSTRAP_ADMIN_PASSWORD JWT_PRIVATE_KEY REDIS_PASSWORD " ]] \
  || fail "guardgate-auth keys: $(keys guardgate-auth)"
[[ "$(keys guardgate-gateway)" == "REDIS_PASSWORD " ]]  || fail "guardgate-gateway keys: $(keys guardgate-gateway)"
[[ "$(keys guardgate-postgres)" == "AUTH_DB_PASSWORD POSTGRES_ADMIN_PASSWORD " ]] || fail "guardgate-postgres keys: $(keys guardgate-postgres)"
[[ "$(keys guardgate-redis)" == "REDIS_PASSWORD " ]]    || fail "guardgate-redis keys: $(keys guardgate-redis)"

[[ "$(val guardgate-postgres AUTH_DB_PASSWORD)" == "$AUTH_DB" ]]         || fail "double quotes / '=' / space not handled"
[[ "$(val guardgate-redis REDIS_PASSWORD)" == "$REDIS_PW" ]]             || fail "single quotes / CRLF not handled"
[[ "$(val guardgate-postgres POSTGRES_ADMIN_PASSWORD)" == "$PG_ADMIN" ]] || fail "CRLF left in value"
[[ "$(val guardgate-auth JWT_PRIVATE_KEY)" == "$JWT" ]]                  || fail "JWT_PRIVATE_KEY value differs"
[[ -z "$(val guardgate-auth BOOTSTRAP_ADMIN_PASSWORD)" ]]               || fail "optional empty key should be empty"

for secret in "$PG_ADMIN" "$AUTH_DB" "$REDIS_PW" "$JWT" "$OTHER"; do
  grep -qF -- "$secret" <<<"$log"              && fail "value printed to output: ${secret:0:4}…"
  grep -qF -- "$secret" "$OUT/argv.log"        && fail "value passed on the command line: ${secret:0:4}…"
done
grep -rqF -- "$OTHER" "$OUT"/guardgate-* && fail "unrelated .env key leaked into a Secret"

# Thiếu key bắt buộc -> thất bại, chỉ nêu tên key
grep -v '^REDIS_PASSWORD' "$work/test.env" > "$work/missing.env"
log=$(bash scripts/k8s/create-secrets.sh "$work/missing.env" guardgate 2>&1); rc=$?
[[ $rc -ne 0 ]] || fail "missing REDIS_PASSWORD should fail"
grep -q 'REDIS_PASSWORD is missing' <<<"$log" || fail "error should name the missing key: $log"

if (( fails )); then echo "$fails create-secrets test(s) failed"; exit 1; fi
echo "create-secrets tests passed"
