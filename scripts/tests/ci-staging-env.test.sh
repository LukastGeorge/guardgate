#!/usr/bin/env bash
# Test cho scripts/ci-staging-env.sh: .env của staging phải đủ biến như .env.example,
# không còn giá trị mẫu "change-me", có khoá JWT PKCS#8 thật, và mỗi lần chạy sinh secret KHÁC nhau.
set -uo pipefail
cd "$(dirname "$0")/../.."
failures=0
check() { if eval "$2"; then echo "  ok  $1"; else echo "FAIL: $1"; failures=$((failures + 1)); fi; }

first=$(bash scripts/ci-staging-env.sh 2>/dev/null) || { echo "FAIL: script exited non-zero"; exit 1; }
second=$(bash scripts/ci-staging-env.sh 2>/dev/null)

keys_example=$(grep -oE '^[A-Z_]+=' .env.example | sort -u)
keys_generated=$(grep -oE '^[A-Z_]+=' <<<"$first" | sort -u)
value() { grep -E "^$1=" <<<"$2" | head -1 | cut -d= -f2-; }

check "contains every variable of .env.example" '[[ "$keys_example" == "$keys_generated" ]]'
check "no placeholder values left"              '! grep -q "change-me" <<<"$first"'
# PKCS#8 có AlgorithmIdentifier rsaEncryption (OID 1.2.840.113549.1.1.1) ở đầu; PKCS#1 thì không (lỗi L2.2)
check "JWT key is a PKCS#8 RSA key (base64 DER)" \
      '[[ "$(value JWT_PRIVATE_KEY "$first" | base64 -d 2>/dev/null | head -c 32 | od -An -tx1 | tr -d " \n")" == *06092a864886f70d010101* ]]'
check "passwords differ between runs"           '[[ "$(value AUTH_DB_PASSWORD "$first")" != "$(value AUTH_DB_PASSWORD "$second")" ]]'
check "JWT key differs between runs"            '[[ "$(value JWT_PRIVATE_KEY "$first")" != "$(value JWT_PRIVATE_KEY "$second")" ]]'
check "passwords are at least 24 chars"         '[[ $(value REDIS_PASSWORD "$first" | tr -d "\n" | wc -c) -ge 24 ]]'

[[ $failures -eq 0 ]] && echo "ci-staging-env tests passed" || { echo "$failures test(s) failed"; exit 1; }
