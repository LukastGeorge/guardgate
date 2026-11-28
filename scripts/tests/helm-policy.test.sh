#!/usr/bin/env bash
# Cổng chặn tĩnh cho Helm chart (không cần cluster): render chart, rồi kiểm tra mọi workload theo
# Global Constraints của plan GĐ5. In TẤT CẢ vi phạm, exit 1 nếu có bất kỳ vi phạm nào.
# Dùng: bash scripts/tests/helm-policy.test.sh [values-file...]
set -uo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1

CHART=charts/guardgate
YQ_IMAGE=mikefarah/yq:4.54.3@sha256:7834187596ad56fd5a81436114e0b0b9dd54c91bb43946d1f7145b2be5f9c3d2
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e
K8S_VERSION=1.35.0

[[ -f "$CHART/Chart.yaml" ]] || { echo "FAIL: chart not found at $CHART"; exit 1; }
extra=(); for f in "$@"; do extra+=(-f "$f"); done

helm lint "$CHART" "${extra[@]}" --quiet >/dev/null || { echo "FAIL: helm lint"; helm lint "$CHART" "${extra[@]}"; exit 1; }
rendered=$(helm template gg "$CHART" --namespace guardgate "${extra[@]}") || { echo "FAIL: helm template"; exit 1; }

# Schema Kubernetes thật (-strict: field lạ cũng là lỗi)
printf '%s\n' "$rendered" | docker run --rm -i "$KUBECONFORM_IMAGE" -strict -summary \
  -kubernetes-version "$K8S_VERSION" -output text - >/tmp/kubeconform.out 2>&1 \
  || { echo "FAIL: kubeconform"; cat /tmp/kubeconform.out; exit 1; }

docs=$(printf '%s\n' "$rendered" | docker run --rm -i "$YQ_IMAGE" -o=json -I=0 'select(. != null)' | jq -s '.') \
  || { echo "FAIL: could not convert rendered manifests to JSON"; exit 1; }

violations=$(jq -r \
  --argjson allowed '{"auth-service":["guardgate-auth"],"gateway":["guardgate-gateway"],"demo-service":[],
                      "postgres":["guardgate-postgres"],"redis":["guardgate-redis"]}' \
  --argjson uids '{"auth-service":10001,"gateway":10001,"demo-service":10001,"postgres":70,"redis":999}' '
  def pods: .[] | select(.kind == "Deployment" or .kind == "StatefulSet")
            | {name: .metadata.name, spec: .spec.template.spec};
  def containers($p): ($p.spec.containers // []) + ($p.spec.initContainers // []);
  def secret_refs($p):
      [ containers($p)[] | (.envFrom // [])[] | .secretRef.name // empty ]
    + [ containers($p)[] | (.env // [])[] | .valueFrom.secretKeyRef.name // empty ]
    + [ ($p.spec.volumes // [])[] | .secret.secretName // empty ];

  ( [ .[] | select(.kind == "Secret") | "manifest contains a Secret object: \(.metadata.name) (secrets must come from existingSecret)" ] ),
  ( ["auth-service","gateway","demo-service"] - [ .[] | select(.kind == "Deployment") | .metadata.name ]
      | map("missing Deployment \(.)") ),
  ( ["postgres","redis"] - [ .[] | select(.kind == "StatefulSet") | .metadata.name ]
      | map("missing StatefulSet \(.)") ),
  ( [ pods as $p
      | (if $p.spec.automountServiceAccountToken != false then "\($p.name): automountServiceAccountToken must be false" else empty end),
        (if $p.spec.enableServiceLinks != false
           then "\($p.name): enableServiceLinks must be false (K8s-injected *_PORT vars clash with app config)" else empty end),
        (if ($p.spec.hostNetwork // false) or ($p.spec.hostPID // false) or ($p.spec.hostIPC // false)
           then "\($p.name): host namespaces are forbidden" else empty end),
        ( ($p.spec.volumes // [])[] | select(.hostPath) | "\($p.name): hostPath volume \(.name) is forbidden" ),
        (if ($p.spec.securityContext.seccompProfile.type // "") != "RuntimeDefault"
           then "\($p.name): pod seccompProfile must be RuntimeDefault" else empty end),
        ( containers($p)[] as $c
          | ($c.securityContext // {}) as $s
          | (if ($s.runAsNonRoot // $p.spec.securityContext.runAsNonRoot // false) != true
               then "\($p.name)/\($c.name): runAsNonRoot must be true" else empty end),
            (if $s.allowPrivilegeEscalation != false then "\($p.name)/\($c.name): allowPrivilegeEscalation must be false" else empty end),
            (if $s.readOnlyRootFilesystem != true then "\($p.name)/\($c.name): readOnlyRootFilesystem must be true" else empty end),
            (if (($s.capabilities.drop // []) | index("ALL")) == null then "\($p.name)/\($c.name): capabilities must drop ALL" else empty end),
            (if ($s.capabilities.add // []) != [] then "\($p.name)/\($c.name): adding capabilities is forbidden" else empty end),
            (if ($s.privileged // false) then "\($p.name)/\($c.name): privileged is forbidden" else empty end),
            (if ($c.resources.requests.cpu == null or $c.resources.requests.memory == null or $c.resources.limits.memory == null)
               then "\($p.name)/\($c.name): requests.cpu, requests.memory and limits.memory are required" else empty end),
            (if ($c.image | test(":[^/]+$") | not) or ($c.image | endswith(":latest"))
               then "\($p.name)/\($c.name): image must carry an explicit, non-latest tag (\($c.image))" else empty end)
        ),
        ( if ($p.name == "gateway" or $p.name == "demo-service") and (secret_refs($p) | index("guardgate-auth")) != null
            then "\($p.name): must not reference Secret guardgate-auth (JWT signing key, DB password)" else empty end ),
        # D21: mỗi workload chỉ được tham chiếu đúng Secret của nó
        ( (secret_refs($p) | unique) - ($allowed[$p.name] // []) | .[]
          | "\($p.name): references Secret \(.) outside its allow-list" ),
        ( if ($uids[$p.name] != null) and ($p.spec.securityContext.runAsUser != $uids[$p.name])
            then "\($p.name): pod runAsUser must be \($uids[$p.name])" else empty end ),
        ( if ($p.name | IN("auth-service","gateway","demo-service"))
            then ( $p.spec.containers[0] as $c
                   | (if $c.startupProbe == null then "\($p.name): startupProbe required" else empty end),
                     (if $c.readinessProbe == null then "\($p.name): readinessProbe required" else empty end),
                     (if $c.livenessProbe == null then "\($p.name): livenessProbe required" else empty end) )
            else empty end )
    ] )
  | .[]' <<<"$docs")

# Script init Postgres trong chart phải giống hệt bản docker-compose dùng (một nguồn sự thật)
if ! cmp -s infra/postgres/init/01-create-auth-db.sh "$CHART/files/01-create-auth-db.sh"; then
  violations+=$'\n'"chart files/01-create-auth-db.sh differs from infra/postgres/init/01-create-auth-db.sh"
  violations=${violations#$'\n'}
fi

if [[ -n "$violations" ]]; then
  echo "$violations" | sed 's/^/FAIL: /'
  echo "$(wc -l <<<"$violations" | tr -d ' ') helm policy violation(s)"
  exit 1
fi
echo "helm policy tests passed ($(jq '[.[] | select(.kind == "Deployment" or .kind == "StatefulSet")] | length' <<<"$docs") workloads, $(jq length <<<"$docs") objects)"
