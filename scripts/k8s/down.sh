#!/usr/bin/env bash
# Xoá cluster k3d "guardgate" (kèm toàn bộ dữ liệu Postgres/Redis trong cluster) và kubeconfig riêng của nó.
# Dùng: bash scripts/k8s/down.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

if [[ -x .tools/k3d.exe ]]; then K3D=.tools/k3d.exe; elif [[ -x .tools/k3d ]]; then K3D=.tools/k3d; else K3D=k3d; fi
"$K3D" cluster delete guardgate
rm -f .tools/kubeconfig
