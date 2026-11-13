#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
cd "${PROJECT_DIR}"

command -v conda >/dev/null || { echo "conda not found; run 0_install_dependencies.sh first." >&2; exit 1; }

exec conda run --no-capture-output -n "${CONDA_ENV_NAME:-n4s_env}" python3 cyberattacks_module.py \
  --feature fabrication \
  --message STEER \
  --signal STEER_signal \
  --value 255 \
  --period 0.02 \
  --duration 5 \
  "$@"
