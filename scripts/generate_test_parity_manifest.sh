#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"
OUT="${2:-}"
SOURCE_PATH="${3:-${PORT_SOURCE_DIR:-}}"
LANGUAGE="${4:-${PORT_LANGUAGE:-go}}"
PARSER="${PORT_PARSER:-auto}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

args=(--root "${ROOT_DIR}" --language "${LANGUAGE}" --parser "${PARSER}")
[[ -n "${OUT}" ]] && args+=(--out "${OUT}")
[[ -n "${SOURCE_PATH}" ]] && args+=(--source "${SOURCE_PATH}")

"${SCRIPT_DIR}/generate_test_parity_manifest.rb" "${args[@]}"
