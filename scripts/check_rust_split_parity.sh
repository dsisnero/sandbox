#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

"${SCRIPT_DIR}/check_port_inventory.sh" . plans/inventory/rust_linux_sandbox_port_inventory.tsv vendor/codex/codex-rs/linux-sandbox rust
"${SCRIPT_DIR}/check_source_parity.sh" . plans/inventory/rust_linux_sandbox_source_parity.tsv vendor/codex/codex-rs/linux-sandbox rust
"${SCRIPT_DIR}/check_test_parity.sh" . plans/inventory/rust_linux_sandbox_test_parity.tsv vendor/codex/codex-rs/linux-sandbox rust

"${SCRIPT_DIR}/check_port_inventory.sh" . plans/inventory/rust_windows_sandbox_port_inventory.tsv vendor/codex/codex-rs/windows-sandbox-rs rust
"${SCRIPT_DIR}/check_source_parity.sh" . plans/inventory/rust_windows_sandbox_source_parity.tsv vendor/codex/codex-rs/windows-sandbox-rs rust
"${SCRIPT_DIR}/check_test_parity.sh" . plans/inventory/rust_windows_sandbox_test_parity.tsv vendor/codex/codex-rs/windows-sandbox-rs rust

"${SCRIPT_DIR}/check_port_inventory.sh" . plans/inventory/rust_seatbelt_port_inventory.tsv plans/parity_sources/seatbelt_core rust
"${SCRIPT_DIR}/check_source_parity.sh" . plans/inventory/rust_seatbelt_source_parity.tsv plans/parity_sources/seatbelt_core rust
"${SCRIPT_DIR}/check_test_parity.sh" . plans/inventory/rust_seatbelt_test_parity.tsv plans/parity_sources/seatbelt_core rust

echo "Rust split parity checks passed."
