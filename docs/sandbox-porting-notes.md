# Sandbox Porting Notes

Upstream revision: `24b8d443b82aad9f336b9c379aebbeab8667466a`

## Source Mapping

- `codex-rs/core/src/sandboxing/mod.rs`
  - Crystal: `src/sandbox/sandboxing.cr`
  - Ported: manager selection/transform flow, permission profile merge/intersection,
    platform dispatch, and policy-env shaping.

- `codex-rs/linux-sandbox/src/lib.rs` (+ runtime entry wiring)
  - Crystal: `src/sandbox/sandboxing/linux_sandbox.cr`
  - Ported: run-main flow, bwrap/fs arg shaping, seccomp network mode resolution,
    proxy-routing helpers, and parity tests.

- `codex-rs/windows-sandbox-rs/src/lib.rs`
  - Crystal: `src/sandbox/sandboxing/windows_sandbox.cr`
  - Ported: policy parsing, env shaping, allow/deny path computation, setup/error
    modeling, helper materialization, audit scanning, setup orchestration fallback,
    capture execution fallback, and parity tests.

- macOS Seatbelt integration (`/usr/bin/sandbox-exec` expectation from
  `codex-rs/core/README.md`)
  - Crystal: `src/sandbox/sandboxing/macos_seatbelt.cr`
  - Ported: executable pin (`/usr/bin/sandbox-exec`), dynamic network policy,
    protected subpath handling, extension policy integration, and parity tests.

## Current Status

- Inventory state:
  - `rust_linux_sandbox_port_inventory.tsv`: `missing=0`, `in_progress=0`, `partial=0`
  - `rust_windows_sandbox_port_inventory.tsv`: `missing=0`, `in_progress=0`, `partial=0`
  - `rust_seatbelt_port_inventory.tsv`: `missing=0`, `in_progress=0`, `partial=0`
  - all `*_test_parity.tsv`: `missing=0`, `in_progress=0`, `partial=0`
  - all `*_source_parity.tsv`: `missing=0`, `in_progress=0`, `partial=0`
- Crystal gates currently pass:
  - `make format`
  - `make lint`
  - `make test`
  - `make parity`

`make parity` now executes canonical split Rust parity check scripts across:
- linux sandbox manifests against `vendor/codex/codex-rs/linux-sandbox`
- windows sandbox manifests against `vendor/codex/codex-rs/windows-sandbox-rs`
- seatbelt manifests against `plans/parity_sources/seatbelt_core`

## Next Porting Steps

1. Continue hardening Windows internals toward stricter upstream robustness, while
   preserving current public API behavior.
2. Keep inventory ledgers authoritative for parity status updates.
3. Re-run full quality gates after each inventory status transition.
