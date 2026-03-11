# Changelog

All notable changes to this project are documented in this file.

## v0.7.0 - 2026-03-11

### Added

- Linux/Windows/macOS CI matrix with parity verification on Linux.
- `make parity-verify` and adversarial split parity verification script.
- Agent-neutral sandbox customization points:
  - Linux default sandbox executable and proxy socket prefix overrides.
  - Windows sandbox state root and identity default overrides.
  - Sandbox signaling environment variable overrides.

### Changed

- README and usage docs now describe library purpose for general Crystal AI agents.
- Split parity inventories are fully completed (`ported`/`mapped`) for:
  - Linux sandbox
  - Windows sandbox
  - Seatbelt integration

### Fixed

- Linux spec parity expectation for default sandbox executable now matches upstream behavior when full-disk-write bypass is active.
