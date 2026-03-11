# Architecture

## Intent

This project provides a reusable Crystal sandbox-planning library for AI agent
runtimes. It started as a source-faithful port of upstream sandbox behavior,
then was adapted into a standalone library.

## Structure

- `vendor/codex/` upstream source snapshot via submodule.
- `src/` Crystal implementation.
- `spec/` behavior and parity-focused tests.

## Core Concepts

- `CommandSpec`:
  User/runtime-provided input that describes what should run before sandbox wrapping.
  It includes executable intent (`program`, `args`), process context (`cwd`, `env`),
  and control metadata (`sandbox_permissions`, `justification`, optional `expiration`).

- `FileSystemSandboxPolicy`:
  Filesystem restriction model used by sandbox planning.
  The key mode is `restricted`, with optional full-disk-write bypass behavior for
  specific parity paths. `unrestricted` and `external` represent less restrictive
  or externally-managed policy modes.

- `NetworkSandboxPolicy`:
  Network restriction mode (`Enabled` or `Restricted`) used during transform and
  environment shaping. Restricted mode drives disabled-network signaling and
  backend-specific network enforcement behavior.

- `SandboxPreference` and `SandboxType`:
  `SandboxPreference` (`Auto`, `Require`, `Forbid`) controls selection behavior.
  `SandboxType` is the selected backend (`None`, `LinuxSeccomp`, `MacosSeatbelt`,
  `WindowsRestrictedToken`) for this request.

- `SandboxManager#select_initial(...)`:
  Policy decision function. Given filesystem/network policy, preference, platform,
  and Windows level, it picks the initial sandbox backend for the run.

- `SandboxManager#transform(...)`:
  Planning step that converts `CommandSpec` + selected policy/backend into a
  concrete `ExecRequest`. This is where wrapper arguments, env updates, and
  backend-specific command layout are produced.

- `ExecRequest`:
  Library-produced execution payload for your runtime to spawn.
  It contains final command argv, env, cwd, selected sandbox metadata, and copied
  request metadata (including optional `expiration`).

- `denied(...)` classification helper:
  Runtime-result helper that classifies likely sandbox denials based on sandbox
  type, stderr, and exit code. This is used after process execution to label
  restricted failures consistently.

## How It Is Used

1. Runtime builds `CommandSpec` for a tool/process request.
2. Runtime chooses or derives policies and preference.
3. Runtime calls `select_initial(...)` to pick backend.
4. Runtime calls `transform(...)` to obtain `ExecRequest`.
5. Runtime executes `ExecRequest` with its own process launcher.
6. Runtime evaluates result and optionally calls `denied(...)`.

This library owns planning and policy-to-command translation; the host runtime
owns execution, approval/elevation UX, timeout handling, and retry/streaming
behavior.

## Current Design Analysis

- Strength: clean separation between planning (`transform`) and execution (host runtime).
- Strength: cross-platform backend abstraction keeps agent integrations stable.
- Strength: policy objects are explicit and testable, which supports parity validation.
- Tradeoff: approval/elevation orchestration is intentionally external, so integrators
  must provide a consistent policy engine around `sandbox_permissions`.
