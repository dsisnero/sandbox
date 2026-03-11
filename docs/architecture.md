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

- `CommandSpec`: high-level user/tool command intent.
- `FileSystemSandboxPolicy` and `NetworkSandboxPolicy`: policy inputs.
- `SandboxManager#select_initial`: chooses backend sandbox type for the host/policy.
- `SandboxManager#transform`: compiles policy + command into `ExecRequest`.
- `ExecRequest`: executable payload for your runner (`command`, `env`, `cwd`, metadata).

## Design Principle

Prefer direct, behavior-faithful translations before optimization or idiomatic
refactors.
