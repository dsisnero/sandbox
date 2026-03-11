# Crystal Sandbox Library

Reusable sandbox library for Crystal AI agent projects.

Originally ported from sandbox code in [openai/codex](https://github.com/openai/codex), then adapted as a standalone Crystal library.

- Upstream: https://github.com/openai/codex.git
- Submodule path: `vendor/codex`
- Tracking policy: `main` branch (current pinned commit `24b8d443b82aad9f336b9c379aebbeab8667466a`)

The upstream Codex source is historical porting input, not an application constraint for this library.

Current release: `v0.7.0`
Changelog: [CHANGELOG.md](CHANGELOG.md)

## What This Library Does

This shard provides a sandbox-policy planning and command-transformation layer for
AI agent command execution:

- Chooses sandbox type by OS and policy (`none`, Linux seccomp, macOS seatbelt, Windows restricted-token level).
- Transforms a command spec into an execution request with sandbox wrapper args/env.
- Models filesystem/network permission policy shapes for sandboxed tool execution.
- Exposes Linux/macOS/Windows helper modules used by the sandbox pipeline.

It is intended to be embedded in any Crystal agent runner/orchestrator that executes the returned `ExecRequest`.

## How To Use It

Add as a shard dependency and require it:

```yaml
dependencies:
  sandbox:
    path: ../sandbox
```

```crystal
require "sandbox"
```

Use the full guide:

- [Usage Guide](docs/usage.md)
- [Architecture](docs/architecture.md)

## Project Layout

- `src/` Crystal implementation
- `spec/` Crystal specs and parity harnesses
- `vendor/codex/` upstream source as a git submodule
- `docs/` architecture and workflow notes
- `plans/inventory/` parity ledgers (`*_port_inventory.tsv`, `*_test_parity.tsv`, `*_source_parity.tsv`)

## Documentation

- [Usage Guide](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Development](docs/development.md)
- [Testing](docs/testing.md)
- [Coding Standards](docs/coding-standards.md)
- [PR Workflow](docs/pr-workflow.md)
- [Sandbox Porting Notes](docs/sandbox-porting-notes.md)

## Sandbox Port Status (Current)

- Linux sandbox port inventory: `missing=0`, `in_progress=0`, `partial=0`
- Seatbelt/core sandbox port inventory: `missing=0`, `in_progress=0`, `partial=0`
- Windows sandbox port inventory: `missing=0`, `in_progress=0`, `partial=0`
- Linux/Windows/Seatbelt test parity inventories: `missing=0`, `in_progress=0`, `partial=0`
- Linux/Windows/Seatbelt source parity inventories: `missing=0`, `in_progress=0`, `partial=0`

## Quality Gates

Use the `Makefile` commands:

- `make install`
- `make update`
- `make format`
- `make lint`
- `make test`
- `make parity`
- `make parity-verify`
- `make clean`

`make parity` runs:
- inventory status cleanliness checks
- canonical split Rust parity drift checks (linux/windows/seatbelt source + test + port inventories)

`make parity-verify` runs:
- `make parity` checks
- inventory TSV shape/quality checks
- placeholder spec checks
- full `crystal spec`

Equivalent checks:

- `crystal tool format --check src spec`
- `ameba src spec`
- `crystal spec`

CI runs these checks on GitHub Actions for:
- Linux (`ubuntu-latest`)
- macOS (`macos-latest`)
- Windows (`windows-latest`)

Workflow file: [ci.yml](.github/workflows/ci.yml)

Current gate status on this branch:
- `make lint` passes
- `make test` passes

## Next Workflow

- Use `porting-to-crystal` to implement source-faithful translations.
- Use `cross-language-crystal-parity` to generate parity inventories and drift reports.
- Keep `plans/inventory/*.tsv` status fields updated in lockstep with code/spec changes.
