# Crystal Sandbox Library

Reusable sandbox library for Crystal AI agent projects.

Originally ported from sandbox code in [openai/codex](https://github.com/openai/codex), then adapted as a standalone Crystal library.

- Upstream: https://github.com/openai/codex.git
- Submodule path: `vendor/codex`
- Tracking policy: `main` branch (current pinned commit `24b8d443b82aad9f336b9c379aebbeab8667466a`)

The upstream Codex source is historical porting input, not an application constraint for this library.

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

Basic usage:

```crystal
manager = Sandbox::Sandboxing.new

fs_policy = Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted
net_policy = Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted

sandbox_type = manager.select_initial(
  fs_policy,
  net_policy,
  Sandbox::Sandboxing::SandboxPreference::Auto,
  Sandbox::Sandboxing::WindowsSandboxLevel::Disabled,
  false
)

request = manager.transform(
  Sandbox::Sandboxing::CommandSpec.new(
    program: "echo",
    args: ["hello"]
  ),
  fs_policy,
  net_policy,
  sandbox_type,
  linux_sandbox_exe: "/usr/local/bin/agent-linux-sandbox",
  use_linux_sandbox_bwrap: true
)

# request.command, request.env, request.cwd are ready for your process launcher.

# Optional: set a shared Windows sandbox state root for your agent runtime.
Sandbox::Sandboxing::WindowsSandbox.sandbox_home = "/var/lib/my-agent/sandbox-state"

# Optional: customize Windows sandbox account/group names for your agent.
Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group = "AgentSandboxUsers"
Sandbox::Sandboxing::WindowsSandbox.offline_username = "AgentSandboxOffline"
Sandbox::Sandboxing::WindowsSandbox.online_username = "AgentSandboxOnline"

# Optional: customize sandbox signaling env var names.
Sandbox::Sandboxing.sandbox_env_var = "AGENT_SANDBOX"
Sandbox::Sandboxing.network_disabled_env_var = "AGENT_SANDBOX_NET_DISABLED"

# Optional Linux defaults used by helper internals.
Sandbox::Sandboxing::LinuxSandbox.default_linux_sandbox_exe = "agent-linux-sandbox"
Sandbox::Sandboxing::LinuxSandbox.proxy_socket_dir_prefix = "agent-linux-sandbox-proxy-"
```

### What The Example Is Doing

1. Create a manager:
   - `Sandbox::Sandboxing.new` returns `SandboxManager`.
2. Define policies:
   - `FileSystemSandboxPolicy.restricted` asks for restricted filesystem behavior.
   - `NetworkSandboxPolicy::Restricted` asks for restricted network behavior.
3. Pick sandbox backend:
   - `select_initial(...)` chooses a platform sandbox type (`LinuxSeccomp`, `MacosSeatbelt`, `WindowsRestrictedToken`, or `None`) based on policy + platform + preference.
4. Build executable request:
   - `transform(...)` converts your high-level `CommandSpec` into an `ExecRequest`.
   - On Linux, passing `linux_sandbox_exe` + `use_linux_sandbox_bwrap: true` wraps the command for the Linux sandbox binary.
   - Backward-compatible alias: `codex_linux_sandbox_exe`.
   - It also injects policy-derived env vars (for example network-disabled signaling under restricted network policy).
   - On Windows, `WindowsSandbox.sandbox_home` controls where setup metadata/log files are stored (defaults to current working directory unless overridden).
   - Windows sandbox identity defaults are configurable via:
     - `WindowsSandbox.sandbox_users_group`
     - `WindowsSandbox.offline_username`
     - `WindowsSandbox.online_username`
5. Execute with your own runner:
   - This library prepares the request; it does not launch the final process for you.
   - Your orchestrator should run `request.command` with `request.env` and `request.cwd`.

For deeper API docs and additional examples, see [docs/usage.md](/Users/dominic/repos/github.com/dsisnero/sandbox/docs/usage.md).

## Project Layout

- `src/` Crystal implementation
- `spec/` Crystal specs and parity harnesses
- `vendor/codex/` upstream source as a git submodule
- `docs/` architecture and workflow notes
- `plans/inventory/` parity ledgers (`*_port_inventory.tsv`, `*_test_parity.tsv`, `*_source_parity.tsv`)

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
- `make clean`

Equivalent checks:

- `crystal tool format --check src spec`
- `ameba src spec`
- `crystal spec`

CI runs these checks on GitHub Actions for:
- Linux (`ubuntu-latest`)
- macOS (`macos-latest`)
- Windows (`windows-latest`)

Workflow file: [ci.yml](/Users/dominic/repos/github.com/dsisnero/sandbox/.github/workflows/ci.yml)

Current gate status on this branch:
- `make lint` passes
- `make test` passes

## Next Workflow

- Use `porting-to-crystal` to implement source-faithful translations.
- Use `cross-language-crystal-parity` to generate parity inventories and drift reports.
- Keep `plans/inventory/*.tsv` status fields updated in lockstep with code/spec changes.
