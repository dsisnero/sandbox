# Usage Guide

## Quick Start

```crystal
require "sandbox"

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

# Optional Windows state root (setup markers, logs, helper metadata):
Sandbox::Sandboxing::WindowsSandbox.sandbox_home = "/var/lib/my-agent/sandbox-state"

# Optional Windows sandbox identity defaults:
Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group = "AgentSandboxUsers"
Sandbox::Sandboxing::WindowsSandbox.offline_username = "AgentSandboxOffline"
Sandbox::Sandboxing::WindowsSandbox.online_username = "AgentSandboxOnline"

# Optional sandbox signaling env var names:
Sandbox::Sandboxing.sandbox_env_var = "AGENT_SANDBOX"
Sandbox::Sandboxing.network_disabled_env_var = "AGENT_SANDBOX_NET_DISABLED"

# Optional Linux helper defaults:
Sandbox::Sandboxing::LinuxSandbox.default_linux_sandbox_exe = "agent-linux-sandbox"
Sandbox::Sandboxing::LinuxSandbox.proxy_socket_dir_prefix = "agent-linux-sandbox-proxy-"
```

## Execution Model

- This library does not execute the final process directly.
- Your runner should execute:
  - `request.command`
  - with `request.env`
  - in `request.cwd`

## What It Returns On Restricted Actions

- `manager.transform(...)` always returns an `ExecRequest` (planning output), even for commands that may later be denied by sandbox policy.
- Denial happens at execution time, not transform time.
- If a command performs a restricted action, the launched process usually returns:
  - non-zero exit code
  - stderr containing denial text (for example permission/sandbox denied wording)
- You can classify a denial with `manager.denied(sandbox_type, stderr, exit_code)`.

Example:

```crystal
status = Process.run(
  request.command.first,
  args: request.command[1..],
  env: request.env,
  chdir: request.cwd,
  output: STDOUT,
  error: STDERR
)

exit_code = status.exit_code
stderr_text = "" # capture from your runner's stderr pipe/buffer
denied = manager.denied(sandbox_type, stderr_text, exit_code)
```

Windows helper capture API behavior:

- `Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(...)` returns `CaptureResult`.
- On restricted/failed runs, `CaptureResult.exit_code` is non-zero and `CaptureResult.stderr` contains failure details.
- On non-Windows hosts, it returns a non-zero result with `stderr` indicating Windows sandbox availability is required.

## Policy Selection

- `SandboxPreference::Auto`: choose sandbox backend based on policy + platform.
- `SandboxPreference::Require`: force platform sandbox.
- `SandboxPreference::Forbid`: force no sandbox wrapping.

Typical policies:

- Restricted filesystem + restricted network:
  - maximizes sandbox wrapping.
- Unrestricted filesystem + enabled network:
  - often resolves to `SandboxType::None` in `Auto`.

## Platform Notes

- Linux:
  - Provide `linux_sandbox_exe` when Linux sandbox wrapping is expected.
  - Backward-compatible alias: `codex_linux_sandbox_exe`.
  - `use_linux_sandbox_bwrap` enables bwrap-style wrapping path.
- macOS:
  - Uses `/usr/bin/sandbox-exec` integration through seatbelt policy generation.
- Windows:
  - Uses Windows sandbox module behavior through policy-driven request transformation.
  - Configure `Sandbox::Sandboxing::WindowsSandbox.sandbox_home` to choose where Windows setup/state files are persisted.
  - Configure sandbox identity defaults for your agent:
    - `Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group`
    - `Sandbox::Sandboxing::WindowsSandbox.offline_username`
    - `Sandbox::Sandboxing::WindowsSandbox.online_username`
  - Windows setup/identity helper APIs are Windows-only and fail fast on Linux/macOS hosts.
  - `run_windows_sandbox_capture`, Windows preflight, and setup refresh/elevated setup reject insecure unsandboxed fallback by default.
  - Transitional override (not recommended): set `SBX_WINDOWS_ALLOW_INSECURE_FALLBACK=1`.

## Minimal Runner Example

```crystal
status = Process.run(
  request.command.first,
  args: request.command[1..],
  env: request.env,
  chdir: request.cwd
)
puts status.exit_code
```
