# Policy Patterns

Agent-agnostic policy patterns for integrating this library, based on upstream
Rust behavior in `vendor/codex/codex-rs/core`.

## Why This Document Exists

`SandboxManager` exposes a compact planning API. Real-world runtimes usually
need stricter policy control (path scopes, host allowlists, per-command
permission widening, escalation prompts). This guide captures those patterns.

## Upstream-Backed Principles

From upstream Rust behavior:

- Keep default execution restricted.
- Treat permission widening as explicit, per-command intent.
- Normalize/reject empty permission requests.
- Preserve denied filesystem entries when merging path grants.
- Gate unsandboxed execution on explicit escalation intent and approval.

Reference points:

- `core/src/sandboxing/mod.rs` (effective permission merge and transform behavior)
- `core/src/tools/handlers/mod.rs` (validation rules for additional permissions)
- `protocol/src/models.rs` (`SandboxPermissions` semantics)

## Permission Intents

Use `sandbox_permissions` as an intent signal in your runtime policy layer:

- `"use_default"`: use baseline turn/session sandbox policy.
- `"with_additional_permissions"`: stay sandboxed, widen scoped permissions.
- `"require_escalated"`: request unsandboxed/host-elevated execution.

This library carries the value through `CommandSpec` and `ExecRequest`; your
runtime decides approval and final execution mode.

## Pattern 1: Baseline Restricted, Then Widen

Start with restricted defaults:

```crystal
base_fs = Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted
base_net = Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
```

For commands that need extra access, compute a per-command permission profile:

```crystal
requested = Sandbox::Sandboxing::PermissionProfile.new(
  file_system: Sandbox::Sandboxing::FileSystemPermissions.new(
    read: ["/workspace/project"],
    write: ["/workspace/project/out"]
  ),
  network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true)
)
```

Normalize and intersect with granted permissions:

```crystal
normalized = Sandbox::Sandboxing.normalize_permission_profile(requested)
raise "empty permission request" unless normalized

effective = Sandbox::Sandboxing.intersect_permission_profiles(normalized, granted_permissions)
```

## Pattern 2: Preserve Explicit Denies

If your runtime maintains denied roots, apply them during merges:

```crystal
merged_fs = Sandbox::Sandboxing.merge_file_system_permissions(
  base_permissions.file_system,
  effective.file_system,
  denied_paths
)
```

This mirrors upstream behavior where deny entries are retained and not
accidentally widened away.

## Pattern 3: Network Restricted by Default

Use `Restricted` unless the command target is explicitly approved:

```crystal
def network_policy_for(host : String?) : Sandbox::Sandboxing::NetworkSandboxPolicy
  allowed = ["api.example.com", "storage.example.com"]
  if host && allowed.includes?(host)
    Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled
  else
    Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
  end
end
```

Practical rule: if host parsing fails, treat as restricted and require review.

## Pattern 4: Escalation Is a Separate Decision

Treat `"require_escalated"` as request intent, not automatic bypass:

1. Validate command against policy.
2. Prompt/approve according to your runtime approval mode.
3. If approved, run unsandboxed or host-elevated path.
4. Otherwise deny.

This mirrors upstream split between policy evaluation and final execution mode.

## Pattern 5: Keep Planning and Execution Separate

Recommended pipeline:

1. Build `CommandSpec`.
2. Compute effective policy inputs in your runtime.
3. Call `select_initial(...)`.
4. Call `transform(...)` to get `ExecRequest`.
5. Apply approval/escalation decision.
6. Execute.
7. Classify denied results with `manager.denied(...)`.

## Integration Checklist

- Default to restricted FS/network.
- Enforce non-empty permission widening requests.
- Intersect requested with granted permissions.
- Preserve explicit denies in merged FS permissions.
- Require explicit approval for escalation.
- Log decision inputs and final mode for auditability.
