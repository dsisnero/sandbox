# AGENTS

## Source Of Truth

- Upstream repository: `https://github.com/openai/codex.git`
- Local mirror path: `vendor/codex` (git submodule)
- Default ref policy: track upstream `main` and pin explicit commits in PR notes
  when needed for reproducibility.

When behavior differs, upstream wins unless this repository documents a deliberate
Crystal-specific deviation.

## Contributor Workflow

1. Sync upstream submodule state first.
2. Port behavior into `src/` and mirror validation in `spec/`.
3. Run local quality gates:
   - `make format`
   - `make lint`
   - `make test`
4. Document parity decisions in `docs/`.

## Skill Handoff

- Use `porting-to-crystal` for implementation work.
- Use `cross-language-crystal-parity` for API/test inventory and drift tracking.
- Use `find-crystal-shards` only when dependency replacement is required.
