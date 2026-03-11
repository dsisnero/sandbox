# Development

## Setup

1. `make install`
2. Verify toolchain:
   - `crystal --version`
   - `shards --version`

## Daily Loop

1. Implement or update ported behavior in `src/`.
2. Add or update specs in `spec/`.
3. Run `make format lint test`.
4. Keep usage/concept docs current (`README.md`, `docs/usage.md`) when APIs or behavior change.
5. Keep parity notes current in docs and PR descriptions.
