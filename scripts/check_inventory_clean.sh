#!/usr/bin/env sh
set -eu

inventory_dir="${1:-plans/inventory}"

if [ ! -d "$inventory_dir" ]; then
  echo "inventory directory not found: $inventory_dir" >&2
  exit 1
fi

pattern='[[:space:]](missing|partial|in_progress|needed)\b'

if command -v rg >/dev/null 2>&1; then
  if rg -n "$pattern" "$inventory_dir"/*.tsv >/dev/null 2>&1; then
    echo "inventory drift detected in $inventory_dir" >&2
    rg -n "$pattern" "$inventory_dir"/*.tsv
    exit 1
  fi
else
  if grep -En "$pattern" "$inventory_dir"/*.tsv >/dev/null 2>&1; then
    echo "inventory drift detected in $inventory_dir" >&2
    grep -En "$pattern" "$inventory_dir"/*.tsv
    exit 1
  fi
fi

echo "inventory clean: no missing/partial/in_progress/needed rows"
