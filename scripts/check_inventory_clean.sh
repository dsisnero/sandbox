#!/usr/bin/env sh
set -eu

inventory_dir="${1:-plans/inventory}"

if [ ! -d "$inventory_dir" ]; then
  echo "inventory directory not found: $inventory_dir" >&2
  exit 1
fi

if rg -n '\t(missing|partial|in_progress|needed)\b' "$inventory_dir"/*.tsv >/dev/null 2>&1; then
  echo "inventory drift detected in $inventory_dir" >&2
  rg -n '\t(missing|partial|in_progress|needed)\b' "$inventory_dir"/*.tsv
  exit 1
fi

echo "inventory clean: no missing/partial/in_progress/needed rows"
