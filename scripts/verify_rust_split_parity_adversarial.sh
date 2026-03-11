#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${ROOT_DIR}"

# 1) Canonical split drift checks.
"${SCRIPT_DIR}/check_rust_split_parity.sh" "${ROOT_DIR}"

# 2) TSV shape checks (no empty cells / trailing tabs).
for manifest in plans/inventory/rust_*_port_inventory.tsv \
                plans/inventory/rust_*_source_parity.tsv \
                plans/inventory/rust_*_test_parity.tsv; do
  if rg -n '\t\t|\t$' "${manifest}" >/dev/null 2>&1; then
    echo "Manifest contains empty TSV fields: ${manifest}" >&2
    exit 1
  fi
done

# 3) Port-inventory quality (`ported|partial` must carry refs).
ruby -e '
  bad = []
  Dir["plans/inventory/rust_*_port_inventory.tsv"].each do |file|
    File.readlines(file, chomp: true).each do |line|
      next if line.start_with?("#") || line.strip.empty?
      cols = line.split("\t", -1)
      if cols.size < 5
        bad << "#{file}: malformed row: #{line}"
        next
      end
      status = cols[2]
      refs = cols[3]
      if %w[ported partial].include?(status) && refs.to_s.strip.empty?
        bad << "#{file}: missing refs for status=#{status}: #{line}"
      end
    end
  end
  unless bad.empty?
    warn bad.join("\n")
    exit 1
  end
'

# 4) No placeholder specs.
if rg -n '\bpending\b|xit\(|xdescribe\(|xcontext\(' spec src >/dev/null 2>&1; then
  echo "Found placeholder specs in src/spec." >&2
  exit 1
fi

# 5) Crystal test gate.
CRYSTAL_CACHE_DIR="${ROOT_DIR}/.crystal-cache" crystal spec

echo "Adversarial split parity verification passed."
