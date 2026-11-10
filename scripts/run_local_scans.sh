#!/usr/bin/env bash
# Run every pipeline scanner locally and save raw JSON to scan-results/<branch>/.
# Exit codes are recorded, not hidden: a non-zero code means the gate failed.
set -u
BRANCH="${1:-$(git rev-parse --abbrev-ref HEAD)}"
OUT="scan-results/${BRANCH}"
mkdir -p "$OUT"
: > "$OUT/exit-codes.txt"
rec() { echo "$1=$2" >> "$OUT/exit-codes.txt"; }

semgrep scan --config p/python --config p/flask --config p/secrets \
  --metrics=off --error --json -o "$OUT/semgrep.json" src/ config/ >/dev/null 2>&1
rec semgrep $?

pip-audit -r requirements.txt --no-deps --disable-pip --format json \
  -o "$OUT/pip-audit.json" >/dev/null 2>&1
rec pip-audit $?

osv-scanner scan source --lockfile requirements.txt --format json \
  > "$OUT/osv-scanner.json" 2>/dev/null
rec osv-scanner $?

gitleaks dir . --config .gitleaks.toml --no-banner --redact \
  --report-format json --report-path "$OUT/gitleaks.json" >/dev/null 2>&1
rec gitleaks $?

checkov -d infra/ --quiet --compact -o json > "$OUT/checkov.json" 2>/dev/null
rec checkov $?

trivy config --severity HIGH,CRITICAL --exit-code 1 --format json \
  -o "$OUT/trivy-config.json" . >/dev/null 2>&1
rec trivy-config $?

BASE=$(awk '/^FROM/{print $2; exit}' Dockerfile)
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format json \
  -o "$OUT/trivy-image.json" "$BASE" >/dev/null 2>&1
rec trivy-image $?

python3 scripts/summarize.py "$OUT" > "$OUT/summary.md"
cat "$OUT/summary.md"
