"""Turn raw scanner JSON into one pass/fail table.

Usage: python scripts/summarize.py scan-results/<branch> [--gate]

Reads whichever of these files exist in the folder and skips the rest:
semgrep.json, pip-audit.json, osv-scanner.json, gitleaks.json, checkov.json,
trivy-config.json, trivy-image.json, zap.json, dast-lite.json.
With --gate, exit 1 when any stage has blocking findings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


def _load(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text())


def count_semgrep(data) -> int:
    return len(data.get("results", []))


def count_pip_audit(data) -> int:
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    return sum(len(d.get("vulns", [])) for d in deps)


def count_osv(data) -> int:
    n = 0
    for res in data.get("results", []) or []:
        for pkg in res.get("packages", []) or []:
            n += len(pkg.get("vulnerabilities", []) or [])
    return n


def count_gitleaks(data) -> int:
    return len(data or [])


def count_checkov(data) -> int:
    reports = data if isinstance(data, list) else [data]
    return sum(
        int(r.get("summary", {}).get("failed", 0))
        for r in reports
        if isinstance(r, dict)
    )


def count_trivy(data, key: str) -> int:
    n = 0
    for res in data.get("Results", []) or []:
        for item in res.get(key, []) or []:
            if item.get("Severity", "").upper() in BLOCKING_SEVERITIES:
                n += 1
    return n


def count_zap(data, min_risk: int = 2) -> int:
    """Count ZAP alerts at Medium (2) risk or higher."""
    n = 0
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            if int(alert.get("riskcode", 0)) >= min_risk:
                n += 1
    return n


def count_dast_lite(data) -> int:
    return sum(1 for c in data.get("checks", []) if not c.get("passed"))


STAGES = [
    # (stage label, tool label, file, counter)
    ("SAST", "Semgrep", "semgrep.json", count_semgrep),
    ("SCA", "pip-audit", "pip-audit.json", count_pip_audit),
    ("SCA", "OSV-Scanner", "osv-scanner.json", count_osv),
    ("Secrets", "gitleaks", "gitleaks.json", count_gitleaks),
    ("IaC", "Checkov", "checkov.json", count_checkov),
    (
        "IaC/Dockerfile",
        "Trivy config",
        "trivy-config.json",
        lambda d: count_trivy(d, "Misconfigurations"),
    ),
    (
        "Container",
        "Trivy image",
        "trivy-image.json",
        lambda d: count_trivy(d, "Vulnerabilities"),
    ),
    ("DAST", "OWASP ZAP baseline", "zap.json", count_zap),
    ("DAST (local)", "dast-lite headers", "dast-lite.json", count_dast_lite),
]


def summarize(folder: Path) -> list[dict]:
    rows = []
    for stage, tool, fname, counter in STAGES:
        data = _load(folder / fname)
        if data is None:
            continue
        n = counter(data)
        rows.append(
            {
                "stage": stage,
                "tool": tool,
                "findings": n,
                "result": "FAIL" if n else "PASS",
            }
        )
    return rows


def render(rows: list[dict], title: str) -> str:
    out = [
        f"## Scan summary: {title}",
        "",
        "| Stage | Tool | Blocking findings | Gate |",
        "|---|---|---|---|",
    ]
    out += [
        f"| {r['stage']} | {r['tool']} | {r['findings']} | {r['result']} |"
        for r in rows
    ]
    failed = sum(r["result"] == "FAIL" for r in rows)
    out += ["", f"Stages failed: {failed}/{len(rows)}"]
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    folder = Path(argv[1])
    rows = summarize(folder)
    print(render(rows, folder.name), end="")
    if "--gate" in argv and any(r["result"] == "FAIL" for r in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
