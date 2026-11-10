"""Tests for the gate logic and for the committed scan evidence."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import summarize as s  # noqa: E402

RESULTS = ROOT / "scan-results"


# ------------------------------------------------------------ counters
def test_count_semgrep():
    assert s.count_semgrep({"results": [{}, {}, {}]}) == 3
    assert s.count_semgrep({"results": []}) == 0


def test_count_pip_audit_sums_vulns_per_dependency():
    data = {
        "dependencies": [{"name": "a", "vulns": [1, 2]}, {"name": "b", "vulns": []}]
    }
    assert s.count_pip_audit(data) == 2


def test_count_osv_nested_structure():
    data = {
        "results": [
            {"packages": [{"vulnerabilities": [1, 2, 3]}, {"vulnerabilities": []}]}
        ]
    }
    assert s.count_osv(data) == 3
    assert s.count_osv({"results": None}) == 0


def test_count_gitleaks():
    assert s.count_gitleaks([{"RuleID": "x"}]) == 1
    assert s.count_gitleaks([]) == 0


def test_count_checkov_handles_list_and_dict():
    assert s.count_checkov({"summary": {"failed": 4}}) == 4
    assert (
        s.count_checkov([{"summary": {"failed": 2}}, {"summary": {"failed": 3}}]) == 5
    )


def test_count_trivy_only_high_and_critical():
    data = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"Severity": "CRITICAL"},
                    {"Severity": "HIGH"},
                    {"Severity": "MEDIUM"},
                    {"Severity": "LOW"},
                ]
            }
        ]
    }
    assert s.count_trivy(data, "Vulnerabilities") == 2


def test_count_zap_medium_and_above():
    data = {
        "site": [
            {
                "alerts": [
                    {"riskcode": "3"},
                    {"riskcode": "2"},
                    {"riskcode": "1"},
                    {"riskcode": "0"},
                ]
            }
        ]
    }
    assert s.count_zap(data) == 2


def test_gate_exit_code(tmp_path):
    (tmp_path / "gitleaks.json").write_text("[]")
    assert s.main(["x", str(tmp_path), "--gate"]) == 0
    (tmp_path / "gitleaks.json").write_text('[{"RuleID": "r"}]')
    assert s.main(["x", str(tmp_path), "--gate"]) == 1


def test_missing_files_are_skipped(tmp_path):
    assert s.summarize(tmp_path) == []


# ----------------------------------------------- committed evidence
def _rows(branch):
    folder = RESULTS / branch
    if not folder.exists():
        pytest.skip(f"no committed results for {branch}")
    return {r["tool"]: r for r in s.summarize(folder)}


def test_main_branch_every_stage_fails():
    rows = _rows("main")
    assert len(rows) >= 7
    assert all(r["result"] == "FAIL" for r in rows.values()), rows


def test_fixed_branch_every_stage_passes():
    rows = _rows("fixed")
    assert len(rows) >= 7
    assert all(r["result"] == "PASS" for r in rows.values()), rows


# ----------------------------------------------- planted-secret hygiene
TOKEN_SHAPES = [
    r"ghp_[A-Za-z0-9]{36}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"sk_live_[A-Za-z0-9]{10,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
]


def _tracked_text_files():
    skip = {".git", ".venv", "scan-results", "__pycache__"}
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & skip):
            try:
                yield p, p.read_text()
            except UnicodeDecodeError:
                continue


def test_no_real_provider_token_shapes_in_repo():
    for path, text in _tracked_text_files():
        for pat in TOKEN_SHAPES:
            assert not re.search(pat, text), f"{path} matches {pat}"


def test_every_planted_secret_carries_fake_marker():
    settings = ROOT / "config" / "settings.py"
    if not settings.exists():
        pytest.skip("settings.py removed on the fixed branch")
    values = re.findall(r'=\s*"([^"]+)"', settings.read_text())
    assert values and all("PLANTED_FAKE" in v for v in values)


def test_gitleaks_report_is_redacted():
    path = RESULTS / "main" / "gitleaks.json"
    if not path.exists():
        pytest.skip("no gitleaks report")
    for finding in json.loads(path.read_text()):
        assert finding["Secret"] == "REDACTED"
