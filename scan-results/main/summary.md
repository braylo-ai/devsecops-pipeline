## Scan summary: main

| Stage | Tool | Blocking findings | Gate |
|---|---|---|---|
| SAST | Semgrep | 11 | FAIL |
| SCA | pip-audit | 78 | FAIL |
| SCA | OSV-Scanner | 80 | FAIL |
| Secrets | gitleaks | 4 | FAIL |
| IaC | Checkov | 35 | FAIL |
| IaC/Dockerfile | Trivy config | 13 | FAIL |
| Container | Trivy image | 18 | FAIL |
| DAST (local) | dast-lite headers | 7 | FAIL |

Stages failed: 8/8
