# Security Policy & Vulnerability Response Process

## 1. Supported Versions & Upgrade Path

`starshield-forensics` follows Semantic Versioning (`MAJOR.MINOR.PATCH`). Security fixes are applied to the latest `0.3.x` release line, with a drop-in zero-dependency upgrade path (`python3 -m pip install --upgrade` or replacing the standalone `starshield.pyz` zipapp after verifying its Ed25519 signature).

| Version | Supported |
| :--- | :--- |
| `0.3.7` (latest) | Supported |
| `< 0.3.7` | Upgrade straight to `0.3.7` (CLI & JSON schemas remain backwards-compatible) |

## 2. Private Vulnerability Reporting (`vulnerability_report_private`)

Please **do not** report security vulnerabilities (such as parser memory exhaustion, zip/zlib decompression bypasses, path traversal, or redaction leaks) via public GitHub issues.

Submit reports privately over HTTPS via **GitHub Private Vulnerability Reporting**:
- **URL:** <https://github.com/Ziqi/starshield-forensics/security/advisories/new>

Include a minimal synthetic proof-of-concept input (never attach real case data) and expected vs. observed behavior.

## 3. Documented Vulnerability Response Process (`vulnerability_response_process`)

1. **Acknowledgement:** Within **48 hours** of private submission.
2. **Triage & Reproduction:** Within **5 calendar days**, confirming severity, affected versions, and CWE classification.
3. **Remediation & Regression Test:** Within **14 calendar days** for High/Critical issues (or **30 days** for Low/Medium), including a dedicated adversarial unit test in `tests/test_adversarial.py` and static/coverage verification.
4. **Coordinated Disclosure & Signed Release:** Publication of a cryptographically signed patched release (`KEYS.pub` + `SHA256SUMS.sig`), GitHub Security Advisory (GHSA/CVE where applicable), and release notes documenting fixed vulnerabilities.

## 4. Reporter Credit Policy (`vulnerability_report_credit`)

All reporters of resolved security vulnerabilities are publicly credited in the corresponding GitHub Security Advisory and `Release Notes` unless the reporter requests anonymity. (No security vulnerabilities have been reported in the past 12 months.)
