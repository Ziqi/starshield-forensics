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

## 5. OpenSSF OSPS Baseline (Level 3) & EU Cyber Resilience Act (CRA) Alignment

`starshield-forensics` maintains machine-verifiable controls aligned with the **OpenSSF Open Source Project Security (OSPS) Baseline (Level 3)** and **EU Cyber Resilience Act (Regulation (EU) 2024/2847, Annex I)** secure-by-design and vulnerability-handling principles:

| Control Domain | OSPS Baseline / EU CRA Reference | Repository Implementation & Verifiable Evidence |
| :--- | :--- | :--- |
| **Access Control & Governance** | `OSPS-AC` / `OSPS-GV` | Documented roles & continuity policy (`GOVERNANCE.md`), mandatory DCO 1.1 sign-off (`CONTRIBUTING.md`), protected `main` rulesets, and SHA-pinned GitHub Actions with `permissions: contents: read` & `persist-credentials: false` (`Scorecard Token-Permissions: 10/10`, `Dangerous-Workflow: 10/10`). |
| **Build & Release Integrity** | `OSPS-BR` / SLSA v1.0 L3 | Isolated **SLSA Build Level 3** provenance (`multiple.intoto.jsonl`), GitHub OIDC + Sigstore (`Fulcio`/`Rekor`) `/attestations`, **PyPI PEP 740** digital attestations, air-gapped OpenSSH `Ed25519` signatures (`KEYS.pub`), and bit-for-bit reproducible `starshield.pyz` (`scripts/build_reproducible.py --verify`). |
| **SBOM, Licensing & Archival** | `OSPS-DO` / `OSPS-LE` / CRA Annex I Part I §2(2) | Deterministic ISO/IEC 5962:2021 **SPDX 2.3 SBOM** (`scripts/generate_spdx_sbom.py --verify`), 100% **FSFE REUSE 3.3** SPDX compliance (`REUSE.toml`), OpenSSF `SECURITY-INSIGHTS.yml` (`v2.0.0`), CERN Zenodo DOI (`10.5281/zenodo.24145804`), and UNESCO/Inria **Software Heritage (`SWHID`)** archival (`swh:1:rel:3fa912215b0bb2510f7a2cfdfbd51293e29980c4`). |
| **Quality, SAST & Continuous Fuzzing** | `OSPS-QA` / CRA Annex I Part I §2(1) | Zero third-party runtime dependencies (`Python >= 3.10` stdlib only, `0` transitive CVEs), automated `CodeQL` + `Bandit` SAST (`10/10`), `>= 80%` coverage gate (`> 85%` actual), **ClusterFuzzLite / Atheris** continuous fuzzing (`Scorecard Fuzzing: 10/10`), and 482-vector dual-tool validation (`UK FSR Statutory Code FSA – DIG 100 / ISO 17025`). |
| **Vulnerability Handling & CVD** | `OSPS-VM` / CRA Annex I Part II | Private HTTPS reporting via GitHub Security Advisories (§2), 48-hour acknowledgment SLA, 14-day High/Critical remediation target with mandatory regression tests (§3), and coordinated GHSA/CVE advisory & signed patch publication (§4). |
| **Security Architecture & Privacy by Default** | `OSPS-SA` / CRA Annex I Part I §1 | Structured NIST IR 7608 assurance case (`SECURITY_ASSURANCE_CASE.md`), strictly offline read-only execution (`0` network sockets, `0` LLM runtime), bounded `zlib` decompression (`CWE-409`), and default ephemeral `HMAC-SHA256` output pseudonymization. |
