# Security Policy & Vulnerability Response Process

## 1. Supported Versions & Upgrade Path

`starshield-forensics` follows Semantic Versioning (`MAJOR.MINOR.PATCH`). Security fixes are applied to the latest `0.3.x` release line, with a drop-in zero-dependency upgrade path (`python3 -m pip install --upgrade starshield-forensics` or replacing the standalone `starshield.pyz` zipapp after verifying its Ed25519 signature).

| Version | Supported |
| :--- | :--- |
| `0.3.9` (latest) | Supported |
| `< 0.3.9` | Upgrade straight to `0.3.9` (CLI & JSON schemas remain backwards-compatible) |

## 2. Private Vulnerability Reporting (`vulnerability_report_private`)

Please **do not** report security vulnerabilities (such as parser memory exhaustion, zip/zlib decompression bypasses, path traversal, or redaction leaks) via public GitHub issues.

Submit reports privately over HTTPS via **GitHub Private Vulnerability Reporting**:
- **URL:** <https://github.com/Ziqi/starshield-forensics/security/advisories/new>

Include a minimal synthetic proof-of-concept input (never attach real case data) and expected vs. observed behavior.

## 3. Documented Vulnerability Response Process (`vulnerability_response_process`)

1. **Acknowledgement:** Within **48 hours** of private submission.
2. **Triage & Reproduction:** Within **5 calendar days**, confirming severity, affected versions, and CWE classification.
3. **Remediation & Regression Test:** Within **14 calendar days** for High/Critical issues (or **30 days** for Low/Medium), including a dedicated adversarial unit test in `tests/test_adversarial.py` and static/coverage verification.
4. **Coordinated Disclosure & Signed Release:** Publication of a cryptographically signed patched release ([`KEYS.pub`](./KEYS.pub) + `SHA256SUMS.sig`), GitHub Security Advisory (GHSA/CVE where applicable), and release notes documenting fixed vulnerabilities.

## 4. Reporter Credit Policy (`vulnerability_report_credit`)

All reporters of resolved security vulnerabilities are publicly credited in the corresponding GitHub Security Advisory and `Release Notes` unless the reporter requests anonymity. (No security vulnerabilities have been reported in the past 12 months.)

## 5. Supply-Chain & Repository Security Controls Summary

The repository maintains the following machine-verifiable engineering controls (documented as open-source engineering practices, not as regulatory certification or laboratory accreditation):

| Control Domain | Repository Implementation & Verifiable Artifacts |
| :--- | :--- |
| **Access Control & Governance** | Documented roles & continuity policy ([`GOVERNANCE.md`](./GOVERNANCE.md)), mandatory DCO 1.1 sign-off ([`CONTRIBUTING.md`](./CONTRIBUTING.md)), [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md), protected `main` rulesets, and SHA-pinned GitHub Actions with `permissions: contents: read` & `persist-credentials: false`. |
| **Build & Release Integrity** | Isolated **SLSA Build Level 3** provenance (`multiple.intoto.jsonl`), GitHub OIDC + Sigstore (`Fulcio`/`Rekor`) `/attestations`, **PyPI PEP 740** digital attestations, offline OpenSSH `Ed25519` signatures ([`KEYS.pub`](./KEYS.pub)), and bit-for-bit reproducible `starshield.pyz` ([`scripts/build_reproducible.py`](./scripts/build_reproducible.py)). |
| **SBOM, Licensing & Archival** | Deterministic ISO/IEC 5962:2021 **SPDX 2.3 SBOM** ([`scripts/generate_spdx_sbom.py`](./scripts/generate_spdx_sbom.py) with `--verify` version parity check), 100% **FSFE REUSE 3.3** SPDX compliance ([`REUSE.toml`](./REUSE.toml)), [`SECURITY-INSIGHTS.yml`](./SECURITY-INSIGHTS.yml), and CERN Zenodo Concept DOI (`10.5281/zenodo.24145804`). |
| **Quality, SAST & Continuous Fuzzing** | Zero third-party runtime dependencies (`Python >= 3.10` stdlib only), automated `CodeQL` + `Bandit` SAST, `>= 80%` statement coverage gate, **ClusterFuzzLite / Atheris** continuous fuzzing, and 538-vector specification/cross-tool harness ([`scripts/verify_cross_tool_forensics.py`](./scripts/verify_cross_tool_forensics.py)). |
| **Vulnerability Handling & CVD** | Private HTTPS reporting via GitHub Security Advisories (§2), 48-hour acknowledgment SLA, 14-day High/Critical remediation target with mandatory regression tests (§3), and coordinated GHSA/CVE advisory & signed patch publication (§4). |
| **Security Architecture & Privacy** | Structured NIST IR 7608 assurance case ([`SECURITY_ASSURANCE_CASE.md`](./SECURITY_ASSURANCE_CASE.md)), strictly offline read-only execution (`0` network sockets, `0` LLM runtime), bounded `zlib` decompression (`CWE-409`), and default output masking. |
