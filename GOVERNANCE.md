# Project Governance & Continuity Policy

## 1. Governance Model

`starshield-forensics` uses an open, meritocratic **Lead Maintainer** governance model appropriate for a clean-room digital forensics library:

- **Decision Making:** Architectural changes, wire-format parser expansions, epistemic boundary definitions, and release cuts are reviewed publicly via GitHub Pull Requests and Issues at <https://github.com/Ziqi/starshield-forensics>.
- **Consensus & Escalation:** Proposed changes remain open for technical review and automated CI verification (unit tests, adversarial boundary suite, `StarShield-Bench-24`, `coverage.py >= 80%`, `Ruff`, and `Bandit`). Where trade-offs arise between feature breadth and evidentiary determinism or zero-dependency portability, **determinism, memory bounds, and stdlib-only isolation** take precedence.

## 2. Roles & Responsibilities

| Role | Current Holder(s) | Responsibilities & Permissions |
| :--- | :--- | :--- |
| **Lead Maintainer & Security Architect** | Ziqi Xiao (`@Ziqi`) | Overall technical roadmap, release engineering, offline Ed25519 cryptographic release signing, Zenodo DOI archival, and private security advisory triage. |
| **Contributors** | Open Community | Submitting bug reports, clean-room synthetic test vectors, parser improvements, documentation enhancements, and peer code reviews under MIT + DCO 1.1. |
| **Users & Evaluators** | DFIR Practitioners, Legal Clinics, Security Teams | Running offline `precheck` / carving / container checks and reporting edge cases via GitHub Issues. |

## 3. Access Continuity & Bus-Factor Resilience (`access_continuity`)

To ensure `starshield-forensics` continues with minimal interruption (creating/closing issues, accepting changes, and cutting signed releases within 7 days) even if any single individual becomes unavailable or incapacitated:

1. **Unrestricted OSI Licensing & Zero Proprietary Lock-In:** Every line of code, specification fixture, and build script is publicly hosted under the OSI-approved **MIT License** with zero proprietary build servers or external dependencies, enabling immediate fork-and-release continuity by any downstream laboratory or contributor.
2. **Permanent Institutional Archival:** Every tagged release and its `StarShield-Bench-24` corpus is permanently archived at **CERN / Zenodo** under Concept DOI [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804), independent of GitHub availability.
3. **GitHub Successor & Encrypted Lockbox Escrow:** In accordance with OpenSSF Silver continuity guidelines for solo-led FLOSS projects, repository administration credentials, GitHub Account Successor instructions, domain control records, and the offline release-signing key recovery material are maintained in an encrypted offline lockbox with documented legal transfer instructions to a designated technical custodian so issue triage and signed releases can resume within 7 days of confirmed incapacitation.
