# `starshield-forensics` (`v0.3.7` — Clean-Room Deterministic DFIR Toolkit)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Ziqi/starshield-forensics/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Ziqi/starshield-forensics)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![Supply-Chain Attestations](https://github.com/Ziqi/starshield-forensics/actions/workflows/attestations.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![REUSE status](https://img.shields.io/badge/REUSE-3.3%20compliant-brightgreen)](./REUSE.toml)
[![FSR / ISO 17025 Validation](https://img.shields.io/badge/Validation-FSR--C--107%20%2F%20ISO%2017025%20Aligned-blue)](./VALIDATION_REPORT_FSR_ISO17025.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24145804.svg)](https://doi.org/10.5281/zenodo.24145804)
[![StarShield Deterministic CI](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml)

> **Deterministic Chromium IndexedDB / LevelDB `.log` Multi-Schema Record Carver, Zero-PII Precheck Gate, Structural Image Container Inspector & Financial Checksum Validator**
>
> **Author:** [Ziqi Xiao](https://ziqi.github.io/starshield/) (`@Ziqi`) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) (`v0.3.7`: [`10.5281/zenodo.24156262`](https://doi.org/10.5281/zenodo.24156262)) · **OpenSSF Best Practices:** [`#16602 (SILVER — 226%)`](https://www.bestpractices.dev/projects/16602) · **Scorecard:** [`7.1/10`](https://securityscorecards.dev/viewer/?uri=github.com/Ziqi/starshield-forensics) · **Provenance:** [SLSA L3 & Sigstore `/attestations`](https://github.com/Ziqi/starshield-forensics/attestations) · **Method Validation:** [FSR-C-107 / ISO 17025 Dual-Tool Summary](./VALIDATION_REPORT_FSR_ISO17025.md) · **License:** MIT (`REUSE 3.3`) · **Runtime:** Python >= 3.10 (stdlib only, zero network calls, zero LLM dependencies)

---

## Scope & Operational Notice

`starshield-forensics` is an **offline, read-only digital forensics and pre-action evidence triage library** for inspecting local Chromium storage write-ahead logs (`.log`), running zero-PII intake feasibility checks (`starshield precheck`), triaging exported web-messaging / B2B portal JSON caches, inspecting PNG/JPEG ICC metadata structures, and validating multi-jurisdiction payment identifiers (ISO/IEC 7812 Luhn, ISO 13616 IBAN Mod-97, ISO 9362 SWIFT/BIC, and intra-message UK Sort Code pairs).

All bundled fixtures in `samples/` and `starshield/data/`—plus the seeded 24-case evaluation suite in `benchmark/benchmark_suite.py` (`StarShield-Bench-24`)—are **100% clean-room specification test vectors** modeled on a fictional 2025 UK supplier-invoice scenario (`GBP 18,400.00`, ISO-13616 example IBANs `GB82WEST12345698765432` and `NO9386011117947`, Luhn test string `6200000000000005`). Zero real incident data or PII is included.

---

## Epistemic Tiers & Capability Boundary Matrix (`v0.3.7`)

Every analytical output carries an explicit machine-readable epistemic tier so investigators and solicitors never conflate raw bytes with interpretive leads:

- **`OBSERVED`**: Directly present in raw input bytes, chunk headers, or JSON fields (bound to physical WAL frame offsets or chunk offsets).
- **`DERIVED`**: Deterministically computed from raw input via standardized algorithms (Castagnoli CRC32C, ISO/IEC 7812 Luhn, ISO-13616 Mod-97, UTC delta arithmetic).
- **`INFERRED`**: Contextual triage lead requiring external corroboration (e.g., server-side bank logs or subpoenaed ISP records); never asserted as standalone proof.
- **`UNKNOWN`**: Explicitly outside the evidentiary boundary of local client artifacts (e.g., records compacted prior to acquisition).

| Module | Capability in `v0.3.7` | Epistemic Boundary & Known Limitations |
| :--- | :--- | :--- |
| **Zero-PII Storage Feasibility Gate** (`precheck`) | Scans Chromium IndexedDB / Local Storage folders or `.log`/`.ldb` files offline, checks LevelDB SSTable footer magic (`0xdb4775248b80fb57`), `.blob` directories, and Blink `0xFF` headers, emitting a deterministic `GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED` manifest with zero plaintext leakage. | *Pre-screens compaction status prior to triage; does not decompress `.ldb` blocks.* |
| **Chromium LevelDB `.log` Multi-Schema Carver** (`leveldb_log.py`) | Parses 32 KiB physical blocks, verifies masked Castagnoli CRC32C (`0xA282EAD8`), reassembles cross-block `FULL`/`FIRST`/`MIDDLE`/`LAST` WriteBatch frames, and extracts UTF-8 & Blink UTF-16LE JSON records across `chatsvc` (Teams/Skype), Slack Web, WhatsApp/Web Messenger, and B2B invoice portals (`--schema auto\|chatsvc\|generic-json`). | *Does not decompress Snappy `.ldb` SSTables or decode non-JSON Blink `StructuredClone` primitives (roadmap: `v0.4`).* |
| **Exported Message & Portal JSON Triage** (`triage-json`) | Enumerates soft-deleted (`deletetime` / `deleted_ts` / `is_deleted`) and edited (`edittime` / `edited.ts`) JSON records across messaging & portal exports, extracting validated IOCs strictly per record. | *Cannot quantify records already compacted or evicted prior to acquisition.* |
| **Financial Checksum Validation** (`ioc_validators.py`) | Validates payment cards via ISO/IEC 7812 **Luhn**, IBANs via all 89 SWIFT IBAN Registry country lengths (15–34 chars) + **Mod-97**, SWIFT/BICs via all **249 ISO 3166-1 alpha-2 country codes + `XK`** (`250` total codes) + stopword filtering, and pairs UK Sort Codes within a 120-char intra-message window. | *Does not bundle proprietary Pay.UK Vocalink sort-code modulus weight tables.* |
| **RFC 2083 PNG & ISO 10918 JPEG Container Inspection** (`image_containers.py`) | Enforces PNG `IHDR` + `IDAT` + `IEND` completeness and per-chunk CRC32, bounded-decompresses `iCCP` chunks (`acsp`), and reassembles multi-chunk JPEG `APP2` `ICC_PROFILE` + `APP13` (`8BIM`) segments through `SOS`/`EOI` (`0xFFD9`). | *Emits neutral container observations + benign screenshot/OS-resave caveats; never declares standalone "proof of forgery".* |
| **Keyed Pseudonymization & Cryptographic Agility** (`cli.py`) | Default masked mode applies ephemeral per-run `HMAC-SHA256` tokens (configurable via `--hmac-digest {sha256,sha384,blake2b}` and external 32-byte salt `--hmac-key-file PATH`) and suppresses raw file `SHA-256` hashes, exact byte lengths, source filenames, PNG `tEXt/iTXt` previews, custom ICC names, exact UTC dates, and failure-path `stderr` filenames/byte counts/snippets. | *Provides keyed pseudonymization for casual screen/log hygiene—NOT formal legal anonymization under UK GDPR / GDPR. Pass `--unredacted` only inside authorized offline environments.* |

---

## Installation, Zero-Install `.pyz` & `StarShield-Bench-24` Quickstart

```bash
# Option A — Zero-install single-file zipapp (for air-gapped forensic VMs & law-firm IT):
python3 starshield.pyz demo
python3 starshield.pyz precheck /path/to/readonly_chromium_idb_copy

# Option B — Clone & run all 25 unit tests + StarShield-Bench-24 (<0.2s, zero dependencies):
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 benchmark/benchmark_suite.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 scripts/verify_cross_tool_forensics.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m starshield.cli demo
```

### CLI Subcommands (`starshield [--unredacted] [--max-mb 64] [--hmac-digest {sha256,sha384,blake2b}] [--hmac-key-file PATH] <subcommand>`)

| Subcommand | Input Artifact | Output JSON Summary |
| :--- | :--- | :--- |
| `demo` | Built-in synthetic fixtures | Runs end-to-end clean-room WAL, JSON, container, and checksum showcase |
| `precheck <path> [--schema ...]` | Chromium folder or `.log`/`.ldb` | Zero-PII `GO` / `PARTIAL` / `NO_GO` feasibility & compaction check |
| `parse-leveldb-log <file.log> [--schema ...]` | Chromium LevelDB `.log` WAL | Physical block CRC32C status, byte-offset-bound carved records, and validated IOCs |
| `triage-json <export.json> [--schema ...]` | Exported messaging/portal JSON | Soft-deleted & edited records + per-record IOC schedule |
| `inspect-image <image.png\|jpg>` | PNG or JPEG exhibit | Chunk/marker integrity, ICC profile (`acsp`) header fields, `8BIM`, and neutral caveats |
| `corroborate-timestamps <events.json>` | Timezone-aware UTC pairs | Monotonicity verification, clock-skew bounds, and edge-node frequency summary |
| `summarize-linguistics <chat.json>` | Chat transcript JSON | Descriptive utterance-length & punctuation distribution (`N >= 30` guardrailed) |

---

## Deterministic Core vs. Human-Reviewed Triage

`starshield-forensics` intentionally contains **zero LLM or network code**. Byte-offset extraction, CRC32C verification, and banking check-digit math must be 100% deterministic and reproducible, ensuring embedded adversary messages cannot trigger indirect prompt injection during extraction. Any downstream bilingual indexing or legal schedule preparation belongs in a human-reviewed workflow where every statement cites an immutable underlying record hash.

---

## Cryptographic Release Verification & Bit-for-Bit Reproducibility (`v0.3.7`)

Every official release (`starshield.pyz`, `.whl`, `.tar.gz`, and ISO/IEC 5962:2021 SPDX 2.3 SBOM `starshield-forensics-0.3.7.spdx.json`) is backed by **triple cryptographic verification**:
1. **GitHub OIDC + Sigstore (`Fulcio` X.509 + `Rekor` transparency log)** build provenance & SPDX 2.3 SBOM attestations at [`/attestations`](https://github.com/Ziqi/starshield-forensics/attestations);
2. **Isolated SLSA Build Level 3** provenance (`multiple.intoto.jsonl` via `slsa-framework/slsa-github-generator`);
3. **Air-gapped OpenSSH `Ed25519`** detached maintainer signature (`SHA256SUMS.sig`) verified against [`KEYS.pub`](./KEYS.pub).

```bash
# 1. Verify Sigstore X.509 + Rekor build & SBOM attestations via GitHub CLI:
gh attestation verify starshield.pyz -R Ziqi/starshield-forensics

# 2. Verify isolated SLSA Build Level 3 provenance (.intoto.jsonl):
slsa-verifier verify-artifact starshield.pyz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/Ziqi/starshield-forensics

# 3. Offline air-gapped verification using standard OpenSSH (>=8.2p1) & SHA256SUMS:
ssh-keygen -Y verify -f KEYS.pub -I "2196305+Ziqi@users.noreply.github.com" -n file -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS

# 4. Rebuild starshield.pyz & SPDX 2.3 SBOM from source and verify bit-for-bit reproducibility:
python3 scripts/build_reproducible.py --verify
python3 scripts/generate_spdx_sbom.py --verify
```

---

## Governance, Method Validation & Security Reporting

- **Dual-Tool Forensic Method Validation (UK FSR `FSR-C-107` / `ISO/IEC 17025` Clause 7.2.2 Aligned):** [`VALIDATION_REPORT_FSR_ISO17025.md`](./VALIDATION_REPORT_FSR_ISO17025.md) (`482` test vectors cross-validated against Google `dfindexeddb 20260210` & `Pillow 13.0.0`; open-source validation aid for accredited laboratories, not a claim of laboratory accreditation)
- **OpenSSF Security Insights (v2.0.0 / OSPS Baseline) & REUSE 3.3:** [`SECURITY-INSIGHTS.yml`](./SECURITY-INSIGHTS.yml) · [`REUSE.toml`](./REUSE.toml)
- **Security Assurance Case & 12-Month Roadmap:** [`SECURITY_ASSURANCE_CASE.md`](./SECURITY_ASSURANCE_CASE.md)
- **Vulnerability Response Policy (48h Ack SLA):** [`SECURITY.md`](./SECURITY.md) · [GitHub Private Vulnerability Reporting](https://github.com/Ziqi/starshield-forensics/security/advisories/new)
- **Governance, Roles & Continuity Policy:** [`GOVERNANCE.md`](./GOVERNANCE.md)
- **Contribution, DCO 1.1 & Testing Standards:** [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)
- **Author:** **Ziqi Xiao** (`@Ziqi`) — [Documentation & Sample Workpaper](https://ziqi.github.io/starshield/) · [GitHub Issues](https://github.com/Ziqi/starshield-forensics/issues)
