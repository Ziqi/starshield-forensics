# `starshield-forensics` (`v0.3.8` — Clean-Room Deterministic DFIR & MCP Toolkit)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![OSPS Baseline](https://img.shields.io/badge/OpenSSF%20OSPS%20Baseline-Level%203%20%28EU%20CRA%20Aligned%29-brightgreen)](./SECURITY.md#5-openssf-osps-baseline-level-3--eu-cyber-resilience-act-cra-alignment)
[![UK FSR Statutory Code / ISO 17025 Validation](https://img.shields.io/badge/Validation-UK%20FSR%20%28FSA--DIG--100%29%20%26%20ISO%2017025%20Aligned-blue)](./VALIDATION_REPORT_FSR_ISO17025.md)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/0.3.8/)

> **English** | **[简体中文 (`README.zh-CN.md`)](./README.zh-CN.md)**

> **Deterministic Chromium & Electron IndexedDB / LevelDB `.log` Multi-Schema Record Carver, Structural PNG/JPEG Container Inspector, Financial Checksum Validator & Zero-Dependency `MCP` Server**
>
> **Author:** [Ziqi Xiao](https://ziqi.github.io/starshield/) (`@Ziqi`) · **PyPI:** [`starshield-forensics 0.3.8 (PEP 740)`](https://pypi.org/project/starshield-forensics/0.3.8/) · **Homebrew:** [`Ziqi/tap/starshield-forensics`](https://github.com/Ziqi/homebrew-tap) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) (`v0.3.7`: [`10.5281/zenodo.24156262`](https://doi.org/10.5281/zenodo.24156262)) · **SWHID:** [`swh:1:snp:4ed5efec...`](https://archive.softwareheritage.org/swh:1:snp:4ed5efecab5e40975e75a5c5107b63121b1df60a;origin=https://github.com/Ziqi/starshield-forensics) · **OpenSSF Best Practices:** [`#16602 (SILVER — 226%)`](https://www.bestpractices.dev/projects/16602) · **Scorecard:** [`8.0 / 10 (Fuzzing 10/10 · 11/18 Perfect Checks)`](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml) · **Provenance:** [SLSA L3 & Sigstore `/attestations`](https://github.com/Ziqi/starshield-forensics/attestations) · **Method Validation:** [UK FSR Statutory Code (`FSA – DIG 100`) / ISO 17025 Summary](./VALIDATION_REPORT_FSR_ISO17025.md) · **License:** MIT (`REUSE 3.3`) · **Runtime:** Python >= 3.10 (stdlib only, zero network calls, zero LLM dependencies)

---

## High-Frequency Use Cases (DFIR, FinTech Audit & Developer Diagnostics)

`starshield-forensics` is an **offline, read-only binary inspection and evidence triage toolkit** serving three primary audiences with zero third-party dependencies:

1. **FinTech, E-Commerce & Expense-Audit Screenshot Pre-Screening (`starshield inspect-image`)**: Millisecond structural verification of reimbursement receipts, payment screenshots, and disputed attachments—verifying RFC 2083 PNG chunk CRC32 integrity (`IHDR`/`IDAT`/`IEND`/`iCCP`), multi-segment ISO 10918 JPEG `APP2 ICC_PROFILE` color headers (`acsp`), and Photoshop `APP13 (8BIM)` resource blocks alongside offline ISO-7812 Luhn / 89-country ISO-13616 IBAN Mod-97 / ISO-9362 SWIFT validation.
2. **Developer & IT Offline Diagnostics for Corrupted Electron / Chrome Caches (`starshield precheck` & `parse-leveldb-log`)**: Read-only local health check and uncompacted `.log` write-ahead log recovery for corrupted Chromium browser (`Chrome`, `Edge`, `Brave`) and **Electron desktop app (`VS Code`, `Slack`, `Microsoft Teams`, `Discord`, `WhatsApp Desktop`)** IndexedDB / Local Storage caches using strict masked Castagnoli CRC32C (`0xA282EAD8`) verification.
3. **Legal & DFIR Pre-Action Evidentiary Triage (`UK FSR FSA – DIG 100` / `ISO 17025` Aligned)**: Byte-offset-cited carving of soft-deleted or edited web-messaging and B2B portal records with explicit four-tier epistemic tagging (`OBSERVED` / `DERIVED` / `INFERRED` / `UNKNOWN`) and ephemeral `HMAC-SHA256` pseudonymization.

All bundled fixtures in `samples/` and `starshield/data/`—plus the seeded 24-case evaluation suite in `benchmark/benchmark_suite.py` (`StarShield-Bench-24`)—are **100% clean-room specification test vectors** modeled on a fictional 2025 UK supplier-invoice scenario (`GBP 18,400.00`, ISO-13616 example IBANs `GB82WEST12345698765432` and `NO9386011117947`, Luhn test string `6200000000000005`). Zero real incident data or PII is included.

---

## Epistemic Tiers & Capability Boundary Matrix (`v0.3.8`)

Every analytical output carries an explicit machine-readable epistemic tier so investigators and solicitors never conflate raw bytes with interpretive leads:

- **`OBSERVED`**: Directly present in raw input bytes, chunk headers, or JSON fields (bound to physical WAL frame offsets or chunk offsets).
- **`DERIVED`**: Deterministically computed from raw input via standardized algorithms (Castagnoli CRC32C, ISO/IEC 7812 Luhn, ISO-13616 Mod-97, UTC delta arithmetic).
- **`INFERRED`**: Contextual triage lead requiring external corroboration (e.g., server-side bank logs or subpoenaed ISP records); never asserted as standalone proof.
- **`UNKNOWN`**: Explicitly outside the evidentiary boundary of local client artifacts (e.g., records compacted prior to acquisition).

| Module | Capability in `v0.3.8` | Epistemic Boundary & Known Limitations |
| :--- | :--- | :--- |
| **Zero-PII Storage Feasibility Gate** (`precheck`) | Scans Chromium & Electron IndexedDB / Local Storage folders or `.log`/`.ldb` files offline, checks LevelDB SSTable footer magic (`0xdb4775248b80fb57`), `.blob` directories, and Blink `0xFF` headers, emitting a deterministic `GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED` manifest with zero plaintext leakage. | *Pre-screens compaction status prior to triage; does not decompress `.ldb` blocks.* |
| **Chromium & Electron LevelDB `.log` Carver** (`leveldb_log.py`) | Parses 32 KiB physical blocks, verifies masked Castagnoli CRC32C (`0xA282EAD8`), reassembles cross-block `FULL`/`FIRST`/`MIDDLE`/`LAST` WriteBatch frames, and extracts UTF-8 & Blink UTF-16LE JSON records across Chromium browsers and Electron desktop apps (`chatsvc` for Microsoft Teams/Skype, Slack, WhatsApp Web/Desktop, Discord, `VS Code`, and B2B invoice portals via `--schema auto\|chatsvc\|generic-json`). | *Does not decompress Snappy `.ldb` SSTables or decode non-JSON Blink `StructuredClone` primitives (roadmap: `v0.4`).* |
| **Exported Message & Portal JSON Triage** (`triage-json`) | Enumerates soft-deleted (`deletetime` / `deleted_ts` / `is_deleted`) and edited (`edittime` / `edited.ts`) JSON records across messaging & portal exports, extracting validated IOCs strictly per record. | *Cannot quantify records already compacted or evicted prior to acquisition.* |
| **Financial Checksum Validation** (`ioc_validators.py`) | Validates payment cards via ISO/IEC 7812 **Luhn**, IBANs via all 89 SWIFT IBAN Registry country lengths (15–34 chars) + **Mod-97**, SWIFT/BICs via all **249 ISO 3166-1 alpha-2 country codes + `XK`** (`250` total codes) + stopword filtering, and pairs UK Sort Codes within a 120-char intra-message window. | *Does not bundle proprietary Pay.UK Vocalink sort-code modulus weight tables.* |
| **RFC 2083 PNG & ISO 10918 JPEG Container Inspection** (`image_containers.py`) | Enforces PNG `IHDR` + `IDAT` + `IEND` completeness and per-chunk CRC32, bounded-decompresses `iCCP` chunks (`acsp`), and reassembles multi-chunk JPEG `APP2` `ICC_PROFILE` + `APP13` (`8BIM`) segments through `SOS`/`EOI` (`0xFFD9`). | *Emits neutral container observations + benign screenshot/OS-resave caveats; never declares standalone "proof of forgery".* |
| **Zero-Dependency `MCP` Server** (`mcp_server.py` / `starshield mcp`) | Exposes 4 read-only deterministic tools (`starshield_demo`, `starshield_precheck_leveldb`, `starshield_inspect_image_tamper`, `starshield_validate_financial_iocs`) over JSON-RPC 2.0 `stdio` (newline & `Content-Length` framed) for Claude Desktop, Cursor, Google Antigravity, and Windsurf. | *Enforces `HMAC-SHA256` masked mode by default so cloud LLMs never receive raw PII, filenames, or raw SHA-256 hashes.* |
| **Keyed Pseudonymization & Cryptographic Agility** (`cli.py`) | Default masked mode applies ephemeral per-run `HMAC-SHA256` tokens (configurable via `--hmac-digest {sha256,sha384,blake2b}` and external 32-byte salt `--hmac-key-file PATH`) and suppresses raw file `SHA-256` hashes, exact byte lengths, source filenames, PNG `tEXt/iTXt` previews, custom ICC names, exact UTC dates, and failure-path `stderr` filenames/byte counts/snippets. | *Provides keyed pseudonymization for casual screen/log hygiene—NOT formal legal anonymization under UK GDPR / GDPR. Pass `--unredacted` only inside authorized offline environments.* |

---

## 10-Second Zero-Install Tryout (`uvx`) & Installation (`pip` PEP 740 / `.pyz`)

```bash
# Instant zero-install clean-room showcase (fetches PyPI wheel directly, zero repo clone needed):
uvx --from starshield-forensics starshield demo

# Option A — Official PyPI package (with PEP 740 Sigstore digital attestations, zero dependencies):
pip install starshield-forensics
starshield demo

# Option A2 — macOS / Linux Homebrew Tap (isolated virtualenv formula, zero dependencies):
brew install Ziqi/tap/starshield-forensics && starshield demo

# Option B — Zero-install single-file zipapp (for air-gapped forensic VMs & law-firm IT):
python3 starshield.pyz demo
python3 starshield.pyz precheck /path/to/readonly_chromium_idb_copy

# Option C — Clone & run all 26 unit/MCP tests, fuzzing harness & StarShield-Bench-24 (<1s, zero dependencies):
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -W error tests/fuzz_parsers.py --stdlib --iterations 2500
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 benchmark/benchmark_suite.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 scripts/verify_cross_tool_forensics.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m starshield.cli demo
```

### Zero-Install AI Agent Integration (`starshield mcp` for Claude Desktop, Cursor, Antigravity & Windsurf)

Mount StarShield's 4 deterministic read-only binary inspection tools directly into any MCP client (privacy-masked by default via ephemeral `HMAC-SHA256` so cloud LLMs never see raw PII, filenames, or raw hashes):

```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics", "starshield", "mcp"]
    }
  }
}
```

### Sample Deterministic Output (`starshield demo`, Default Masked Mode)

```json
{
  "epistemic_tier": "OBSERVED",
  "schema_detected": "chatsvc",
  "leveldb_batch_byte_offset": 397,
  "leveldb_sequence_number": 1002,
  "is_soft_deleted_in_ui": true,
  "sender_mri": "[REDACTED_HMAC:1b71a34908e1]",
  "cached_content": "[REDACTED_CONTENT — pass --unredacted to view]",
  "extracted_iocs": {
    "luhn_validated_cards": ["[REDACTED_HMAC:3ec5f5677098]"],
    "mod97_validated_ibans": ["[REDACTED_HMAC:4dad6b1cc0be]", "[REDACTED_HMAC:f21864d3e75c]"]
  }
}
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
| `mcp` | JSON-RPC 2.0 `stdio` stream | Read-only MCP server exposing `starshield_demo`, `starshield_precheck_leveldb`, `starshield_inspect_image_tamper`, and `starshield_validate_financial_iocs` |

---

## Deterministic Core vs. Human-Reviewed Triage

`starshield-forensics` intentionally contains **zero LLM or network code**. Byte-offset extraction, CRC32C verification, and banking check-digit math must be 100% deterministic and reproducible, ensuring embedded adversary messages cannot trigger indirect prompt injection during extraction. Any downstream bilingual indexing or legal schedule preparation belongs in a human-reviewed workflow where every statement cites an immutable underlying record hash.

---

## Cryptographic Release Verification & Bit-for-Bit Reproducibility (`v0.3.8`)

Every official release (`starshield.pyz`, `.whl`, `.tar.gz`, and ISO/IEC 5962:2021 SPDX 2.3 SBOM `starshield-forensics-0.3.8.spdx.json`) is backed by **triple cryptographic verification**:
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

| Verification / Archival Dimension | Live Status & Permanent Identifier |
| :--- | :--- |
| **Continuous Fuzzing (`ClusterFuzzLite / Atheris`)** | [![Fuzzing: 10/10](https://img.shields.io/badge/Scorecard%20Fuzzing-10%2F10%20%28ClusterFuzzLite%29-brightgreen)](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml) [![Continuous Fuzzing](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/cflite.yml) |
| **Static Security (`CodeQL SAST`) & Deterministic CI** | [![CodeQL SAST](https://github.com/Ziqi/starshield-forensics/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/codeql.yml) [![StarShield Deterministic CI](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml) |
| **Supply-Chain Provenance & Licensing (`REUSE 3.3`)** | [![Supply-Chain Attestations](https://github.com/Ziqi/starshield-forensics/actions/workflows/attestations.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/attestations) [![REUSE status](https://img.shields.io/badge/REUSE-3.3%20compliant-brightgreen)](./REUSE.toml) |
| **Packaging (`Homebrew Tap`) & Scholarly / UNESCO Archival** | [![Homebrew Tap](https://img.shields.io/badge/Homebrew-Ziqi%2Ftap-FBB040.svg?logo=homebrew&logoColor=white)](https://github.com/Ziqi/homebrew-tap) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24145804.svg)](https://doi.org/10.5281/zenodo.24145804) [![SWHID](https://img.shields.io/badge/SWHID-swh%3A1%3Asnp%3A4ed5efec-e20026)](https://archive.softwareheritage.org/swh:1:snp:4ed5efecab5e40975e75a5c5107b63121b1df60a;origin=https://github.com/Ziqi/starshield-forensics) |

- **Dual-Tool Forensic Method Validation (UK FSR Statutory Code `FSA – DIG 100` [superseding `FSR-C-107`] & `ISO/IEC 17025` Clause 7.2.2 Aligned):** [`VALIDATION_REPORT_FSR_ISO17025.md`](./VALIDATION_REPORT_FSR_ISO17025.md) (`482` test vectors cross-validated against Google `dfindexeddb 20260210` & `Pillow 13.0.0`; open-source validation aid for accredited laboratories, not a claim of laboratory accreditation)
- **OpenSSF Security Insights (v2.0.0), OSPS Baseline Level 3 (EU CRA Aligned) & REUSE 3.3:** [`SECURITY-INSIGHTS.yml`](./SECURITY-INSIGHTS.yml) · [`SECURITY.md §5`](./SECURITY.md#5-openssf-osps-baseline-level-3--eu-cyber-resilience-act-cra-alignment) · [`REUSE.toml`](./REUSE.toml) · **SWHID (`v0.3.7`):** [`swh:1:rel:3fa912215b0bb2510f7a2cfdfbd51293e29980c4`](https://archive.softwareheritage.org/swh:1:rel:3fa912215b0bb2510f7a2cfdfbd51293e29980c4;origin=https://github.com/Ziqi/starshield-forensics)
- **Security Assurance Case & 12-Month Roadmap:** [`SECURITY_ASSURANCE_CASE.md`](./SECURITY_ASSURANCE_CASE.md)
- **Vulnerability Response Policy (48h Ack SLA):** [`SECURITY.md`](./SECURITY.md) · [GitHub Private Vulnerability Reporting](https://github.com/Ziqi/starshield-forensics/security/advisories/new)
- **Governance, Roles & Continuity Policy:** [`GOVERNANCE.md`](./GOVERNANCE.md)
- **Contribution, DCO 1.1 & Testing Standards:** [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)
- **Author:** **Ziqi Xiao** (`@Ziqi`) — [Documentation & Sample Workpaper](https://ziqi.github.io/starshield/) · [GitHub Issues](https://github.com/Ziqi/starshield-forensics/issues)
