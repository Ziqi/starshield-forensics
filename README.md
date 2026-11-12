# `starshield-forensics` (`v0.3.7` — Clean-Room Deterministic DFIR Toolkit)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24145804.svg)](https://doi.org/10.5281/zenodo.24145804)
[![StarShield Deterministic CI](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/starshield-forensics/actions/workflows/ci.yml)

> **Deterministic Chromium IndexedDB / LevelDB `.log` Multi-Schema Record Carver, Zero-PII Precheck Gate, Structural Image Container Inspector & Financial Checksum Validator**
>
> **Author:** [Ziqi Xiao](https://ziqi.github.io/starshield/) (`@Ziqi`) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) · **OpenSSF Best Practices:** [`#16602 (SILVER)`](https://www.bestpractices.dev/projects/16602) · **License:** MIT · **Runtime:** Python >= 3.10 (stdlib only, zero network calls, zero LLM dependencies)

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
| **Keyed Pseudonymization & Masked Output Model** (`cli.py`) | Default masked mode applies ephemeral per-run `HMAC-SHA256` tokens (zero prefix/suffix character leakage) and suppresses raw file `SHA-256` hashes, exact byte lengths, source filenames, PNG `tEXt/iTXt` previews, custom ICC names, exact UTC dates, and failure-path `stderr` filenames/byte counts/snippets. | *Provides keyed pseudonymization for casual screen/log hygiene—NOT formal legal anonymization under UK GDPR / GDPR. Pass `--unredacted` only inside authorized offline environments.* |

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
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m starshield.cli demo
```

### CLI Subcommands (`starshield [--unredacted] [--max-mb 64] <subcommand>`)

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

Every official release (`starshield.pyz`, `.whl`, `.tar.gz`) is accompanied by `SHA256SUMS` and a detached OpenSSH `Ed25519` cryptographic signature (`SHA256SUMS.sig`) generated from an air-gapped maintainer signing key whose public verifier is distributed in [`KEYS.pub`](./KEYS.pub):

```bash
# 1. Verify detached Ed25519 signature over SHA256SUMS using standard OpenSSH (>=8.2p1):
ssh-keygen -Y verify -f KEYS.pub -I "2196305+Ziqi@users.noreply.github.com" -n file -s SHA256SUMS.sig < SHA256SUMS

# 2. Verify artifact SHA-256 digests:
shasum -a 256 -c SHA256SUMS

# 3. Rebuild starshield.pyz from source and verify bit-for-bit SHA-256 reproducibility:
python3 scripts/build_reproducible.py --verify
```

---

## Governance, Assurance Case & Security Reporting

- **Security Assurance Case & 12-Month Roadmap:** [`SECURITY_ASSURANCE_CASE.md`](./SECURITY_ASSURANCE_CASE.md)
- **Vulnerability Response Policy (48h Ack SLA):** [`SECURITY.md`](./SECURITY.md) · [GitHub Private Vulnerability Reporting](https://github.com/Ziqi/starshield-forensics/security/advisories/new)
- **Governance, Roles & Continuity Policy:** [`GOVERNANCE.md`](./GOVERNANCE.md)
- **Contribution, DCO 1.1 & Testing Standards:** [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)
- **Author:** **Ziqi Xiao** (`@Ziqi`) — [Documentation & Sample Workpaper](https://ziqi.github.io/starshield/) · [GitHub Issues](https://github.com/Ziqi/starshield-forensics/issues)
