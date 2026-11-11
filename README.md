# `starshield-forensics` (`v0.3.5` — Clean-Room Alpha Prototype)

> **Deterministic Chromium IndexedDB / LevelDB `.log` Record Carver, Structural Image Container Inspector & Financial Checksum Validator**
>
> **Author:** [Ziqi Xiao](https://ziqi.github.io/starshield/) (`@Ziqi`) · **License:** MIT · **Status:** Alpha Research Prototype · **Runtime:** Python >= 3.9 (stdlib only, zero network calls, zero LLM dependencies)

---

## Scope & Operational Notice

`starshield-forensics` is an **offline, read-only digital forensics and pre-action evidence triage library** for inspecting local Chromium storage write-ahead logs (`.log`), exported web-messaging JSON caches, PNG/JPEG ICC metadata structures, and multi-jurisdiction payment identifiers (ISO/IEC 7812 Luhn, ISO 13616 IBAN Mod-97, ISO 9362 SWIFT/BIC, and intra-message UK Sort Code pairs).

All bundled fixtures in `samples/` and `starshield/data/`—plus the seeded 24-case evaluation suite in `benchmark/benchmark_suite.py` (`StarShield-Bench-24`)—are **100% clean-room specification test vectors** modeled on a fictional 2025 UK supplier-invoice scenario (`GBP 18,400.00`, ISO-13616 example IBANs `GB82WEST12345698765432` and `NO9386011117947`, Luhn test string `6200000000000005`). Zero real incident data or PII is included.

---

## Epistemic Tiers & Capability Boundary Matrix (`v0.3.5`)

Every analytical output carries an explicit machine-readable epistemic tier so investigators and solicitors never conflate raw bytes with interpretive leads:

- **`OBSERVED`**: Directly present in raw input bytes, chunk headers, or JSON fields (bound to physical WAL frame offsets or chunk offsets).
- **`DERIVED`**: Deterministically computed from raw input via standardized algorithms (Castagnoli CRC32C, ISO/IEC 7812 Luhn, ISO-13616 Mod-97, UTC delta arithmetic).
- **`INFERRED`**: Contextual triage lead requiring external corroboration (e.g., server-side bank logs or subpoenaed ISP records); never asserted as standalone proof.
- **`UNKNOWN`**: Explicitly outside the evidentiary boundary of local client artifacts (e.g., records compacted prior to acquisition).

| Module | Capability in `v0.3.5` | Epistemic Boundary & Known Limitations |
| :--- | :--- | :--- |
| **Chromium LevelDB `.log` Write-Ahead Log Parser** (`leveldb_log.py`) | Parses 32 KiB physical blocks, verifies masked Castagnoli CRC32C (`0xA282EAD8`), reassembles cross-block `FULL`/`FIRST`/`MIDDLE`/`LAST` WriteBatch frames, enforces strict op-count/length/EOF bounds, and extracts UTF-8 & Blink UTF-16LE JSON records via `JSONDecoder.raw_decode`. | *Does not decompress Snappy `.ldb` SSTables or decode non-JSON Blink `StructuredClone` primitives.* |
| **Exported Message JSON Triage** (`triage-json`) | Enumerates soft-deleted (`deletetime`) and edited (`edittime`) JSON records present in an export, extracting validated IOCs strictly per message. | *Cannot quantify records already compacted or evicted prior to acquisition.* |
| **Financial Checksum Validation** (`ioc_validators.py`) | Validates payment cards via ISO/IEC 7812 **Luhn**, IBANs via all 89 SWIFT IBAN Registry country lengths (15–34 chars) + **Mod-97**, SWIFT/BICs via all **249 ISO 3166-1 alpha-2 country codes + `XK`** (`250` total codes) + stopword filtering, and pairs UK Sort Codes within a 120-char intra-message window. | *Does not bundle proprietary Pay.UK Vocalink sort-code modulus weight tables.* |
| **RFC 2083 PNG & ISO 10918 JPEG Container Inspection** (`image_containers.py`) | Enforces PNG `IHDR` + `IDAT` + `IEND` completeness and per-chunk CRC32, bounded-decompresses `iCCP` chunks (`acsp`), and reassembles multi-chunk JPEG `APP2` `ICC_PROFILE` + `APP13` (`8BIM`) segments through `SOS`/`EOI` (`0xFFD9`). | *Emits neutral container observations + benign screenshot/OS-resave caveats; never declares standalone "proof of forgery".* |
| **Keyed Pseudonymization & Masked Output Model** (`cli.py`) | Default masked mode applies ephemeral per-run `HMAC-SHA256` tokens (zero prefix/suffix character leakage) and suppresses raw file `SHA-256` hashes, exact byte lengths, source filenames, PNG `tEXt/iTXt` previews, custom ICC names, exact UTC dates, and failure-path `stderr` filenames/byte counts/snippets. | *Provides keyed pseudonymization for casual screen/log hygiene—NOT formal legal anonymization under UK GDPR / GDPR. Pass `--unredacted` only inside authorized offline environments.* |

---

## Quickstart, CLI Reference & `StarShield-Bench-24` Reproduction

```bash
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics

# 1. Run all 22 positive, adversarial, malformed-input & canary privacy unit tests:
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -v

# 2. Run the 24-case seeded synthetic benchmark (StarShield-Bench-24, <0.2s):
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 benchmark/benchmark_suite.py

# 3. Run deterministic clean-room specification demo (salted masked mode by default):
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m starshield.cli demo
```

### CLI Subcommands (`python3 -m starshield.cli [--unredacted] [--max-mb 64] <subcommand>`)

| Subcommand | Input Artifact | Output JSON Summary |
| :--- | :--- | :--- |
| `demo` | Built-in synthetic fixtures | Runs end-to-end clean-room WAL, JSON, container, and checksum showcase |
| `parse-leveldb-log <file.log>` | Chromium LevelDB `.log` WAL | Physical block CRC32C status, byte-offset-bound carved records, and validated IOCs |
| `triage-json <export.json>` | Exported messaging JSON | Soft-deleted (`deletetime`) & edited (`edittime`) records + per-message IOC schedule |
| `inspect-image <image.png\|jpg>` | PNG or JPEG exhibit | Chunk/marker integrity, ICC profile (`acsp`) header fields, `8BIM`, and neutral caveats |
| `corroborate-timestamps <events.json>` | Timezone-aware UTC pairs | Monotonicity verification, clock-skew bounds, and edge-node frequency summary |
| `summarize-linguistics <chat.json>` | Chat transcript JSON | Descriptive utterance-length & punctuation distribution (`N >= 30` guardrailed) |

---

## Deterministic Core vs. Human-Reviewed Triage

`starshield-forensics` intentionally contains **zero LLM or network code**. Byte-offset extraction, CRC32C verification, and banking check-digit math must be 100% deterministic and reproducible, ensuring embedded adversary messages cannot trigger indirect prompt injection during extraction. Any downstream bilingual indexing or legal schedule preparation belongs in a human-reviewed workflow where every statement cites an immutable underlying record hash.

---

## Author, Security Reporting & Inquiries

- **Ziqi Xiao** (`@Ziqi`) — Independent Security Architect & Digital Forensics Researcher
- **Documentation & Sample Workpaper:** [https://ziqi.github.io/starshield/](https://ziqi.github.io/starshield/)
- **Issues & Engagement Inquiries:** [GitHub Issues (`@Ziqi/starshield-forensics`)](https://github.com/Ziqi/starshield-forensics/issues)
- **Vulnerability Disclosure:** Please use [GitHub Private Vulnerability Reporting](https://github.com/Ziqi/starshield-forensics/security/advisories/new) rather than public issues for security findings.
