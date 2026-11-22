<!--
SPDX-FileCopyrightText: 2026 Ziqi Xiao (@Ziqi)
SPDX-License-Identifier: MIT
-->

# Cross-Tool & Specification Reference Validation Summary (`starshield-forensics v0.3.11`)

> [!IMPORTANT]
> **Scope & Non-Accreditation Notice**: Open-source technical cross-validation summary documenting reproducible execution of `scripts/verify_cross_tool_forensics.py` (`538` vectors) against external open-source reference libraries (Google `dfindexeddb` and `Pillow`, when installed in an isolated QA virtual environment via `--require-external`) and published format specifications. **This document is an engineering verification record, NOT a claim of laboratory accreditation, regulatory compliance, or certification.** Note: Historical URL path `VALIDATION_REPORT_FSR_ISO17025.md` is retained solely to prevent broken external links from prior archival records; this file is excluded from the PyPI `sdist` (`MANIFEST.in`).

---

## 1. Technical Scope (`v0.3.11`)

`starshield-forensics` (`v0.3.11`) is a deterministic, zero-dependency, offline Python standard-library command-line toolkit for read-only pre-screening of:
1. **Uncompacted Chromium & Electron LevelDB Write-Ahead Logs (`.log`)**: Frame-level recovery of `WriteBatch` records across 32,768-byte physical blocks (`FULL`, `FIRST`, `MIDDLE`, `LAST`) with Castagnoli CRC32C (`polynomial 0x82F63B78`, LevelDB `mask delta 0xA282EAD8`) verification, per-operation internal sequence progression, and UTF-8 / Blink UTF-16LE JSON extraction.
2. **PNG (`RFC 2083`), JPEG (`ISO/IEC 10918-1`) & PDF (`ISO 32000-1`) Binary Containers**: Chunk-level IEEE 802.3 CRC-32 validation, bounded `zlib` decompression (`<= 16 MiB` single-chunk / `<= 32 MiB` cumulative per-file budget) of `iCCP` profiles, multi-segment JPEG `APP2` (`ICC_PROFILE`) reassembly, `ISO 15076-1` (`acsp`) 128-byte header parsing, `APP13` (`Photoshop 3.0\x008BIM`) resource block observation, and unified lexical PDF trailer `%%EOF` / `startxref` / `xref` counting (skipping stream spans, strings, hex strings, and comments) without substring false positives.
3. **Identifier Check-Digit & Registry Syntax**: `ISO/IEC 7812` Luhn card check-digit verification, `ISO 13616` IBAN length and `ISO/IEC 7064` Mod 97-10 check-digit verification across all 89 registered SWIFT jurisdictions, and `ISO 9362` SWIFT/BIC country-code (`250` codes) and context verification. Check-digit verification confirms mathematical syntax only—it does NOT indicate fraud or prove that a payment occurred.

### Explicit Non-Goals & Epistemic Boundaries
- **Not a Compacted `.ldb` SSTable Decompressor**: `v0.3.11` does not decompress Snappy `.ldb` SSTables, follow external `.blob` directories, decode non-JSON Blink `StructuredClone` primitives, or parse newly created Chrome 156+ SQLite IndexedDB stores. `starshield precheck` emits `NO_GO_COMPACTED_OR_UNSUPPORTED` when zero carvable `.log` JSON records exist, and emits `PARTIAL` rather than `GO` whenever any `.ldb`/`.sst`, `.blob`, or co-located SQLite storage entry is present.
- **Not an Image or PDF Forgery Detector**: Container `iCCP`, `APP13`/`8BIM`, and PDF `%%EOF`/`xref` observations are structural container checks accompanied by mandatory benign `alternative_explanations`.
- **Standalone vs. External Dual-Tool Execution**: When `dfindexeddb` or `Pillow` is not installed, `scripts/verify_cross_tool_forensics.py` explicitly reports `STANDALONE SELF-CHECK ONLY` (`external_concordance_measured: false`) and never claims external concordance.

---

## 2. Test Environment & Release Provenance (`v0.3.11`)

| Parameter | Verified Value |
| :--- | :--- |
| **Subject Tool & Version** | `starshield-forensics v0.3.11` (`0` third-party runtime dependencies) |
| **Validation Harness** | [`scripts/verify_cross_tool_forensics.py`](scripts/verify_cross_tool_forensics.py) (`starshield-cross-tool-validation/v1`) |
| **Deterministic Zipapp (`starshield.pyz`)** | `7bdcf29b9471c19375251d24a9993d946224be167d5187735d2343262618a3b7` *(depends solely on `starshield/` runtime sources; verified in CI via `scripts/build_reproducible.py --verify`)* |
| **Source Tarball (`sdist`), Wheel & SPDX 2.3 SBOM** | Cryptographically bound by the release-attached offline Ed25519-signed manifest `SHA256SUMS` + `SHA256SUMS.sig` (verified against [`KEYS.pub`](KEYS.pub)), GitHub Release Sigstore provenance (`multiple.intoto.jsonl`), and PyPI Trusted Publisher PEP 740 attestations *(archive digests are not duplicated inline in repository markdown to prevent post-build hash drift or self-referential tarball circularity)* |
| **Zenodo Concept DOI** | [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) *(currently resolves to archived `v0.3.7`: `10.5281/zenodo.24156262`)* |
| **Reference Python Runtime** | CPython `3.12.13` (`Darwin-arm64` QA venv) + Ubuntu GitHub Actions CI matrix (`3.10`, `3.11`, `3.12`, `3.13`) |
| **External Comparator 1 (LevelDB WAL)** | Google [`dfindexeddb`](https://github.com/google/dfindexeddb) `20260210` (`Apache-2.0`, `dfindexeddb.leveldb.log.FileReader`, isolated QA venv via `--require-external`) |
| **External Comparator 2 (PNG / JPEG / ICC)** | [`Pillow`](https://python-pillow.org/) `13.0.0` (`PIL.Image`, isolated QA venv via `--require-external`) |
| **Specification Comparator 3 (Check-Digit Math)** | Independent `GF(10)` table-lookup Luhn (`ISO/IEC 7812`), streaming Horner `Mod 97-10` (`ISO 13616`), and `ISO 9362` registry matrix |

---

## 3. Cross-Tool & Specification Matrix (`538` Total Vectors: `6 + 6 + 526`)

When executed with `--require-external` (`dfindexeddb==20260210` and `Pillow==13.0.0` installed in an isolated QA venv), `starshield-forensics v0.3.11` passes all **`538` deterministic vectors** (`6` LevelDB WAL vectors, `6` PNG/JPEG container vectors, and `526` check-digit/registry vectors).

### 3.1 Suite 1: Chromium LevelDB `.log` WAL Carving vs. Google `dfindexeddb` (`20260210`, `6` Vectors)

| Vector ID | Scenario & Structural Boundary | Size (B) | StarShield Frames / Records | `dfindexeddb 20260210` Frames / Records | Result & Key / Value SHA-256 Comparison |
| :--- | :--- | ---: | :---: | :---: | :--- |
| **`S1-V01`** | Multi-block Blink WAL (`FULL` + 3-block `FIRST/MIDDLE/LAST`) | `68,779` | `4` valid / `0` corrupt / `2` rec | `4` phys / `2` batch / `2` val | **PASS (`100%` match on CRC32C, seq `1001`–`1002`, key & value SHA-256)** |
| **`S1-V02`** | Multi-op atomic `WriteBatch` (`kTypeValue` + `kTypeDeletion` + `kTypeValue`) | `422` | `1` valid / `0` corrupt / `2` rec | `1` phys / `1` batch / `2` val | **PASS (`100%` match on batch seq `204801`, tombstone skip, key & value SHA-256)** |
| **`S1-V03`** | 32 KiB block-trailer zero-pad (`< 7 B` remaining) + Blink `UTF-16LE` JSON | `33,279` | `2` valid / `0` corrupt / `2` rec | `2` phys / `2` batch / `2` val | **PASS (`100%` match across zero-padded block trailer + UTF-16LE value SHA-256)** |
| **`S1-V04`** | 4-block fragmented `WriteBatch` (`FIRST` + `2x MIDDLE` + `LAST`, `> 105 KiB`) | `105,264` | `4` valid / `0` corrupt / `1` rec | `4` phys / `1` batch / `1` val | **PASS (`100%` match on 4-fragment reassembly & `105 KiB` value SHA-256)** |
| **`S1-V05`** | Adversarial 1-bit payload flip (CRC32C mismatch in Block 0 + Block 1 resync) | `32,933` | `2` valid / `1` corrupt / `2` rec | `3` phys / `3` batch / `3` val* | **PASS (StarShield quarantined corrupted `seq 500002` & resynced at `32,768`; see Note 1)** |
| **`S1-V06`** | Truncated mid-frame tail (`64 B` missing at EOF simulating power loss) | `400` | `1` valid / `1` corrupt / `1` rec | N/A (`ParserError` on EOF) | **PASS (StarShield preserved committed `seq 600001` & logged `1` truncated tail frame)** |

- **Note 1 (`S1-V05` — Upstream Issue `google/dfindexeddb#92` / PR `#94`)**: `dfindexeddb 20260210` stores `PhysicalRecord.checksum` without verifying Castagnoli CRC32C (`polynomial 0x82F63B78`, `mask delta 0xA282EAD8`) prior to `WriteBatch` decoding, emitting the bit-flipped `seq 500002` record. `starshield-forensics` quarantines the corrupted frame (`corrupted_frames_count = 1`) and resynchronizes at byte `32,768`.

### 3.2 Suite 2: PNG (`RFC 2083`) & JPEG (`ISO/IEC 10918-1`) Container Framing vs. `Pillow 13.0.0` (`6` Vectors)

| Vector ID | Container Format & Test Condition | StarShield Result | `Pillow 13.0.0` (`PIL.Image`) Result | Comparison |
| :--- | :--- | :--- | :--- | :---: |
| **`S2-V01`** | Valid RFC 2083 PNG + `iCCP` (`Display P3` / `APPL`) + `Software` `tEXt` | `valid_container=True`, `Display P3`, `APPL`, `0` CRC errors | `verify()` PASS, `160 B` `acsp` ICC, `Software` matched | **PASS (`100%`)** |
| **`S2-V02`** | Valid RFC 2083 PNG + `iCCP` (`sRGB IEC61966-2.1` / `MSFT`) | `valid_container=True`, `sRGB IEC61966-2.1`, `MSFT` | `verify()` PASS, `160 B` `acsp` ICC (`MSFT`) matched | **PASS (`100%`)** |
| **`S2-V03`** | Valid ISO 10918-1 JPEG + 3-chunk split `APP2` ICC + `APP13` `8BIM` + `0xFF00` stuffing | `valid_container=True`, `3` `APP2` chunks reassembled, `1` `8BIM` offset | `format='JPEG'`, `160 B` reassembled `acsp` ICC + `photoshop` dict | **PASS (`100%`)** |
| **`S2-V04`** | Corrupted PNG `iCCP` chunk (1-bit flip breaking IEEE 802.3 CRC-32) | `valid_container=False`, `crc_errors=1` (`CRC32 mismatch`) | `verify()` raised `SyntaxError` (CRC error rejected) | **PASS (`100%`)** |
| **`S2-V05`** | Truncated JPEG container missing terminal `0xFFD9` `EOI` marker | `valid_container=False`, missing `EOI` (`0xFFD9`) flagged | Structural `EOI` absence confirmed by reference scanner | **PASS (`100%`)** |
| **`S2-V06`** | Non-image JSON chat log containing `"Photoshop 3.0\x008BIM"` & `"Display P3 acsp"` | `valid_container=False` (`UNSUPPORTED_OR_NOT_AN_IMAGE`, `0` false positives) | Raised `UnidentifiedImageError` (`0` false positives) | **PASS (`100%`)** |

### 3.3 Suite 3: Identifier Check-Digit & Registry Math Verification (`526` Vectors)

| Sub-Suite | Standard & Coverage Scope | Vectors Tested | Positive / Negative Split | Reference Comparator | Pass Rate |
| :--- | :--- | ---: | :--- | :--- | :---: |
| **`S3-V01`** | `ISO/IEC 7812` Card Luhn (`13`–`19` digits, single-digit & transposition errors, `extract_validated_iocs` separation) | `12` | `5` valid / `7` invalid | Independent `GF(10)` table-lookup Luhn | **PASS (`12 / 12`)** |
| **`S3-V02`** | `ISO 13616` / SWIFT IBAN Registry across **all `89` registered jurisdictions** (`15`-char `NO` to `33`-char `RU`) + `ISO/IEC 7064` Mod 97-10 | `184` | `89` valid / `95` invalid (`89` bad check digit + `6` unregistered/length) | Streaming Horner `Mod 97-10` evaluator | **PASS (`184 / 184`)** |
| **`S3-V03`** | `ISO 9362` SWIFT/BIC across **all `250` `ISO 3166-1` alpha-2 / `XK` territory codes** + `74` English 8-letter stopwords + banking-context gate | `330` | `251` valid / `79` invalid (`4` bad country + `74` stopwords + `1` no-context) | Exhaustive `ISO 3166-1` + context matrix | **PASS (`330 / 330`)** |

---

## 4. Local Re-Verification Commands

### A. Standalone Self-Check (Zero External Packages; Reports `STANDALONE SELF-CHECK ONLY`)
```bash
python3 scripts/verify_cross_tool_forensics.py
```

### B. Full Dual-Tool External Cross-Validation (`dfindexeddb` + `Pillow` in an Isolated Venv)
```bash
python3 -m venv /tmp/starshield-qa-venv
/tmp/starshield-qa-venv/bin/pip install --upgrade pip
/tmp/starshield-qa-venv/bin/pip install --no-deps dfindexeddb==20260210
/tmp/starshield-qa-venv/bin/pip install Pillow==13.0.0
/tmp/starshield-qa-venv/bin/python scripts/verify_cross_tool_forensics.py \
  --require-external \
  --json-out /tmp/starshield_crossval_report.json
rm -rf /tmp/starshield-qa-venv
```

### C. Binary Reproducibility & Attestation Verification
```bash
python3 scripts/build_reproducible.py --verify
python3 scripts/generate_spdx_sbom.py --verify
gh attestation verify dist/starshield.pyz --repo Ziqi/starshield-forensics
```
