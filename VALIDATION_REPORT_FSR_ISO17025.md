<!--
SPDX-FileCopyrightText: 2026 Ziqi Xiao (@Ziqi)
SPDX-License-Identifier: MIT
-->

# Dual-Tool Forensic Method Validation Summary (`FSR-C-107` / `ISO/IEC 17025` Clause 7.2.2 Alignment)

> [!IMPORTANT]
> **Scope & Accreditation Disclaimer**: Self-contained open-source tool validation summary structured in alignment with UK Forensic Science Regulator (FSR) Code of Practice (`FSR-C-100` / `FSR-C-107`) and `ISO/IEC 17025:2017` Clause 7.2.2 to assist accredited forensic laboratories, Expert Witnesses, and instructing solicitors in their local method-validation workflows — **not a claim of laboratory accreditation**. Under UK Criminal Procedure Rules (`CrimPR Part 19`), Civil Procedure Rules (`CPR Part 35`), and `FSR-C-107`, final validation sign-off within a specific laboratory environment remains the responsibility of the deploying forensic unit.

---

## 1. Validation Scope & Intended Use (`ISO/IEC 17025` Clause 7.2.2.1)

`starshield-forensics` (`v0.3.7`) is a deterministic, zero-dependency, offline Python standard-library command-line toolkit designed for reproducible triage of:
1. **Uncompacted Chromium LevelDB Write-Ahead Logs (`.log`)**: Frame-level recovery of IndexedDB / Web Storage `WriteBatch` records across 32,768-byte physical blocks (`FULL`, `FIRST`, `MIDDLE`, `LAST`) with masked Castagnoli CRC32C (`0x82F63B78`) verification and Blink/V8 serialized JSON payload extraction (`UTF-8` and `UTF-16LE`).
2. **PNG (`RFC 2083`) & JPEG (`ISO/IEC 10918-1`) Binary Containers**: Chunk-level IEEE 802.3 CRC-32 validation, bounded `zlib` decompression (`<= 16 MiB`) of `iCCP` profiles, multi-segment JPEG `APP2` (`ICC_PROFILE`) reassembly, `ISO 15076-1` (`acsp`) 128-byte header parsing, and `APP13` (`Photoshop 3.0\x008BIM`) resource detection without naive substring false positives.
3. **Multi-Jurisdiction Financial Indicators**: `ISO/IEC 7812` Luhn card check-digit verification, `ISO 13616` IBAN length and `ISO/IEC 7064` Mod 97-10 check-digit verification across all 89 registered SWIFT jurisdictions, and `ISO 9362` SWIFT/BIC country-code (`250` codes) and context validation.

### Explicit Non-Goals & Epistemic Boundaries
- **Not a Compacted `.ldb` SSTable Decompressor**: Chromium LevelDB tables that have already compacted into Snappy- or Zstandard-compressed `.ldb` SSTables require an external library such as Google `dfindexeddb` or `ccl_chromium_reader`. `starshield precheck` deterministically detects `.ldb`-only directories and emits `NO_GO_COMPACTED_OR_UNSUPPORTED` prior to engagement.
- **Not an Image Pixel Forgery Detector**: Container `iCCP` (`Display P3`, `sRGB`) and `APP13`/`8BIM` observations are tagged `OBSERVED` / `DERIVED` alongside mandatory benign `alternative_explanations`; the tool never claims "mathematical proof of forgery".
- **Pseudonymization vs. Legal Anonymization**: Default output applies ephemeral per-run keyed `HMAC-SHA256` pseudonymization (`[REDACTED_HMAC:...]`), which prevents cross-report dictionary confirmation but does not constitute formal legal anonymization under UK GDPR / GDPR Recital 26.

---

## 2. Test Environment & Cryptographic Release Provenance

| Parameter | Verified Value |
| :--- | :--- |
| **Subject Tool & Version** | `starshield-forensics v0.3.7` (`0` third-party runtime dependencies) |
| **Validation Harness** | [`scripts/verify_cross_tool_forensics.py`](scripts/verify_cross_tool_forensics.py) (`starshield-cross-tool-validation/v1`) |
| **Deterministic Zipapp (`starshield.pyz`)** | `e6603ef083b20a5460bf56818f63a3a94b856deb377a5b6330be2394e0e21232` (`SOURCE_DATE_EPOCH=1767225600`) |
| **Python Wheel (`.whl`) SHA-256** | `4ffe6454c4ec78d3485326a4ac763ce1abaa1205009b057d07f69ad99dc37730` |
| **Source Tarball (`.tar.gz`) SHA-256** | `2dd56e823d46fd41d570ee6281d98db120ad64e64b55950827ef57c186e40edd` |
| **SLSA Build Level 3 Provenance** | `multiple.intoto.jsonl` (`048cba50acd4cc8250368df5dcaa3753fc189fa8ee6fc7fcfb4b0b7a8517fafc`) |
| **SPDX 2.3 Software Bill of Materials** | `starshield-forensics-0.3.7.spdx.json` (`67ce4adc4033db1051e7c46344e4ffb8ae2d075a71a485f02691a7974a676a3b`) |
| **Archival Zenodo DOI** | [`10.5281/zenodo.24156262`](https://doi.org/10.5281/zenodo.24156262) (Concept DOI `10.5281/zenodo.24145804`) |
| **OpenSSF Supply-Chain Posture** | OpenSSF Best Practices **SILVER** ([`#16602`](https://www.bestpractices.dev/en/projects/16602), `226%`) · OpenSSF Scorecard **`7.1/10`** |
| **Reference Python Runtime** | CPython `3.12.13` (`Darwin-arm64` QA run) + Ubuntu GitHub Actions CI matrix (`3.10`, `3.11`, `3.12`, `3.13`) |
| **External Comparator 1 (LevelDB WAL)** | Google [`dfindexeddb`](https://github.com/google/dfindexeddb) `20260210` (`Apache-2.0`, `dfindexeddb.leveldb.log.FileReader`, isolated QA venv) |
| **External Comparator 2 (PNG / JPEG / ICC)** | [`Pillow`](https://python-pillow.org/) `13.0.0` (`PIL.Image`, isolated QA venv) + clean-room RFC 2083 / ISO 10918-1 reference verifiers |
| **External Comparator 3 (ISO Banking Math)** | Clean-room `GF(10)` table-lookup Luhn (`ISO/IEC 7812`), streaming Horner `Mod 97-10` (`ISO 13616`), and `ISO 9362` registry matrix |

---

## 3. Dual-Tool Concordance Matrix (`ISO/IEC 17025` Clause 7.2.2.2)

Across all three validation suites (**`482` deterministic binary and mathematical test vectors**), `starshield-forensics v0.3.7` achieved **`100.0%` concordance** with external reference tools on all specification-compliant inputs and satisfied **`100.0%` of adversarial quarantine and negative-rejection gates**.

### 3.1 Suite 1: Chromium LevelDB `.log` WAL Carving vs. Google `dfindexeddb` (`20260210`)

| Vector ID | Scenario & Structural Boundary | Size (B) | Input SHA-256 | StarShield Frames / Records | `dfindexeddb 20260210` Frames / Records | Result & Key / Value SHA-256 Concordance |
| :--- | :--- | ---: | :--- | :---: | :---: | :--- |
| **`S1-V01`** | `EXH-01` canonical multi-block Blink WAL (`FULL` + 3-block `FIRST/MIDDLE/LAST`) | `68,779` | `c2ac19e91535c2a6...e75bf6b172ff` | `4` valid / `0` corrupt / `2` rec | `4` phys / `2` batch / `2` val | **PASS (`100%` exact match on CRC32C, seq `1001`–`1002`, key & value SHA-256)** |
| **`S1-V02`** | Multi-op atomic `WriteBatch` (`kTypeValue` + `kTypeDeletion` tombstone + `kTypeValue`) | `422` | `feb95031e262eac6...f11d0a54258` | `1` valid / `0` corrupt / `2` rec | `1` phys / `1` batch / `2` val | **PASS (`100%` exact match on batch seq `204801`, tombstone skip, key & value SHA-256)** |
| **`S1-V03`** | 32 KiB block-trailer zero-pad (`< 7 B` remaining) + Blink V8 `UTF-16LE` JSON | `33,279` | `a15d6311bbd98752...35db07617fa` | `2` valid / `0` corrupt / `2` rec | `2` phys / `2` batch / `2` val | **PASS (`100%` exact match across zero-padded block trailer + UTF-16LE value SHA-256)** |
| **`S1-V04`** | 4-block fragmented `WriteBatch` (`FIRST` + `2x MIDDLE` + `LAST`, `> 105 KiB`) | `105,264` | `59fd1f755334e70b...78877a4574f` | `4` valid / `0` corrupt / `1` rec | `4` phys / `1` batch / `1` val | **PASS (`100%` exact match on 4-fragment reassembly & `105 KiB` value SHA-256)** |
| **`S1-V05`** | Adversarial 1-bit payload flip (CRC32C mismatch in Block 0 + Block 1 resync) | `32,933` | `4bcd6211257960d6...3f5338b569a9` | `2` valid / `1` corrupt / `2` rec | `3` phys / `3` batch / `3` val* | **PASS (StarShield quarantined corrupted `seq 500002` & resynced at `32,768`; see Note 1)** |
| **`S1-V06`** | Truncated mid-frame tail (`64 B` missing at EOF simulating power loss) | `400` | `a76539e0aef5cad9...d1d6eee9e07d` | `1` valid / `1` corrupt / `1` rec | N/A (`ParserError` on EOF) | **PASS (StarShield preserved committed `seq 600001` & logged `1` truncated tail frame)** |

#### Empirical Cross-Tool Engineering Observations (Suite 1)
1. **Note 1 — Masked Castagnoli CRC32C Quarantine vs. Unchecked Emit (`S1-V05`)**: Inspection and execution against `dfindexeddb 20260210` (`dfindexeddb/leveldb/log.py`, `PhysicalRecord.FromDecoder`) confirmed that `dfindexeddb` decodes and stores the 32-bit `PhysicalRecord.checksum` header field without verifying masked Castagnoli CRC32C prior to `WriteBatch` parsing, causing it to emit the bit-flipped `seq 500002` record. `starshield-forensics` enforces masked Castagnoli CRC32C verification on every physical frame, quarantining the corrupted frame (`corrupted_frames_count = 1`) with exact byte offset and stored/expected CRC hex values while cleanly resynchronizing at the next 32,768-byte block boundary (`seq 500003`).
2. **Note 2 — Multi-Operation `WriteBatch` Sequence Number Convention (`S1-V02`)**: In `starshield-forensics`, `leveldb_sequence_number` records the raw 8-byte `WriteBatch` header base sequence number (`WriteBatch.sequence_number` in `dfindexeddb`, e.g., `204801`), whereas `dfindexeddb`'s `ParsedInternalKey.sequence_number` computes `batch.sequence_number + relative_op_index` (`204801`, `204803`). Investigators correlating multi-operation batches across both tools should match `starshield`'s `leveldb_sequence_number` to `dfindexeddb`'s `WriteBatch.sequence_number` alongside `key_sha256` and `value_sha256`.

---

### 3.2 Suite 2: PNG (`RFC 2083`) & JPEG (`ISO/IEC 10918-1`) Container Framing vs. `Pillow 13.0.0`

| Vector ID | Container Format & Test Condition | Input SHA-256 | StarShield Result | `Pillow 13.0.0` (`PIL.Image`) Result | Concordance |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **`S2-V01`** | Valid RFC 2083 PNG + `iCCP` (`Display P3` / `APPL`) + `Software` `tEXt` | `068e9a47ee0f1444...106aea2bf` | `valid_container=True`, `Display P3`, `APPL`, `0` CRC errors | `verify()` PASS, `160 B` `acsp` ICC, `Software` matched | **PASS (`100%`)** |
| **`S2-V02`** | Valid RFC 2083 PNG + `iCCP` (`sRGB IEC61966-2.1` / `MSFT`) | `5db2d92fd7899635...ef52adf03a` | `valid_container=True`, `sRGB IEC61966-2.1`, `MSFT` | `verify()` PASS, `160 B` `acsp` ICC (`MSFT`) matched | **PASS (`100%`)** |
| **`S2-V03`** | Valid ISO 10918-1 JPEG + 3-chunk split `APP2` ICC + `APP13` `8BIM` + `0xFF00` stuffing | `6c628563fbab5b27...67cf0eeb7b` | `valid_container=True`, `3` `APP2` chunks reassembled, `1` `8BIM` offset | `format='JPEG'`, `160 B` reassembled `acsp` ICC + `photoshop` dict | **PASS (`100%`)** |
| **`S2-V04`** | Corrupted PNG `iCCP` chunk (1-bit flip breaking IEEE 802.3 CRC-32) | `a835922c3c196b29...cf117f4b16` | `valid_container=False`, `crc_errors=1` (`CRC32 mismatch`) | `verify()` raised `SyntaxError` (CRC error rejected) | **PASS (`100%`)** |
| **`S2-V05`** | Truncated JPEG container missing terminal `0xFFD9` `EOI` marker | `b3124d533c638683...ecf6734dd0` | `valid_container=False`, missing `EOI` (`0xFFD9`) flagged | Structural `EOI` absence confirmed by reference scanner | **PASS (`100%`)** |
| **`S2-V06`** | Non-image JSON chat log containing `"Photoshop 3.0\x008BIM"` & `"Display P3 acsp"` | `b8bb2eb3ad6ca2f7...b70a148b` | `valid_container=False` (`UNSUPPORTED_OR_NOT_AN_IMAGE`, `0` false positives) | Raised `UnidentifiedImageError` (`0` false positives) | **PASS (`100%`)** |

---

### 3.3 Suite 3: Financial Indicator Mathematical Cross-Validation (`470` Vectors)

| Sub-Suite | Standard & Coverage Scope | Vectors Tested | Positive / Negative Split | Reference Comparator | Concordance |
| :--- | :--- | ---: | :--- | :--- | :---: |
| **`S3-V01`** | `ISO/IEC 7812` Payment Card Luhn (`13`–`19` digits, single-digit & transposition errors, `extract_validated_iocs` separation) | `12` | `5` valid / `7` invalid | Independent `GF(10)` table-lookup Luhn | **PASS (`12 / 12 = 100%`)** |
| **`S3-V02`** | `ISO 13616` / SWIFT IBAN Registry across **all `89` registered jurisdictions** (`15`-char `NO` to `33`-char `RU`) + `ISO/IEC 7064` Mod 97-10 | `184` | `89` valid / `95` invalid (`89` bad check digit + `6` unregistered/length) | Streaming Horner `Mod 97-10` evaluator | **PASS (`184 / 184 = 100%`)** |
| **`S3-V03`** | `ISO 9362` SWIFT/BIC across **all `250` `ISO 3166-1` alpha-2 (`+ XK`) codes** + `18` English 8-letter stopwords + banking-context gate | `274` | `251` valid / `23` invalid (`4` bad country + `18` stopwords + `1` no-context) | Exhaustive `ISO 3166-1` + context matrix | **PASS (`274 / 274 = 100%`)** |

---

## 4. Known Limitations, Error Boundaries & Operational Guardrails (`ISO/IEC 17025` Clause 7.2.2.3)

| Condition / Edge Case | Deterministic Tool Behavior | Recommended Laboratory Mitigation |
| :--- | :--- | :--- |
| **Chromium LevelDB compaction to `.ldb` SSTables** | `starshield precheck` reports `NO_GO_COMPACTED_OR_UNSUPPORTED` when only `.ldb` files exist without live `.log` WAL frames. | Acquire endpoint artifacts immediately before browser restart/compaction, or pair with Google `dfindexeddb` for Snappy/Zstandard `.ldb` table parsing. |
| **Non-JSON Blink/V8 serialized binary values** | Values lacking UTF-8 / UTF-16LE JSON objects are counted under `blink_v8_non_json_values_skipped` rather than guessed via heuristic regexes. | Inspect raw V8 StructuredClone / IndexedDB keys with `dfindexeddb` when non-JSON object stores are in scope. |
| **UK Sort Code + 8-Digit Account Number pairing** | Paired strictly within a `<= 120`-character single-message window; Pay.UK Vocalink modulus weight tables are not bundled (`validation_note` attached). | Verify candidate UK Faster Payments account pairs against bank statements or licensed Vocalink modulus tables. |
| **Cross-endpoint timestamp interval calculation** | Timezone-naive timestamps (`INVALID_OR_TIMEZONE_NAIVE_TIMESTAMP`) and negative intervals (`REJECTED_NEGATIVE_DELTA_CLOCK_SKEW_OR_BAD_INPUT`) are rejected rather than coerced. | Corroborate client cache timestamps against server-side logs or NTP synchronization records. |
| **Post-acquisition byte integrity** | `input_sha256` attests integrity from the moment bytes enter `starshield` onward (`provenance_caveat`). | Maintain an independent forensic acquisition log (`ewfacquire`, OS unified logs, or signed witness capture sheet) at collection time. |

---

## 5. One-Command Local Re-Verification Procedure for Accredited Laboratories

Any forensic laboratory, academic reviewer, or instructing legal team can reproduce both the zero-dependency specification check and the full dual-tool external cross-validation in under 15 seconds:

### A. Zero-Dependency Standard-Library Verification (Runs Automatically in CI)
```bash
python3 scripts/verify_cross_tool_forensics.py
```

### B. Full Dual-Tool External Cross-Validation (with Google `dfindexeddb` + `Pillow` in an Ephemeral Venv)
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

### C. Cryptographic Supply-Chain & Binary Reproducibility Verification
```bash
# 1. Verify bit-for-bit deterministic starshield.pyz build
python3 scripts/build_reproducible.py --verify

# 2. Verify GitHub OIDC Sigstore build provenance & SLSA Level 3 attestation
gh attestation verify commercial_kit/starshield.pyz --repo Ziqi/starshield-forensics
```
