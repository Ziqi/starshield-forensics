# Security Assurance Case, Architecture & 12-Month Roadmap

> **Structured Software Assurance Case (aligned with NIST IR 7608)** for `starshield-forensics` (`v0.3.8`).

---

## 1. High-Level Architecture (`documentation_architecture`)

`starshield-forensics` is an **air-gapped, single-process, read-only command-line toolkit and library** written in pure Python >= 3.10 standard library with zero third-party runtime dependencies and zero network sockets:

```text
  Untrusted Local Artifact Copy (.log / .ldb / .json / .png / .jpg)
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Trust Boundary 1: Bounded File & Size Gate (`cli.py`)       │
  │  • Enforces `--max-mb` (default 64 MiB) prior to `.read()`  │
  │  • Opens inputs strictly read-only; suppresses OS paths     │
  └─────────────────────────────┬───────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  ┌───────────────┐     ┌───────────────┐     ┌─────────────────┐
  │ `leveldb_log` │     │ `image_cont.` │     │ `ioc_validator` │
  │ • 32KiB blocks│     │ • PNG CRC32   │     │ • ISO-7812 Luhn │
  │ • CRC32C mask │     │ • Bounded zlib│     │ • 89-ctry IBAN  │
  │ • SSTable mag.│     │ • JPEG APP2   │     │ • 250-code BIC  │
  └───────┬───────┘     └───────┬───────┘     └────────┬────────┘
          └─────────────────────┼──────────────────────┘
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │ Trust Boundary 2: Keyed Pseudonymization & Output Gate      │
  │  • Default masked mode (`HMAC-SHA256` / `SHA-384` / BLAKE2b)│
  │  • Suppresses raw SHA-256, byte counts, UTC dates & text    │
  │  • Tags every claim: OBSERVED | DERIVED | INFERRED | UNKNOWN│
  └─────────────────────────────┬───────────────────────────────┘
                                ▼
                   Deterministic JSON (`stdout`)
```

---

## 2. Security Expectations & Operational Boundaries (`documentation_security`)

### What Users CAN Expect
- **Zero Network Exfiltration:** No module imports `urllib`, `http`, `socket`, or `ssl` at runtime; execution succeeds inside network-disconnected forensic VMs.
- **Bounded Memory & Decompression Safety:** Input reads are capped by `--max-mb` (64 MiB default), and compressed PNG `iCCP` chunks use `zlib.decompressobj().decompress(data, MAX_ICCP_DECOMPRESSED_BYTES)` (`1 MiB` hard ceiling) to defeat zip/zlib decompression bombs.
- **Default Screen/Log Pseudonymization:** Without `--unredacted`, identifiers are keyed via CSPRNG `secrets.token_bytes(32)` HMAC (with configurable digest agility via `--hmac-digest` and external key separation via `--hmac-key-file`), and error paths scrub filenames and raw snippets from `stderr`.
- **Cryptographic Release Authenticity:** Official releases provide `SHA256SUMS` and detached OpenSSH `Ed25519` signatures (`SHA256SUMS.sig`) verifiable offline against `KEYS.pub`.

### What Users CANNOT Expect (Explicit Non-Guarantees)
- **Not Formal GDPR Anonymization:** Keyed HMAC pseudonymization prevents casual screen/log exposure; it is not formal legal anonymization against an adversary holding the original raw artifact.
- **Not Upstream Device Attestation:** File hashes verify post-acquisition byte integrity only; upstream device chain-of-custody requires independent acquisition logs.
- **Not an LLM Agent:** `starshield-forensics` performs deterministic binary/JSON parsing only; if downstream analysts pass `--unredacted` output into external LLMs, untrusted chat payloads could carry indirect prompt injections (evaluated by `StarShield-Bench-24`).

---

## 3. Threat Model & Trust Boundaries (`assurance_case`)

### Adversary Capabilities Assumed
Forensic inputs (Chromium caches, screenshots, exported chat JSONs) originate from **potentially adversarial or corrupted sources**. An attacker may craft inputs attempting to:
1. **T1 — Parser Resource Exhaustion / Decompression Bombs:** Oversized files, truncated LevelDB 32 KiB frames, malformed varints, PNG `iCCP` zlib bombs, or cyclic/truncated JPEG markers.
2. **T2 — Checksum Spoofing & False-Positive Injection:** Crafted account numbers, invalid country IBANs, or English words mimicking 8-letter SWIFT BICs to mislead investigators.
3. **T3 — Sensitive Data Leakage in Masked Mode:** Triggering parser exceptions (`UnicodeDecodeError`, `JSONDecodeError`, `OSError`) hoping raw filenames, paths, or plaintext chat snippets leak into `stderr`.
4. **T4 — Supply-Chain Tampering:** Modifying distributed `.pyz` or `.whl` artifacts or introducing vulnerable third-party transitive packages.

### Trust Boundaries
- **TB-1 (Disk $\rightarrow$ Parser):** Raw byte buffers read from untrusted files are treated as hostile until structurally validated (magic bytes, chunk bounds, CRC32 / CRC32C, UTF-8/UTF-16LE decoding bounds).
- **TB-2 (Internal Representation $\rightarrow$ CLI Output):** Unmasked fields exist only in transient process memory and are scrubbed prior to JSON serialization unless `--unredacted` is explicitly asserted by the operator.
- **TB-3 (Offline Maintainer Workstation $\rightarrow$ Public Distribution):** Release signing private keys reside exclusively in an encrypted local vault outside GitHub/Zenodo infrastructure.

---

## 4. Application of Saltzer & Schroeder Secure Design Principles (`implement_secure_design`)

1. **Economy of Mechanism:** Zero external runtime packages (`dependencies = []`), eliminating transitive PyPI supply-chain surface.
2. **Fail-Safe Defaults:** Masked HMAC pseudonymization is ON by default; `--max-mb=64` is enforced by default; malformed WAL frames increment `corrupted_frames_count` without crashing or executing dynamic code.
3. **Complete Mediation:** Every file read passes through `read_bounded_bytes()`; every PNG chunk and LevelDB physical record header checks remaining slice length before slicing or unpacking.
4. **Open Design:** Security relies on standard algorithms (`HMAC-SHA256/SHA384/BLAKE2b`, `Ed25519` release signatures) rather than obscurity; all source and test vectors are MIT-licensed.
5. **Separation of Privilege / Least Privilege:** Runs strictly as an unprivileged user process requiring read-only file access; release signing keys are air-gapped from CI runners.
6. **Least Common Mechanism:** Each CLI invocation is stateless with fresh CSPRNG keys (`secrets.token_bytes(32)`) and zero shared daemons or temp-file caches.

---

## 5. Countermeasures Against Common Implementation Weaknesses (CWE / OWASP)

| Weakness Class | CWE ID | Countermeasure & Verification Evidence |
| :--- | :--- | :--- |
| Arbitrary Code Execution / Deserialization | CWE-502 / CWE-94 | Never calls `eval`, `exec`, `pickle`, `marshal`, `yaml.load`, or `subprocess(..., shell=True)`. Verified via `Bandit` CI scan (`0` issues). |
| Uncontrolled Resource Consumption / Zip Bomb | CWE-400 / CWE-409 | `--max-mb` pre-read stat gate + `zlib.decompressobj().decompress(payload, 1_048_576)` + bounded varint loop (`shift <= 63`). Verified in `tests/test_adversarial.py`. |
| Out-of-Bounds Read / Truncated Frame Handling | CWE-125 | Explicit `offset + length > len(data)` allowlist checks across LevelDB 7-byte headers, PNG 12-byte chunk frames, and JPEG segment lengths. |
| Improper Input Validation | CWE-20 | Strict allowlists on `--schema` (`auto`, `chatsvc`, `generic-json`), `--hmac-digest` (`sha256`, `sha384`, `blake2b`), ISO-3166 alpha-2 (`250` codes), and ISO-13616 IBAN lengths (`89` countries). |
| Use of Broken Crypto / Hardcoded Keys | CWE-327 / CWE-798 | Uses CSPRNG `secrets.token_bytes(32)` + `HMAC-SHA256` (with `--hmac-digest` agility and `--hmac-key-file` external key storage); zero MD5/SHA-1. |
| Sensitive Information Exposure in Error Messages | CWE-209 | Exception handler in `cli.py` suppresses raw `UnicodeDecodeError`/`JSONDecodeError` context and scrubs input paths in masked mode (tested by canary unit tests). |

---

## 6. Verification Evidence Summary

1. **Automated Test Suite & Coverage (`>= 80%` Gate):** `tests/test_adversarial.py` + `benchmark/benchmark_suite.py` achieve **> 85% statement coverage** across `starshield/`, enforced on Python 3.10–3.13 in `.github/workflows/ci.yml`.
2. **Static Security & Style Analysis:** `GitHub CodeQL`, `PyCQA Bandit`, and `Astral Ruff` execute automatically on every push/PR in CI with zero findings permitted.
3. **Bit-for-Bit Reproducible Builds:** `scripts/build_reproducible.py --verify` builds `starshield.pyz` twice from source and asserts identical `SHA-256` digests in CI, paired with `scripts/generate_spdx_sbom.py --verify` for ISO/IEC 5962:2021 SPDX 2.3 SBOM verification.
4. **Continuous Coverage-Guided & Mutation Fuzzing (`Fuzzing: 10/10`):** `tests/fuzz_parsers.py` + `.clusterfuzzlite/` (`google/clusterfuzzlite` + `Atheris` libFuzzer in `.github/workflows/cflite.yml`) continuously fuzz LevelDB 32 KiB WAL block reassembly, PNG `iCCP` zlib streams, multi-segment JPEG `APP2`/`8BIM` containers, and ISO-7812/13616/9362 checksum validators, achieving `10/10` on the OpenSSF Scorecard `Fuzzing` check (`8.0/10` overall).
5. **Dual-Tool Forensic Method Validation (`482` Vectors):** `VALIDATION_REPORT_FSR_ISO17025.md` and `scripts/verify_cross_tool_forensics.py` cross-validate 482 deterministic test vectors against Google `dfindexeddb 20260210` and `Pillow 13.0.0` in alignment with the UK FSR Statutory Code of Practice (`FSA – DIG 100`, superseding `FSR-C-107`) and `ISO/IEC 17025` Clause 7.2.2.

---

## 7. 12-Month Technical Roadmap & Explicit Non-Goals (`documentation_roadmap`)

### Planned Milestones (2026 Q4 – 2027 Q4)
- **Q1 2027 (`v0.4.0`):** Pure-Python zero-dependency Snappy block decompressor for `.ldb` LevelDB SSTable read-only inspection and cross-generation sequence-number diffing (`precheck` $\rightarrow$ full `.ldb` carving).
- **Q2 2027 (`v0.4.5`):** Deterministic Blink V8 `StructuredClone` and IndexedDB binary key (`IDBKey`) wire-format decoder for non-JSON IndexedDB stores.
- **Q3 2027 (`v0.5.0`):** Expansion of `StarShield-Bench-24` to `StarShield-Bench-100` (100 seeded multi-client synthetic corruption & indirect prompt-injection test cases) plus dual-`SHA-256` zero-mutation audit receipts, RFC 3161 trusted-timestamp verification helpers, and `CASE/UCO` JSON-LD / `Timesketch JSONL` timeline interoperability.
- **Q4 2027 (`v1.0.0`):** Stable 1.0 schema specification, external third-party security review, and localized CLI summary templates for European university legal clinics.

### Explicit Non-Goals (What the Project Intends NOT to Do)
- **No Cloud SaaS or Telemetry:** Will never upload evidence artifacts to remote servers or embed analytics.
- **No Built-In LLM Inference:** Will never bundle generative AI summarizers inside the evidentiary parser, preserving 100% deterministic reproducibility.
- **No Offensive / Bypass Capabilities:** Does not decrypt OS keychain secrets, bypass device passcodes, or modify source storage directories.
