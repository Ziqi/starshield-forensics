# `StarShield-Bench-24` (`v1.0.0` · Paired with `starshield-forensics v0.4.1`)

> **24-Case Deterministic Offline Endpoint Triage & Parser Resilience Suite**  
> **Author:** Ziqi Xiao (`@Ziqi`) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) *(currently resolves to archived `v0.3.7`)* · **License:** MIT · **Classification:** `TLP:CLEAR (100% Synthetic)`

---

## 1. Benchmark Scope & Target Audience

`StarShield-Bench-24` is a **machine-scored, seeded 24-case synthetic regression suite** built for **offline endpoint and digital forensics pre-screening**, evaluating parser framing, byte-offset fidelity, check-digit math, container error rejection, and default masked-mode canary non-leakage.

Every test vector is 100% synthetic (modeled on ISO-13616 example IBANs, ISO/IEC 7812 Luhn check-digit vectors, RFC 2083 / ISO 10918 container structures, and fictional 2025 transcripts).

### Five Machine-Scored Categories (`SSB24-01` – `SSB24-24`)

| Category | Case IDs | What Is Tested & Scored |
| :--- | :---: | :--- |
| **A. Chromium LevelDB `.log` Framing & Corruption** | `SSB24-01`..`06` | Single-block `FULL` recovery (`0x0`), cross-32KiB `FIRST/MIDDLE/LAST` (>66 KiB) reassembly, UTF-16LE Blink-prefixed JSON recovery, Castagnoli `CRC32C` (`polynomial 0x82F63B78`, `mask delta 0xA282EAD8`) bit-flip rejection, truncated `WriteBatch` rejection, and unclosed `FIRST` EOF detection. |
| **B. Exported JSON, Anti-Pairing & UTC Intervals** | `SSB24-07`..`11` | Soft-deleted (`deletetime`) vs `edittime` separation, cross-message UK Sort Code anti-pairing, >120-char intra-message exclusion, nested JSON child-dict non-duplication, and naive/negative UTC delta rejection. |
| **C. Identifier Check-Digit Syntax & Linguistics** | `SSB24-12`..`16` | ISO/IEC 7812 Luhn valid vs typo separation, 15/22/30-char ISO-13616 IBAN Mod-97 (`NO`, `GB`, `YE`), invalid `ZZ` country rejection, ISO-9362 BIC stopword filtering (`WORKSHOP`/`DOCUMENT`), and `N<30` descriptive linguistics guardrails. |
| **D. Structural PNG / JPEG Container Observation** | `SSB24-17`..`20` | RFC 2083 PNG `iCCP` (`acsp`) + `tEXt` with mandatory benign screenshot caveats, 3-chunk JPEG `APP2` ICC + `APP13/8BIM` reassembly, plain-text non-image rejection, and truncated/bad-CRC32 PNG rejection. |
| **E. Adversarial Chat Strings & Masked-Mode Canaries** | `SSB24-21`..`24` | Verifies that deterministic check-digit extraction ignores surrounding instruction-like text strings in English & Mandarin (`starshield` is NOT a natural-language prompt-injection filter), plus default masked-mode canary checks across `stdout` and failure-path `stderr` (`0.0000` leak rate). |

---

## 2. One-Command Local Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/benchmark_suite.py
```

To export a machine-readable scorecard JSON (`starshield_bench_24_scorecard.json`):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/benchmark_suite.py --output-dir ./artifacts
```

---

## 3. Zenodo Archival & Citation (`10.5281/zenodo.24145804`)

- **Concept DOI (Currently Resolves to Archived `v0.3.7`):** [`https://doi.org/10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804)
- **Historical Prior-Release DOIs:** `v0.3.7` [`10.5281/zenodo.24156262`](https://doi.org/10.5281/zenodo.24156262) · `v0.3.6` [`10.5281/zenodo.24151431`](https://doi.org/10.5281/zenodo.24151431)
- **Machine-Readable Citation:** [`../CITATION.cff`](../CITATION.cff)
