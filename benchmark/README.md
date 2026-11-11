# `StarShield-Bench-24` (`v1.0.0` · Paired with `starshield-forensics v0.3.5`)

> **24-Case Deterministic Evidentiary Triage & Adversarial Prompt-Injection Benchmark**  
> **Author:** Ziqi Xiao (`@Ziqi`) · **License:** MIT · **Classification:** `TLP:CLEAR (100% Synthetic)`

---

## 1. Why `StarShield-Bench-24` Establishes an Industry Standard

A single synthetic sample report demonstrates consulting formatting, whereas a **machine-scored, seeded 24-case synthetic benchmark (`StarShield-Bench-24`)** gives DFIR laboratories, payment-dispute compliance teams, and AI safety researchers an objective baseline they can **re-run in under 1 second** and **cite via academic DOI (`CITATION.cff` / Zenodo)**.

Every test vector is 100% synthetic (modeled on ISO-13616 example IBANs, ISO/IEC 7812 Luhn check-digit vectors, RFC 2083 / ISO 10918 container structures, and fictional 2025 supplier-invoice transcripts).

### Five Machine-Scored Benchmark Categories (`SSB24-01` – `SSB24-24`)

| Category | Case IDs | What Is Tested & Scored |
| :--- | :---: | :--- |
| **A. Chromium LevelDB `.log` Framing & Corruption** | `SSB24-01`..`06` | Single-block `FULL` recovery (`0x0`), cross-32KiB `FIRST/MIDDLE/LAST` (>66 KiB) reassembly, UTF-16LE Blink-prefixed JSON recovery, Castagnoli `CRC32C` bit-flip rejection, truncated `WriteBatch` rejection, and unclosed `FIRST` EOF detection. |
| **B. Exported JSON, Anti-Pairing & UTC Intervals** | `SSB24-07`..`11` | Soft-deleted (`deletetime`) vs `edittime` separation, cross-message UK Sort Code anti-pairing, >120-char intra-message exclusion, nested JSON child-dict non-duplication, and naive/negative UTC delta rejection. |
| **C. Multi-Jurisdiction Financial Checksums** | `SSB24-12`..`16` | ISO/IEC 7812 Luhn valid vs typo separation, 15/22/30-char ISO-13616 IBAN Mod-97 (`NO`, `GB`, `YE`), invalid `ZZ` country rejection, ISO-9362 BIC stopword filtering (`WORKSHOP`/`DOCUMENT`), and `N<30` descriptive linguistics guardrails. |
| **D. Structural PNG / JPEG Container Provenance** | `SSB24-17`..`20` | RFC 2083 PNG `iCCP` (`acsp`) + `tEXt` with mandatory benign screenshot caveats, 3-chunk JPEG `APP2` ICC + `APP13/8BIM` reassembly, plain-text non-image rejection, and truncated/bad-CRC32 PNG rejection. |
| **E. Indirect Prompt Injection & Zero-Leak Privacy** | `SSB24-21`..`24` | English & Mandarin/English instruction-override payloads embedded inside adversary chat messages (100% deterministic IOC survival), plus default masked-mode canary tests across `stdout` and failure-path `stderr` (`0.0000` leak rate). |

---

## 2. One-Command Local Reproduction

```bash
PYTHONDONTWRITEBYTECODE=1 python3 benchmark_suite.py
```

To export a machine-readable scorecard JSON (`starshield_bench_24_scorecard.json`):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 benchmark_suite.py --output-dir ./artifacts
```

---

## 3. Minting Your Official Academic DOI via Zenodo (3-Minute Setup After GitHub Push)

1. Copy `CITATION.cff` and `benchmark_suite.py` into your public `starshield-forensics` repository root (or `benchmark/` subfolder) when publishing `v0.3.5`.
2. Sign in to **[https://zenodo.org](https://zenodo.org)** using your GitHub account (`@Ziqi`).
3. Toggle **ON** the switch next to `Ziqi/starshield-forensics` under *GitHub -> Repositories*.
4. Create GitHub Release tag `v0.3.5` — Zenodo automatically archives the release and issues a permanent **`10.5281/zenodo.XXXXXXX` DOI badge** for academic papers, NLnet grant reviews, and law-firm technical due diligence.
