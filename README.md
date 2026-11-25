# `starshield-forensics` (`v0.4.0` — Offline LevelDB `.log`/`.ldb`/`MANIFEST` & Container Triage Toolkit)

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16602/badge)](https://www.bestpractices.dev/projects/16602)
[![OpenSSF Scorecard](https://img.shields.io/endpoint?url=https%3A%2F%2Fziqi.github.io%2Fstarshield%2Fscorecard.json)](https://github.com/Ziqi/starshield-forensics/actions/workflows/scorecard.yml)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/starshield-forensics/attestations)
[![PyPI](https://img.shields.io/pypi/v/starshield-forensics?label=PyPI%20%28PEP%20740%29&color=blue)](https://pypi.org/project/starshield-forensics/)

> **English** | **[简体中文 (`README.zh-CN.md`)](./README.zh-CN.md)**

> **Offline Read-Only Chromium & Electron LevelDB `.log` / Snappy `.ldb` SSTable / `MANIFEST` Carver, PNG/JPEG/PDF Container Structure Inspector, Mathematical Check-Digit Verifier & Structural `MCP` Server**
>
> **Author:** [Ziqi Xiao](https://ziqi.github.io/starshield/) (`@Ziqi`) · **PyPI:** [`starshield-forensics 0.4.0`](https://pypi.org/project/starshield-forensics/) · **Homebrew:** [`Ziqi/tap/starshield-forensics`](https://github.com/Ziqi/homebrew-tap) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) *(currently resolves to archived `v0.3.7`)* · **License:** MIT (`REUSE 3.3`) · **Runtime:** Python >= 3.10 (stdlib only, zero network calls, zero LLM dependencies)

---

## Focused Scope: Offline Endpoint & Evidentiary Pre-Screening

`starshield-forensics` is an **offline, read-only binary inspection and endpoint pre-screening toolkit** built with zero third-party runtime dependencies (`dependencies = []`) for digital forensics and incident response (DFIR) practitioners working on air-gapped jump hosts (all `<= v0.4.x` releases represent an independent, self-funded open-source engineering baseline):

1. **Corrupted or Compacted LevelDB `.log` + Snappy `.ldb` + `MANIFEST` Triage (`precheck`, `parse-leveldb-log` & `parse-leveldb-store`)**: Read-only compaction diagnostics, uncompacted write-ahead log (`.log`) carving, pure-stdlib Snappy (`.ldb`/`.sst`) SSTable block decompression, and multi-record `MANIFEST-*` `VersionEdit` state-machine replay for Chromium browsers (`Chrome`, `Edge`, `Brave` Local Storage & existing LevelDB-backed IndexedDB, WhatsApp Web, browser extensions) and **Electron desktop apps (`Microsoft Teams`, `Slack` Local Storage)**—enforcing Castagnoli CRC32C (`polynomial 0x82F63B78`, LevelDB `mask delta 0xA282EAD8`) block/frame quarantine and reconciling `LIVE_ACTIVE`, `UI_SOFT_DELETED`, and `TOMBSTONED_HISTORICAL_RECOVERED` records across compaction levels.
2. **PNG, JPEG & PDF Container Structure Inspection (`inspect-image` & `inspect-pdf`)**: Pure-stdlib structural parsing of RFC 2083 PNG chunk CRC32s (`IHDR`/`IDAT`/`IEND`/`iCCP`), ISO 10918 JPEG `APP2 ICC_PROFILE` / `APP13 (8BIM)`, and ISO 32000 PDF incremental save revisions (`%%EOF`/`xref`/`startxref`, bounded `<= 16 MiB` `zlib` `/FlateDecode` `/Type /ObjStm` Info/XMP metadata, and `/JavaScript` `/Launch` `/EmbeddedFiles` cues). Reports **container structure observations only** alongside mandatory benign OS-save, e-signature, and form-fill caveats—never pixel forgery or tamper authentication.
3. **Offline Identifier Check-Digit Syntax & Structural `MCP` Airlock (`starshield mcp` + `detokenize` + `shred-vault`)**: Mathematical check-digit and registry syntax verification (`ISO/IEC 7812` Luhn, 89-country `ISO 13616` IBAN Mod-97, 250-territory `ISO 9362` SWIFT/BIC, US ABA, `ISO 11649` RF, `ISO 17442` LEI, TRON TRC-20 Base58Check, and Ethereum EIP-55) to filter OCR or transcription typos. **Check-digit validation confirms mathematical syntax only; it does NOT indicate fraud or prove that a payment occurred.** `starshield mcp` is **not** a natural-language prompt-injection filter—instead, its parse/triage tools withhold free-form prose by default and emit structural skeletons, paired with local CLI `starshield detokenize` and `starshield shred-vault`.

All bundled fixtures in `samples/` and `starshield/data/`—plus the seeded 24-case evaluation suite in `benchmark/benchmark_suite.py` (`StarShield-Bench-24`)—are **100% clean-room specification test vectors** (`GBP 18,400.00`, ISO-13616 example IBANs `GB82WEST12345698765432` and `NO9386011117947`, Luhn test string `6200000000000005`). Zero real incident data or PII is included.

---

## Epistemic Tiers & Capability Boundary Matrix (`v0.4.0`)

Every output carries an explicit machine-readable epistemic tier:

- **`OBSERVED`**: Directly present in raw input bytes, chunk headers, or JSON fields (bound to physical WAL frame, SSTable block, or container offsets).
- **`DERIVED`**: Deterministically computed from raw input via standardized algorithms (Castagnoli CRC32C, ISO/IEC 7812 Luhn, ISO-13616 Mod-97, UTC delta arithmetic).
- **`INFERRED`**: Contextual triage lead requiring external corroboration; never asserted as standalone proof.
- **`UNKNOWN`**: Explicitly outside the evidentiary boundary of local client artifacts (e.g., records compacted and physically overwritten prior to acquisition).

| Module | Capability in `v0.4.0` | Epistemic Boundary & Current Limitations |
| :--- | :--- | :--- |
| **Zero-PII Storage Feasibility Gate** (`precheck`) | Scans Chromium & Electron LevelDB folders or `.log`/`.ldb` files offline (capped at `4,096` files), verifies `.log` WAL frames and Snappy/raw `.ldb` SSTables (`0xdb4775248b80fb57`), and flags `.blob` directories, `0x02` Zstandard blocks, Blink `0xFF` headers, or 16-byte SQLite3 headers, emitting a deterministic `GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED` manifest with zero plaintext leakage. | *Emits `GO` on healthy `.log` and/or Snappy `.ldb` stores; downgrades to `PARTIAL` or `NO_GO_COMPACTED_OR_UNSUPPORTED` when Zstd (`0x02`) blocks, external `.blob` files, binary-only V8 payloads, or SQLite stores are present.* |
| **LevelDB `.log` WAL + Snappy `.ldb` SSTable + `MANIFEST` Reconciler** (`leveldb_log.py` & `leveldb_sstable.py`) | Parses 32 KiB `.log` frames (`FULL`/`FIRST`/`MIDDLE`/`LAST`), pure-stdlib Snappy (`0x01`) & raw (`0x00`) `.ldb` SSTable blocks (5-byte Castagnoli CRC32C trailers, Restart-Point prefix keys, 8-byte `InternalKey` tombstones), and multi-record `MANIFEST-*` `VersionEdit` logs, reconciling `LIVE_ACTIVE`, `UI_SOFT_DELETED`, and `TOMBSTONED_HISTORICAL_RECOVERED` JSON & LocalStorage KV text slices. | *Does not decompress Zstandard (`0x02`) SSTable blocks (`zstd_unsupported_blocks_count`), follow external `.blob` directories, deserialize binary-only Blink V8 `StructuredClone` AST primitives, or parse newly created Chrome 156+ SQLite-backed IndexedDB stores.* |
| **Exported Message JSON Triage** (`triage-json`) | Enumerates soft-deleted (`deletetime` / `deleted_ts` / `is_deleted`) and edited (`edittime` / `edited.ts`) JSON records across messaging exports, extracting syntax-checked identifiers strictly per record. | *Cannot quantify records already compacted and physically evicted prior to acquisition.* |
| **Identifier Check-Digit Syntax** (`ioc_validators.py`) | Verifies ISO/IEC 7812 **Luhn**, all 89 SWIFT IBAN Registry country lengths (15–33 chars) + **Mod-97**, **250** ISO 3166-1 / `XK` SWIFT/BIC territory codes, UK Sort Code + Account pairs, **US ABA 3-7-1**, **ISO 11649 `RF`**, **ISO 17442 LEIs**, **TRON TRC-20** Base58Check, and **Ethereum EIP-55**. | *Confirms mathematical syntax only—never fraud or payment execution. Does not bundle proprietary Pay.UK Vocalink sort-code modulus weight tables.* |
| **PNG, JPEG & PDF Container Structure** (`image_containers.py` & `pdf_containers.py`) | Verifies PNG `IHDR`/`IDAT`/`IEND` CRC32 + `iCCP` (`16 MiB` single-chunk / `32 MiB` cumulative cap), multi-chunk JPEG `APP2` `ICC_PROFILE` + `APP13` (`8BIM`), and ISO 32000 PDF structural `%%EOF`/`xref`/`startxref` revisions (skipping stream spans, string literals, and `obj..endobj`/`<<..>>`/`[..]` nesting) + `/FlateDecode` `/Type /ObjStm` Info/XMP metadata. | *Container structure observation only + `undecoded_filter_streams` counts + benign caveats (OS resaves, e-signatures, AcroForm fills, linearization); never detects pixel forgery or tamper.* |
| **Zero-Dependency Structural `MCP` Server** (`mcp_server.py` / `starshield mcp`) | Exposes 8 read-only deterministic tools (`starshield_demo`, `starshield_precheck_leveldb`, `starshield_parse_leveldb_log`, `starshield_parse_leveldb_store`, `starshield_triage_json`, `starshield_inspect_image_tamper`, `starshield_validate_financial_iocs`, `starshield_inspect_pdf_tamper`) over JSON-RPC 2.0 `stdio`. | *Not a prompt-injection filter: withholds raw prose in parse/triage tools; currency amounts and 2-letter IBAN/BIC country codes remain visible in structural tokens. `detokenize` is never registered as an MCP tool.* |
| **Local Session Token Vault & Shredder** (`pseudonymizer.py` & `cli.py`) | In-RAM by default; optional `--vault-file PATH` (`0600` `O_NOFOLLOW` atomic local JSON, e.g. Linux `/dev/shm` `tmpfs` or macOS `~/.starshield/vault.json`) + local CLI `starshield detokenize` (4-hex `session_tag` anti-collision check) + `starshield shred-vault` (verifies `starshield-token-vault/v1` header before `best-effort overwrite + unlink`). | *Same-host OS-permission-protected plaintext JSON lookup table (not hardware-separated isolation; Python stdlib has no native AEAD). `shred-vault` does NOT guarantee physical block erasure on SSD/NVMe or APFS/Btrfs/ZFS CoW volumes—prefer RAM-backed `tmpfs` where available.* |

### Browser & Desktop Storage Target Matrix

| Target Artifact / Application | Underlying Storage Format | `starshield-forensics v0.4.0` Support |
| :--- | :--- | :--- |
| **Chrome / Edge / Brave Local Storage & existing LevelDB IndexedDB** | LevelDB `.log` WAL + Snappy `.ldb` SSTables + `MANIFEST-*` | **Supported (`.log` + Snappy `.ldb` + `MANIFEST`)** via `precheck`, `parse-leveldb-log` & `parse-leveldb-store` |
| **WhatsApp Web, Microsoft Teams (Web/Electron Local Storage), Slack Local Storage, Browser Extensions (`Local Extension Settings`)** | LevelDB `.log` WAL & `.ldb` SSTables (`chatsvc` / `generic-json`) | **Supported (`.log` + Snappy `.ldb`)** with UTF-8, Blink UTF-16LE JSON & LocalStorage KV text carving plus `0x00` tombstone reconciliation |
| **Zstandard (`0x02`) SSTable Blocks, Binary-Only Blink V8 `StructuredClone` & External `.blob` Directories** | Zstd-compressed blocks / V8 binary AST (`0xFF`) / IndexedDB `.blob` | `precheck` & `parse-leveldb-store` report `zstd_unsupported_blocks_count`, `blink_v8_non_json_values_skipped`, and `external_blob_warning`; `v0.4.0` does **not** decompress Zstd (`0x02`), reconstruct `.blob` files, or deserialize binary-only V8 ASTs |
| **Chrome 156+ Newly Created IndexedDB Stores, VS Code / Cursor `state.vscdb`, Native Encrypted WhatsApp Desktop `messages.db`, Discord `SimpleCache`** | SQLite B-Tree / SQLCipher / Chromium `SimpleCache` | **Out of LevelDB scope** (`precheck` detects 16-byte `SQLite format 3\x00` headers for accurate routing; existing LevelDB stores remain in LevelDB, whereas newly created Chrome 156+ stores use SQLite — inspect SQLite stores with `sqlite3`) |

---

## Quick Tryout (`uvx`) & Installation (`pip` PEP 740 / `.pyz`)

```bash
# Instant zero-install clean-room showcase (fetches PyPI wheel directly, zero repo clone needed):
uvx --from starshield-forensics starshield demo

# Option A — Official PyPI package (with PEP 740 Sigstore digital attestations, zero dependencies):
pip install starshield-forensics
starshield demo

# Option A2 — macOS / Linux Homebrew Tap (isolated libexec formula, zero dependencies):
brew install Ziqi/tap/starshield-forensics && starshield demo

# Option B — Zero-install single-file zipapp (for air-gapped forensic VMs):
python3 starshield.pyz demo
python3 starshield.pyz precheck /path/to/readonly_chromium_idb_copy

# Option C — Clone & run the bundled <= 500 KB corrupted LevelDB challenge + test & benchmark suites:
git clone https://github.com/Ziqi/starshield-forensics.git
cd starshield-forensics
python3 -m starshield precheck examples/corrupted_leveldb_challenge
python3 -m starshield parse-leveldb-store examples/corrupted_leveldb_challenge
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -W error tests/fuzz_parsers.py --stdlib --iterations 3000
PYTHONDONTWRITEBYTECODE=1 python3 benchmark/benchmark_suite.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify_cross_tool_forensics.py
```

See [`examples/README.md`](./examples/README.md) for a walkthrough of the deterministic `1,996`-byte corrupted `.log + .ldb + MANIFEST` challenge bundle (`examples/corrupted_leveldb_challenge`).

### AI Agent Integration (`starshield mcp`) & Two Output Masking Modes

Mount the 8 read-only inspection tools over JSON-RPC 2.0 `stdio` (omit `--vault-file` for purely in-RAM sessions, or choose a platform-appropriate `0600` local vault path):

- **Linux (`tmpfs` RAM disk):**
```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics", "starshield", "--vault-file", "/dev/shm/starshield_vault.json", "mcp"]
    }
  }
}
```

- **macOS (private `0700` user directory — macOS has no `/dev/shm`):**
```json
{
  "mcpServers": {
    "starshield-forensics": {
      "command": "uvx",
      "args": ["--from", "starshield-forensics", "starshield", "--vault-file", "/Users/<you>/.starshield/vault.json", "mcp"]
    }
  }
}
```

`starshield-forensics` implements **two distinct masking modes**—do not conflate them:

1. **Mode A — Keyed Ephemeral HMAC Mode (Default CLI commands & `starshield_demo`)**: Replaces identifiers with per-run `[REDACTED_HMAC:<12-hex>]` digests; CLI replaces prose with `[REDACTED_CONTENT]` (and MCP `starshield_demo` replaces prose with `[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]`).
   ```json
   {
     "epistemic_tier": "OBSERVED",
     "schema_detected": "chatsvc",
     "leveldb_batch_byte_offset": 397,
     "leveldb_batch_sequence_number": 1002,
     "leveldb_sequence_number": 1002,
     "is_soft_deleted_in_ui": true,
     "sender_mri": "[REDACTED_HMAC:1b71a34908e1]",
     "cached_content": "[REDACTED_CONTENT]",
     "extracted_iocs": {
       "luhn_validated_cards": ["[REDACTED_HMAC:3ec5f5677098]"],
       "mod97_validated_ibans": ["[REDACTED_HMAC:4dad6b1cc0be]", "[REDACTED_HMAC:f21864d3e75c]"]
     }
   }
   ```
2. **Mode B — Session-Tagged Structural Skeleton Mode (`starshield mcp` `parse_leveldb_log` / `parse_leveldb_store` / `triage_json`, and CLI `--pseudonymize` / `--vault-file`)**: Withholds free-form prose (`[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]`) and assigns order-preserving session tokens. **Explicit visibility boundary:** `extracted_currency_amounts` (e.g. `USD 9,500.00`) and 2-letter ISO country codes inside `<IBAN_GB_9F3A_01>` / `<BIC_GB_9F3A_01>` are **not** hidden by this airlock (`starshield_validate_financial_iocs` returns both `validated_iocs` HMAC digests and `order_preserving_iocs` tokens alongside `validation_scope_note`).
   ```json
   {
     "epistemic_tier": "OBSERVED",
     "schema_detected": "chatsvc",
     "sender_mri": "<ENTITY_9F3A_01>",
     "cached_plaintext": "[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]",
     "extracted_currency_amounts": ["USD 9,500.00"],
     "extracted_iocs": {
       "mod97_validated_ibans": ["<IBAN_GB_9F3A_01>"]
     }
   }
   ```

### CLI Subcommands (`starshield [--version] [--unredacted] [--pseudonymize] [--vault-file PATH] [--max-mb 64] [--hmac-digest {sha256,sha384,blake2b}] [--hmac-key-file PATH] <subcommand>`)

| Subcommand | Input Artifact | Output JSON Summary |
| :--- | :--- | :--- |
| `demo` | Built-in synthetic fixtures | Runs clean-room WAL, Snappy `.ldb` SSTable, JSON, container, and check-digit showcase (Mode A HMAC) |
| `precheck <path> [--schema ...]` | Chromium folder or `.log`/`.ldb` | Zero-PII `GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED` feasibility check |
| `parse-leveldb-log <file.log> [--schema ...]` | Chromium LevelDB `.log` WAL | Physical block CRC32C status, byte-offset-bound carved records, and syntax-checked IOCs |
| `parse-leveldb-store <dir_or_file> [--schema ...]` | LevelDB folder (`MANIFEST`+`.ldb`+`.log`) or `.ldb` | Reconciles `LIVE_ACTIVE`, `UI_SOFT_DELETED`, and `TOMBSTONED_HISTORICAL_RECOVERED` records across Snappy SSTables & WAL |
| `triage-json <export.json> [--schema ...]` | Exported messaging JSON | Soft-deleted & edited records + per-record syntax-checked IOCs |
| `inspect-image <image.png\|jpg>` | PNG or JPEG file | Chunk/marker integrity, ICC (`acsp`) header fields, `8BIM`, and benign caveats |
| `inspect-pdf <document.pdf>` | Local PDF file | Incremental save revisions (`%%EOF`/`xref`/`startxref`), `/ObjStm` Info/XMP cues, and benign caveats |
| `corroborate-timestamps <events.json>` | Timezone-aware UTC pairs | Monotonicity verification, clock-skew bounds, and edge-node frequency summary |
| `summarize-linguistics <chat.json>` | Chat transcript JSON | Descriptive utterance-length & punctuation distribution (`N >= 30` guardrailed) |
| `detokenize --vault <vault.json> [--input ...]` | Draft with `<IBAN_GB_9F3A_01>` tokens | Local CLI restoration enforcing 4-hex `session_tag` anti-collision check |
| `shred-vault --vault <vault.json>` | Local `0600` token vault JSON | Best-effort 2-pass (`urandom` + `0x00` + `fsync`) logical overwrite + unlink (prefer `/dev/shm`) |
| `mcp` | JSON-RPC 2.0 `stdio` stream | Read-only MCP server exposing 8 deterministic tools |

---

## Cryptographic Release Verification & Bit-for-Bit Reproducibility (`v0.4.0`)

Each official release separates CI-rebuilt provenance from maintainer-signed PyPI distributions (`starshield-forensics-0.4.0.spdx.json`):
1. **`starshield.pyz` (Bit-for-Bit Reproducible Zipapp):** Rebuilt directly from source in GitHub Actions with isolated **SLSA Build Level 3** provenance (`multiple.intoto.jsonl` via `slsa-framework/slsa-github-generator`) and GitHub OIDC + Sigstore (`Fulcio` X.509 + `Rekor`) attestations at [`/attestations`](https://github.com/Ziqi/starshield-forensics/attestations);
2. **`.whl` & `.tar.gz` (`sdist` Distributions):** Signed offline by the maintainer with OpenSSH `Ed25519` (`SHA256SUMS.sig` verified against [`KEYS.pub`](./KEYS.pub) prior to CI publication) and published via **PyPI Trusted Publisher PEP 740** digital attestations;
3. **SPDX 2.3 SBOM (`starshield-forensics-0.4.0.spdx.json`):** Records SHA-256 digests across `starshield.pyz`, `.whl`, and `.tar.gz` and is Sigstore-attested in CI.

```bash
# 1. Verify Sigstore X.509 + Rekor build & SBOM attestations via GitHub CLI:
gh attestation verify starshield.pyz -R Ziqi/starshield-forensics

# 2. Verify isolated SLSA Build Level 3 provenance (.intoto.jsonl):
slsa-verifier verify-artifact starshield.pyz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/Ziqi/starshield-forensics

# 3. Offline verification using standard OpenSSH (>=8.2p1) & SHA256SUMS:
ssh-keygen -Y verify -f KEYS.pub -I "2196305+Ziqi@users.noreply.github.com" -n file -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS

# 4. Rebuild starshield.pyz & SPDX 2.3 SBOM from source and verify version & digest parity:
python3 scripts/build_reproducible.py --verify
python3 scripts/generate_spdx_sbom.py --verify
```

---

## Governance, Cross-Tool Verification & Security Reporting

- **Cross-Tool & Specification Test Harness (`542` Vectors):** [`scripts/verify_cross_tool_forensics.py`](./scripts/verify_cross_tool_forensics.py) (`6` LevelDB WAL vectors, `4` LevelDB SSTable/MANIFEST vectors, `6` PNG/JPEG container vectors, and `526` check-digit/registry vectors; compares against Google `dfindexeddb` and `Pillow` when installed via `--require-external`, or runs standalone self-checks without claiming external concordance)
- **Security Insights & Licensing:** [`SECURITY-INSIGHTS.yml`](./SECURITY-INSIGHTS.yml) · [`SECURITY.md`](./SECURITY.md) · [`REUSE.toml`](./REUSE.toml) · **Concept DOI:** [`10.5281/zenodo.24145804`](https://doi.org/10.5281/zenodo.24145804) *(currently resolves to archived `v0.3.7`: `10.5281/zenodo.24156262`)*
- **Security Assurance Case & Scope Boundaries:** [`SECURITY_ASSURANCE_CASE.md`](./SECURITY_ASSURANCE_CASE.md)
- **Private Vulnerability Reporting (48h Ack SLA):** [`SECURITY.md`](./SECURITY.md) · [GitHub Private Vulnerability Reporting](https://github.com/Ziqi/starshield-forensics/security/advisories/new)
- **Governance & Contribution Standards:** [`GOVERNANCE.md`](./GOVERNANCE.md) · [`CONTRIBUTING.md`](./CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md)
- **Author:** **Ziqi Xiao** (`@Ziqi`) — [Documentation Portal](https://ziqi.github.io/starshield/) · [GitHub Issues](https://github.com/Ziqi/starshield-forensics/issues)
