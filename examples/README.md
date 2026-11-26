# Clean-Room Corrupted LevelDB Store Challenge (`v0.4.1`)

This directory contains a deterministic, **100% synthetic** Chromium/Electron LevelDB store (`< 16 KB` total, zero real incident data) designed for reproducible 10-second verification of `starshield-forensics v0.4.1`:

## Artifact Layout (`examples/corrupted_leveldb_challenge/`)

- `CURRENT` & `MANIFEST-000002`: Two sequential `VersionEdit` records (`comparator="idb_cmp1"`) that register `000001.ldb`, then evict `000001.ldb` (`kDeletedFile`) while promoting `000003.ldb` (Level 1) and `000005.ldb` (Level 0).
- `000001.ldb`: Uncollected **orphan** Snappy-compressed SSTable evicted by `MANIFEST-000002` (`chal_msg_orphan_8900`, classified as `TOMBSTONED_HISTORICAL_RECOVERED` with `evicted_from_manifest: true` rather than live).
- `000003.ldb`: Active Level-1 Snappy-compressed SSTable containing three Data Blocks — Blocks 0 and 1 are intact (`chal_msg_tombstoned_9001` & `chal_msg_live_9002`), while Block 2 has a **1-bit storage flip** quarantined by 5-byte Castagnoli `CRC32C` verification without aborting recovery of healthy blocks.
- `000005.ldb`: Active Level-0 Snappy-compressed SSTable carrying a `kTypeDeletion (0x00)` tombstone (`seq=9020`) for `idb:conv:thread_01:msg_01`, demonstrating recovery of the pre-tombstone Level-1 payload (`TOMBSTONED_HISTORICAL_RECOVERED`).
- `000006.log`: Uncompacted 291-byte LevelDB Write-Ahead Log frame carrying an application-layer `UI_SOFT_DELETED` message (`chal_msg_wal_softdel_9045`).

## 10-Second Tryout

```bash
# 1. Zero-PII feasibility precheck (reports PARTIAL due to the 1 bit-flipped SSTable block)
starshield precheck examples/corrupted_leveldb_challenge

# 2. Default HMAC-masked store reconciliation (zero plaintext prose or file paths leaked)
starshield parse-leveldb-store examples/corrupted_leveldb_challenge

# 3. Lab-mode inspection (synthetic benchmark vectors only)
starshield --unredacted parse-leveldb-store examples/corrupted_leveldb_challenge
```
