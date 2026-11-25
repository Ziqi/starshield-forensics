#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Deterministic Clean-Room Corrupted `.log + .ldb + MANIFEST` Challenge Builder.

Generates `examples/corrupted_leveldb_challenge/` (< 64 KB total, 100% synthetic specification
vectors) exercising every v0.4.0 capability:
  1. Multi-record `MANIFEST-000002` replay (`NewFile` + `DeletedFile`) distinguishing active L0/L1
     `.ldb` SSTables (`000003.ldb`, `000005.ldb`) from an uncollected disk orphan (`000001.ldb`).
  2. Snappy-compressed multi-block `.ldb` (`000003.ldb`) where Data Block 0 is intact and Data
     Block 1 has a 1-bit payload flip quarantined by 5-byte Castagnoli CRC32C verification.
  3. Cross-level `kTypeDeletion (0x00)` tombstone in L0 (`000005.ldb`, seq=9020) masking an older
     L1 value (`000003.ldb`, seq=9001) — recovered as `TOMBSTONED_HISTORICAL_RECOVERED`.
  4. Uncompacted `.log` WAL (`000006.log`, seq=9045) carrying an application-layer `UI_SOFT_DELETED`
     record (`deletetime` populated).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield.leveldb_log import (  # noqa: E402
    REC_FULL,
    build_writebatch,
    encode_leveldb_log_record,
    encode_logical_record_across_blocks,
)
from starshield.leveldb_sstable import (  # noqa: E402
    build_leveldb_sstable,
    build_version_edit,
    pack_internal_key,
)


def build_challenge_files(out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Orphan L1 SSTable (000001.ldb) — evicted by MANIFEST VersionEdit #2 but still on disk
    orphan_msg = json.dumps(
        {
            "id": "chal_msg_orphan_8900",
            "from": "8:live:meridian_ops_bot",
            "composetime": "2025-03-18T08:00:00Z",
            "content": "Legacy settlement baseline IBAN NL91ABNA0417164300 before compaction.",
        }
    ).encode("utf-8")
    ldb_000001 = build_leveldb_sstable(
        [(b"idb:conv:thread_01:msg_00", 8900, 1, orphan_msg)],
        compress=True,
    )

    # 2. Active L1 SSTable (000003.ldb) — 2 Snappy Data Blocks; Block 1 receives a 1-bit flip
    l1_tombstoned_target = json.dumps(
        {
            "id": "chal_msg_tombstoned_9001",
            "from": "8:live:impersonated_vendor_desk",
            "composetime": "2025-03-18T09:12:00Z",
            "content": (
                "Draft remittance instruction (GBP 18,400.00) to IBAN GB82WEST12345698765432 "
                "(SWIFT NWBKGB2LXXX) prior to key deletion."
            ),
        }
    ).encode("utf-8")
    l1_live_record = json.dumps(
        {
            "id": "chal_msg_live_9002",
            "from": "8:live:meridian_ap_clerk",
            "composetime": "2025-03-18T09:20:00Z",
            "content": " Creditor reference RF18539007547034 logged for supplier verification.",
        }
    ).encode("utf-8")
    l1_block2_victim = json.dumps(
        {
            "id": "chal_msg_corrupt_blk1_9003",
            "from": "8:live:meridian_ap_clerk",
            "composetime": "2025-03-18T09:25:00Z",
            "content": "Padding block payload to force a second SSTable data block: " + ("P" * 600),
        }
    ).encode("utf-8")

    clean_000003 = bytearray(
        build_leveldb_sstable(
            [
                (b"idb:conv:thread_01:msg_01", 9001, 1, l1_tombstoned_target),
                (b"idb:conv:thread_01:msg_02", 9002, 1, l1_live_record),
                (b"idb:conv:thread_01:msg_99", 9003, 1, l1_block2_victim),
            ],
            compress=True,
            block_target_bytes=220,
        )
    )
    # Inject a deterministic 1-bit storage fault inside the third data block (leaving Block 0/1 & Index intact)
    # Find offset of `"P" * 20` or flip a byte right after Block 0+1 before MetaIndex/Index
    # Specifically, parse index handles first to locate the last data block cleanly:
    from starshield.leveldb_sstable import _decode_varint64_bounded, _iter_sstable_block_entries, decompress_snappy

    footer = bytes(clean_000003[-48:])
    p = 0
    _mo, p = _decode_varint64_bounded(footer, p, 40)
    _ms, p = _decode_varint64_bounded(footer, p, 40)
    idx_off, p = _decode_varint64_bounded(footer, p, 40)
    idx_size, p = _decode_varint64_bounded(footer, p, 40)
    idx_raw = decompress_snappy(bytes(clean_000003[idx_off : idx_off + idx_size]))
    idx_items = _iter_sstable_block_entries(idx_raw)
    last_handle = idx_items[-1][2]
    hp = 0
    last_blk_off, hp = _decode_varint64_bounded(last_handle, hp, len(last_handle))
    clean_000003[last_blk_off + 2] ^= 0x01
    ldb_000003 = bytes(clean_000003)

    # 3. Active L0 SSTable (000005.ldb) — carries kTypeDeletion (0x00) tombstone at seq=9020 for msg_01
    ldb_000005 = build_leveldb_sstable(
        [(b"idb:conv:thread_01:msg_01", 9020, 0, b"")],
        compress=True,
    )

    # 4. Uncompacted WAL (000006.log) — carries UI soft-deleted message at seq=9045
    wal_soft_del = json.dumps(
        {
            "id": "chal_msg_wal_softdel_9045",
            "from": "8:live:impersonated_vendor_desk",
            "composetime": "2025-03-18T10:05:00Z",
            "properties": {"deletetime": "1742292400000"},
            "content": "Retracted chat reminder citing Norway test IBAN NO9386011117947.",
        }
    ).encode("utf-8")
    wb_000006 = build_writebatch(9045, [(1, b"idb:conv:thread_01:msg_04", wal_soft_del)])
    log_000006 = encode_logical_record_across_blocks(wb_000006)

    # 5. MANIFEST-000002 (2 sequential VersionEdits: add 1, then delete 1 + add 3 & 5)
    ve1 = build_version_edit(
        comparator="idb_cmp1",
        log_number=4,
        next_file_number=3,
        last_sequence=8950,
        new_files=[
            (
                1,
                1,
                len(ldb_000001),
                pack_internal_key(b"idb:conv:thread_01:msg_00", 8900, 1),
                pack_internal_key(b"idb:conv:thread_01:msg_00", 8900, 1),
            )
        ],
    )
    ve2 = build_version_edit(
        log_number=6,
        next_file_number=7,
        last_sequence=9045,
        deleted_files=[(1, 1)],
        new_files=[
            (
                1,
                3,
                len(ldb_000003),
                pack_internal_key(b"idb:conv:thread_01:msg_01", 9001, 1),
                pack_internal_key(b"idb:conv:thread_01:msg_99", 9003, 1),
            ),
            (
                0,
                5,
                len(ldb_000005),
                pack_internal_key(b"idb:conv:thread_01:msg_01", 9020, 0),
                pack_internal_key(b"idb:conv:thread_01:msg_01", 9020, 0),
            ),
        ],
    )
    manifest_000002 = encode_leveldb_log_record(REC_FULL, ve1) + encode_leveldb_log_record(REC_FULL, ve2)

    artifacts = {
        "CURRENT": b"MANIFEST-000002\n",
        "MANIFEST-000002": manifest_000002,
        "000001.ldb": ldb_000001,
        "000003.ldb": ldb_000003,
        "000005.ldb": ldb_000005,
        "000006.log": log_000006,
    }

    digests: dict[str, str] = {}
    for fname, content in artifacts.items():
        fpath = out_dir / fname
        fpath.write_bytes(content)
        digests[fname] = hashlib.sha256(content).hexdigest()
    return digests


def main() -> int:
    target_dir = REPO_ROOT / "examples" / "corrupted_leveldb_challenge"
    digests = build_challenge_files(target_dir)
    total_bytes = sum((target_dir / k).stat().st_size for k in digests)
    print(json.dumps({"target_dir": str(target_dir), "total_bytes": total_bytes, "sha256": digests}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
