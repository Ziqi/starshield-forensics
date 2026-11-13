#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao (@Ziqi)
# SPDX-License-Identifier: MIT
"""
Dual-Tool & Independent Reference Cross-Validation Harness (`verify_cross_tool_forensics.py`).

Structured in alignment with:
  - UK Forensic Science Regulator (FSR) Code of Practice (`FSR-C-100` / `FSR-C-107`)
  - ISO/IEC 17025:2017 Clause 7.2.2 (Validation of Methods)
  - NIST SP 800-86 / SWGDE Digital Forensics Tool Testing Guidelines

Executes three deterministic validation suites without modifying runtime dependencies:
  - Suite 1: Chromium LevelDB `.log` Write-Ahead Log (WAL) frame-by-frame and record-by-record
    cross-validation against Google's `dfindexeddb` (`dfindexeddb.leveldb.log.FileReader`, when
    installed in an isolated QA venv) plus an independent clean-room LevelDB log decoder.
  - Suite 2: PNG (RFC 2083) & JPEG (ISO/IEC 10918-1) container framing and ISO 15076-1 (`acsp`)
    ICC header cross-validation against `Pillow` (`PIL.Image`, when installed) plus independent
    structural chunk/marker verifiers.
  - Suite 3: Financial indicator mathematical cross-validation across ISO/IEC 7812 Luhn cards,
    all 89 ISO 13616 IBAN jurisdictions (Mod-97-10), and all 250 ISO 9362 SWIFT/BIC country codes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import platform
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield import __version__  # noqa: E402
from starshield.cli import build_synthetic_leveldb_wal_bytes  # noqa: E402
from starshield.image_containers import (  # noqa: E402
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (  # noqa: E402
    COMMON_ENGLISH_8LETTER_STOPWORDS,
    IBAN_LENGTHS,
    ISO_3166_ALPHA2,
    extract_validated_iocs,
    iban_mod97_valid,
    luhn_valid,
)
from starshield.leveldb_log import (  # noqa: E402
    BLOCK_SIZE,
    HEADER_SIZE,
    REC_FULL,
    build_writebatch,
    crc32c,
    encode_leveldb_log_record,
    encode_logical_record_across_blocks,
    parse_leveldb_wal,
)

EXPECTED_EXH01_LEN = 68779
EXPECTED_EXH01_SHA256 = "c2ac19e91535c2a641023ac96893c2d5c25a38c3e5f507254e91e75bf6b172ff"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"Cross-validation check failed: {message}")


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _detect_optional_pkg(dist_name: str, module_name: str) -> Tuple[bool, str | None]:
    try:
        spec = importlib.util.find_spec(module_name)
    except ModuleNotFoundError:
        return False, None
    if spec is None:
        return False, None
    try:
        return True, importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return True, "unknown"


# ---------------------------------------------------------------------------
# Independent Clean-Room Specification Verifiers (Zero Third-Party Deps)
# ---------------------------------------------------------------------------


def _ref_decode_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    shift = 0
    result = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
    raise ValueError("Truncated varint in reference WriteBatch decoder")


def _ref_parse_valid_leveldb_wal(raw: bytes) -> Dict[str, Any]:
    """Independent clean-room LevelDB log specification reader for valid WAL streams."""
    physical_crcs: List[int] = []
    batches: List[int] = []
    value_ops: List[Dict[str, Any]] = []
    deletion_ops = 0

    frag = bytearray()
    n_blocks = (len(raw) + BLOCK_SIZE - 1) // BLOCK_SIZE
    for blk_idx in range(n_blocks):
        blk = raw[blk_idx * BLOCK_SIZE : (blk_idx + 1) * BLOCK_SIZE]
        pos = 0
        while pos + HEADER_SIZE <= len(blk):
            header = blk[pos : pos + HEADER_SIZE]
            if header == b"\x00" * HEADER_SIZE:
                break
            stored_crc, length, rtype = struct.unpack("<IHB", header)
            if stored_crc == 0 and length == 0 and rtype == 0:
                break
            payload = blk[pos + HEADER_SIZE : pos + HEADER_SIZE + length]
            _require(len(payload) == length, "Reference reader encountered truncated frame")
            raw_crc = crc32c(bytes([rtype]) + payload)
            calc_masked = (((raw_crc >> 15) | ((raw_crc << 17) & 0xFFFFFFFF)) + 0xA282EAD8) & 0xFFFFFFFF
            _require(calc_masked == stored_crc, "Reference reader encountered CRC32C mismatch")
            physical_crcs.append(stored_crc)
            pos += HEADER_SIZE + length

            if rtype == 1:  # FULL
                wb_bytes = payload
            elif rtype == 2:  # FIRST
                frag = bytearray(payload)
                continue
            elif rtype == 3:  # MIDDLE
                frag.extend(payload)
                continue
            elif rtype == 4:  # LAST
                frag.extend(payload)
                wb_bytes = bytes(frag)
                frag.clear()
            else:
                raise ValueError(f"Unsupported LevelDB record type {rtype}")

            seq_base, count = struct.unpack_from("<QI", wb_bytes, 0)
            batches.append(seq_base)
            wpos = 12
            for idx in range(count):
                tag = wb_bytes[wpos]
                wpos += 1
                klen, wpos = _ref_decode_varint(wb_bytes, wpos)
                key = wb_bytes[wpos : wpos + klen]
                wpos += klen
                if tag == 1:
                    vlen, wpos = _ref_decode_varint(wb_bytes, wpos)
                    val = wb_bytes[wpos : wpos + vlen]
                    wpos += vlen
                    value_ops.append(
                        {
                            "batch_seq": seq_base,
                            "internal_key_seq": seq_base + idx,
                            "key_sha256": _sha256_hex(key),
                            "value_sha256": _sha256_hex(val),
                        }
                    )
                elif tag == 0:
                    deletion_ops += 1
                else:
                    raise ValueError(f"Unsupported WriteBatch tag {tag}")

    return {
        "physical_frames": len(physical_crcs),
        "physical_crcs": physical_crcs,
        "batches": batches,
        "value_ops": value_ops,
        "deletion_ops": deletion_ops,
    }


def _ref_luhn_gf10(digits: str) -> bool:
    """Independent table-lookup ISO/IEC 7812 Luhn check-digit verifier."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    double_map = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)
    parity = len(digits) % 2
    acc = 0
    for idx, ch in enumerate(digits):
        d = ord(ch) - 48
        acc += double_map[d] if (idx % 2 == parity) else d
    return (acc % 10) == 0


def _ref_iban_horner_mod97(iban: str) -> bool:
    """Independent streaming Horner ISO/IEC 7064 Mod 97-10 IBAN verifier."""
    cleaned = "".join(ch for ch in iban.upper() if ch not in " -")
    if len(cleaned) < 15 or len(cleaned) > 34 or not cleaned.isalnum():
        return False
    if not cleaned[:2].isalpha() or not cleaned[2:4].isdigit():
        return False
    expected = IBAN_LENGTHS.get(cleaned[:2])
    if expected is None or len(cleaned) != expected:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    rem = 0
    for ch in rearranged:
        if "0" <= ch <= "9":
            rem = (rem * 10 + (ord(ch) - 48)) % 97
        else:
            val = ord(ch) - 55
            rem = (rem * 100 + val) % 97
    return rem == 1


def _build_valid_iban_for_country(cc: str, length: int) -> str:
    body_len = length - 4
    pattern = f"{cc}99" + ("1234567890" * 4)
    bban = "".join(str((ord(ch) % 10)) if ch.isalpha() else ch for ch in pattern[:body_len])
    rearranged_zero = bban + cc + "00"
    rem = 0
    for ch in rearranged_zero:
        if "0" <= ch <= "9":
            rem = (rem * 10 + (ord(ch) - 48)) % 97
        else:
            rem = (rem * 100 + (ord(ch) - 55)) % 97
    check = 98 - rem
    return f"{cc}{check:02d}{bban}"


# ---------------------------------------------------------------------------
# Suite 1: Chromium LevelDB `.log` WAL Cross-Validation
# ---------------------------------------------------------------------------


def _build_suite1_vectors() -> List[Dict[str, Any]]:
    exh01 = build_synthetic_leveldb_wal_bytes()
    _require(len(exh01) == EXPECTED_EXH01_LEN, f"EXH-01 length drift: {len(exh01)}")
    _require(_sha256_hex(exh01) == EXPECTED_EXH01_SHA256, "EXH-01 SHA-256 drift")

    # S1-V02: Single-block FULL multi-operation WriteBatch (Value + Deletion + Value)
    msg_u1 = json.dumps(
        {
            "id": "msg_utf8_01",
            "from": "user:ap_desk",
            "composetime": "2025-04-01T09:00:00Z",
            "content": "Primary UTF-8 invoice control record.",
        }
    ).encode("utf-8")
    msg_u2 = json.dumps(
        {
            "id": "msg_utf8_02",
            "from": "user:ap_desk",
            "composetime": "2025-04-01T09:05:00Z",
            "content": "Secondary UTF-8 invoice control record after tombstone.",
            "properties": {"deletetime": "1743498600000"},
        }
    ).encode("utf-8")
    wb_v02 = build_writebatch(
        204801,
        [
            (1, b"idb:key:utf8_01", msg_u1),
            (0, b"idb:key:obsolete_tombstone", b""),
            (1, b"idb:key:utf8_02", msg_u2),
        ],
    )
    wal_v02 = encode_logical_record_across_blocks(wb_v02, initial_block_used=0)

    # S1-V03: Block-boundary zero-padded trailer (<7 bytes remaining) + Blink UTF-16LE JSON
    pad_msg = json.dumps(
        {
            "id": "msg_pad_block0",
            "from": "user:ap_desk",
            "composetime": "2025-04-01T10:00:00Z",
            "content": "B" * 32550,
        }
    ).encode("utf-8")
    wb_pad = build_writebatch(300001, [(1, b"k_pad", pad_msg)])
    raw_pad = encode_leveldb_log_record(REC_FULL, wb_pad)
    # Adjust filler so block 0 has 5 trailing bytes (< 7-byte header), triggering zero-pad trailer
    rem_in_blk0 = BLOCK_SIZE - len(raw_pad)
    if rem_in_blk0 >= HEADER_SIZE:
        extra = rem_in_blk0 - 5
        pad_msg = json.dumps(
            {
                "id": "msg_pad_block0",
                "from": "user:ap_desk",
                "composetime": "2025-04-01T10:00:00Z",
                "content": "B" * (32550 + extra - HEADER_SIZE),
            }
        ).encode("utf-8")
        # Fine-tune exact length to leave <= 6 bytes in block 0
        wb_pad = build_writebatch(300001, [(1, b"k_pad", pad_msg)])
        raw_pad = encode_leveldb_log_record(REC_FULL, wb_pad)
        while BLOCK_SIZE - len(raw_pad) >= HEADER_SIZE:
            pad_msg += b" "
            wb_pad = build_writebatch(300001, [(1, b"k_pad", pad_msg)])
            raw_pad = encode_leveldb_log_record(REC_FULL, wb_pad)
    blk0_padded = raw_pad + b"\x00" * (BLOCK_SIZE - len(raw_pad))

    utf16_json = json.dumps(
        {
            "id": "msg_utf16le_boundary_01",
            "from": "user:blink_v8_store",
            "composetime": "2025-04-01T10:15:00Z",
            "content": "Blink V8 UTF-16LE serialized IndexedDB payload across block boundary.",
            "properties": {"deletetime": "1743502500000"},
        }
    ).encode("utf-16-le")
    blink_utf16_val = b"\xff\x15\xfe\x00\x63\x00" + utf16_json
    wb_utf16 = build_writebatch(300002, [(1, b"\x00\x01idb:utf16_01", blink_utf16_val)])
    wal_v03 = blk0_padded + encode_logical_record_across_blocks(wb_utf16, initial_block_used=0)

    # S1-V04: 4-block large fragmented WriteBatch (FIRST + MIDDLE + MIDDLE + LAST)
    large_msg = b"\xff\x15\xfe\x00\x22" + json.dumps(
        {
            "id": "msg_4block_frag_01",
            "from": "user:large_attachment_meta",
            "composetime": "2025-04-01T11:00:00Z",
            "content": "Multi-block fragmented WriteBatch control vector.",
            "properties": {"large_pad": "Z" * 105000},
        }
    ).encode("utf-8")
    wb_v04 = build_writebatch(400001, [(1, b"idb:large:01", large_msg)])
    wal_v04 = encode_logical_record_across_blocks(wb_v04, initial_block_used=0)

    # S1-V05: Adversarial CRC32C bit-flip corruption in Block 0 + clean Block 1 resynchronization
    f_good1 = encode_leveldb_log_record(
        REC_FULL,
        build_writebatch(
            500001,
            [
                (
                    1,
                    b"k1",
                    json.dumps(
                        {
                            "id": "msg_pre_corrupt",
                            "from": "user:ctrl",
                            "composetime": "2025-04-01T12:00:00Z",
                            "content": "Intact frame prior to bit-rot.",
                        }
                    ).encode("utf-8"),
                )
            ],
        ),
    )
    f_bad_raw = bytearray(
        encode_leveldb_log_record(
            REC_FULL,
            build_writebatch(
                500002,
                [
                    (
                        1,
                        b"k2",
                        json.dumps(
                            {
                                "id": "msg_corrupted_bitflip",
                                "from": "user:ctrl",
                                "composetime": "2025-04-01T12:01:00Z",
                                "content": "Payload with injected bit-flip.",
                            }
                        ).encode("utf-8"),
                    )
                ],
            ),
        )
    )
    f_bad_raw[-10] ^= 0x01  # Flip 1 bit in payload without updating stored Castagnoli CRC32C
    blk0_corrupt = bytes(f_good1 + bytes(f_bad_raw)).ljust(BLOCK_SIZE, b"\x00")
    f_good3 = encode_leveldb_log_record(
        REC_FULL,
        build_writebatch(
            500003,
            [
                (
                    1,
                    b"k3",
                    json.dumps(
                        {
                            "id": "msg_post_resync",
                            "from": "user:ctrl",
                            "composetime": "2025-04-01T12:02:00Z",
                            "content": "Intact frame in subsequent 32 KiB block.",
                        }
                    ).encode("utf-8"),
                )
            ],
        ),
    )
    wal_v05 = blk0_corrupt + f_good3

    # S1-V06: Truncated mid-frame tail (power-loss / unflushed tail simulation)
    f_trunc_ok = encode_leveldb_log_record(
        REC_FULL,
        build_writebatch(
            600001,
            [
                (
                    1,
                    b"k_trunc_ok",
                    json.dumps(
                        {
                            "id": "msg_before_trunc",
                            "from": "user:ctrl",
                            "composetime": "2025-04-01T13:00:00Z",
                            "content": "Committed record before tail truncation.",
                        }
                    ).encode("utf-8"),
                )
            ],
        ),
    )
    f_trunc_tail = encode_leveldb_log_record(
        REC_FULL,
        build_writebatch(600002, [(1, b"k_trunc_cut", b"A" * 256)]),
    )[:-64]
    wal_v06 = f_trunc_ok + f_trunc_tail

    return [
        {
            "id": "S1-V01",
            "label": "EXH-01 canonical multi-block Blink WAL (FULL + FIRST/MIDDLE/LAST)",
            "raw": exh01,
            "is_valid_stream": True,
            "expected_msg_ids": ["msg_spec_0001", "msg_spec_0002"],
        },
        {
            "id": "S1-V02",
            "label": "Multi-op WriteBatch (kTypeValue + kTypeDeletion tombstone + kTypeValue)",
            "raw": wal_v02,
            "is_valid_stream": True,
            "expected_msg_ids": ["msg_utf8_01", "msg_utf8_02"],
        },
        {
            "id": "S1-V03",
            "label": "32 KiB block-trailer zero-pad (<7B) + Blink V8 UTF-16LE JSON payload",
            "raw": wal_v03,
            "is_valid_stream": True,
            "expected_msg_ids": ["msg_pad_block0", "msg_utf16le_boundary_01"],
        },
        {
            "id": "S1-V04",
            "label": "4-block fragmented WriteBatch (FIRST + 2x MIDDLE + LAST, >105 KiB)",
            "raw": wal_v04,
            "is_valid_stream": True,
            "expected_msg_ids": ["msg_4block_frag_01"],
        },
        {
            "id": "S1-V05",
            "label": "Adversarial payload bit-flip (CRC32C mismatch quarantine + 32 KiB block resync)",
            "raw": wal_v05,
            "is_valid_stream": False,
            "expected_corrupted_frames": 1,
            "expected_msg_ids": ["msg_pre_corrupt", "msg_post_resync"],
        },
        {
            "id": "S1-V06",
            "label": "Truncated mid-frame tail recovery (unflushed EOF simulation)",
            "raw": wal_v06,
            "is_valid_stream": False,
            "expected_corrupted_frames": 1,
            "expected_msg_ids": ["msg_before_trunc"],
        },
    ]


def run_suite_1_leveldb(has_dfindexeddb: bool) -> Dict[str, Any]:
    df_log = None
    df_defs = None
    if has_dfindexeddb:
        from dfindexeddb.leveldb import definitions as _df_defs
        from dfindexeddb.leveldb import log as _df_log

        df_log = _df_log
        df_defs = _df_defs

    vectors = _build_suite1_vectors()
    vector_reports: List[Dict[str, Any]] = []
    valid_records_compared = 0
    valid_frames_compared = 0

    for vec in vectors:
        raw = vec["raw"]
        ss = parse_leveldb_wal(raw, schema_mode="auto")
        got_ids = [r["message_id"] for r in ss["recovered_records"]]
        _require(
            got_ids == vec["expected_msg_ids"],
            f"{vec['id']} message_id mismatch: got {got_ids}, expected {vec['expected_msg_ids']}",
        )

        entry: Dict[str, Any] = {
            "vector_id": vec["id"],
            "description": vec["label"],
            "byte_length": len(raw),
            "sha256": _sha256_hex(raw),
            "starshield_valid_frames": ss["valid_physical_frames"],
            "starshield_corrupted_frames": ss["corrupted_frames_count"],
            "starshield_recovered_records": len(ss["recovered_records"]),
            "concordance_status": "PASS",
        }

        if vec["is_valid_stream"]:
            _require(ss["corrupted_frames_count"] == 0, f"{vec['id']} unexpected corruption")
            ref = _ref_parse_valid_leveldb_wal(raw)
            _require(
                ss["valid_physical_frames"] == ref["physical_frames"],
                f"{vec['id']} physical frame count mismatch vs reference",
            )
            ss_ops = [
                {
                    "batch_seq": r["leveldb_sequence_number"],
                    "key_sha256": r["key_sha256"],
                    "value_sha256": r["value_sha256"],
                }
                for r in ss["recovered_records"]
            ]
            ref_batch_ops = [
                {
                    "batch_seq": op["batch_seq"],
                    "key_sha256": op["key_sha256"],
                    "value_sha256": op["value_sha256"],
                }
                for op in ref["value_ops"]
            ]
            _require(ss_ops == ref_batch_ops, f"{vec['id']} WriteBatch record digest mismatch vs reference")
            valid_frames_compared += ref["physical_frames"]
            valid_records_compared += len(ss_ops)

            if df_log is not None and df_defs is not None:
                with tempfile.NamedTemporaryFile(suffix=".log") as tf:
                    tf.write(raw)
                    tf.flush()
                    reader = df_log.FileReader(tf.name)
                    df_phys = list(reader.GetPhysicalRecords())
                    df_batches = list(reader.GetWriteBatches())

                _require(
                    len(df_phys) == ss["valid_physical_frames"],
                    f"{vec['id']} dfindexeddb physical frame count mismatch",
                )
                df_crcs = [p.checksum for p in df_phys]
                _require(
                    df_crcs == ref["physical_crcs"],
                    f"{vec['id']} dfindexeddb header checksum list mismatch",
                )
                df_val_ops = []
                df_internal_ops = []
                for b in df_batches:
                    for k in b.records:
                        if k.record_type == df_defs.InternalRecordType.VALUE:
                            df_val_ops.append(
                                {
                                    "batch_seq": b.sequence_number,
                                    "key_sha256": _sha256_hex(k.key),
                                    "value_sha256": _sha256_hex(k.value),
                                }
                            )
                            df_internal_ops.append(
                                {
                                    "batch_seq": b.sequence_number,
                                    "internal_key_seq": k.sequence_number,
                                    "key_sha256": _sha256_hex(k.key),
                                    "value_sha256": _sha256_hex(k.value),
                                }
                            )
                _require(
                    df_val_ops == ss_ops and df_internal_ops == ref["value_ops"],
                    f"{vec['id']} dfindexeddb vs StarShield record SHA-256/sequence mismatch",
                )
                entry["dfindexeddb_physical_frames"] = len(df_phys)
                entry["dfindexeddb_batches"] = len(df_batches)
                entry["dfindexeddb_value_records"] = len(df_val_ops)
                entry["dfindexeddb_exact_match"] = True
        else:
            _require(
                ss["corrupted_frames_count"] == vec["expected_corrupted_frames"],
                f"{vec['id']} expected {vec['expected_corrupted_frames']} corrupted frames",
            )
            if df_log is not None and vec["id"] == "S1-V05":
                with tempfile.NamedTemporaryFile(suffix=".log") as tf:
                    tf.write(raw)
                    tf.flush()
                    reader = df_log.FileReader(tf.name)
                    df_keys = list(reader.GetParsedInternalKeys())
                # Documented cross-tool behavioral finding: dfindexeddb stores PhysicalRecord.checksum
                # without enforcing masked Castagnoli CRC32C verification prior to WriteBatch decode.
                _require(
                    len(df_keys) == 3 and len(ss["recovered_records"]) == 2,
                    "Expected StarShield to quarantine CRC-corrupted record while dfindexeddb emits unverified record",
                )
                entry["documented_error_boundary"] = (
                    "StarShield quarantined 1 CRC32C-corrupted frame (seq 500002) and resynchronized at byte 32768; "
                    "dfindexeddb 20260210 stores PhysicalRecord.checksum without validating CRC32C and yielded 3 records."
                )

        vector_reports.append(entry)

    return {
        "suite": "Suite 1 - Chromium LevelDB .log WAL Carving & Fragmented WriteBatch Reassembly",
        "external_comparator": "google/dfindexeddb" if has_dfindexeddb else "stdlib-reference-only",
        "vectors_tested": len(vectors),
        "valid_physical_frames_verified": valid_frames_compared,
        "valid_records_verified": valid_records_compared,
        "concordance_rate_valid_streams": 1.0,
        "vectors": vector_reports,
    }


# ---------------------------------------------------------------------------
# Suite 2: Structural PNG & JPEG Container + ISO 15076-1 ICC Cross-Validation
# ---------------------------------------------------------------------------


def run_suite_2_containers(has_pillow: bool) -> Dict[str, Any]:
    pil_image = None
    pil_unidentified = None
    if has_pillow:
        from PIL import Image as _pil_image
        from PIL import UnidentifiedImageError as _pil_unidentified

        pil_image = _pil_image
        pil_unidentified = _pil_unidentified

    png_p3 = build_valid_png_with_iccp(
        "Display P3",
        "APPL",
        software_text="Software\x00QuickShot Raster Editor 4.2",
    )
    png_srgb = build_valid_png_with_iccp("sRGB IEC61966-2.1", "MSFT")
    jpg_split3 = build_valid_jpeg_with_icc_and_8bim("Display P3", "APPL", split_icc_chunks=3)

    # S2-V04: Flip 1 bit inside PNG iCCP chunk data to trigger IEEE 802.3 CRC-32 failure
    png_bad_crc_mut = bytearray(png_p3)
    iccp_idx = png_bad_crc_mut.index(b"iCCP")
    png_bad_crc_mut[iccp_idx + 10] ^= 0x01
    png_bad_crc = bytes(png_bad_crc_mut)

    # S2-V05: Truncated JPEG missing terminal 0xFFD9 EOI marker
    jpg_trunc = jpg_split3[:-2]

    # S2-V06: Plaintext chat export containing image-profile keywords (anti-substring false-positive check)
    text_decoy = (
        b'{"message": "User discussed Photoshop 3.0\x008BIM and Display P3 acsp ICC_PROFILE in chat text."}'
    )

    cases: List[Dict[str, Any]] = []

    # Check S2-V01 (including independent RFC 2083 IEEE 802.3 CRC-32 walk)
    ppos = 8
    while ppos < len(png_p3):
        clen = struct.unpack_from(">I", png_p3, ppos)[0]
        body = png_p3[ppos + 4 : ppos + 8 + clen]
        scrc = struct.unpack_from(">I", png_p3, ppos + 8 + clen)[0]
        _require((zlib.crc32(body) & 0xFFFFFFFF) == scrc, "Independent RFC 2083 CRC32 mismatch on S2-V01")
        ppos += 12 + clen
    r_p3 = inspect_image_container(png_p3, "S2-V01_display_p3.png")
    _require(r_p3["valid_container"] is True and r_p3["container_format"] == "PNG", "S2-V01 PNG invalid")
    _require(
        r_p3["icc_profiles"][0]["description_hint"] == "Display P3"
        and r_p3["icc_profiles"][0]["primary_platform"] == "APPL",
        "S2-V01 ICC mismatch",
    )
    if pil_image is not None:
        im = pil_image.open(io.BytesIO(png_p3))
        pil_icc = im.info.get("icc_profile", b"")
        _require(im.format == "PNG" and len(pil_icc) == 160 and pil_icc[36:40] == b"acsp", "Pillow S2-V01 mismatch")
        im.verify()
    cases.append({"vector_id": "S2-V01", "format": "PNG", "status": "PASS", "sha256": _sha256_hex(png_p3)})

    # Check S2-V02
    r_srgb = inspect_image_container(png_srgb, "S2-V02_srgb_msft.png")
    _require(r_srgb["valid_container"] is True, "S2-V02 PNG invalid")
    _require(
        r_srgb["icc_profiles"][0]["description_hint"] == "sRGB IEC61966-2.1"
        and r_srgb["icc_profiles"][0]["primary_platform"] == "MSFT",
        "S2-V02 ICC mismatch",
    )
    if pil_image is not None:
        im2 = pil_image.open(io.BytesIO(png_srgb))
        pil_icc2 = im2.info.get("icc_profile", b"")
        _require(b"sRGB IEC61966-2.1" in pil_icc2 and pil_icc2[40:44] == b"MSFT", "Pillow S2-V02 mismatch")
        im2.verify()
    cases.append({"vector_id": "S2-V02", "format": "PNG", "status": "PASS", "sha256": _sha256_hex(png_srgb)})

    # Check S2-V03
    r_jpg = inspect_image_container(jpg_split3, "S2-V03_multi_app2_8bim.jpg")
    _require(r_jpg["valid_container"] is True and r_jpg["container_format"] == "JPEG", "S2-V03 JPEG invalid")
    _require(r_jpg["icc_profiles"][0]["jpeg_app2_chunks_reassembled"] == 3, "S2-V03 APP2 chunk count mismatch")
    _require(len(r_jpg["photoshop_app13_8bim_offsets"]) == 1, "S2-V03 APP13 8BIM offset missing")
    if pil_image is not None:
        im3 = pil_image.open(io.BytesIO(jpg_split3))
        pil_icc3 = im3.info.get("icc_profile", b"")
        _require(
            im3.format == "JPEG" and len(pil_icc3) == 160 and pil_icc3[36:40] == b"acsp" and "photoshop" in im3.info,
            "Pillow S2-V03 JPEG multi-APP2/8BIM mismatch",
        )
    cases.append({"vector_id": "S2-V03", "format": "JPEG", "status": "PASS", "sha256": _sha256_hex(jpg_split3)})

    # Check S2-V04 (corrupted PNG iCCP CRC32)
    r_bad_crc = inspect_image_container(png_bad_crc, "S2-V04_corrupt_crc.png")
    _require(r_bad_crc["valid_container"] is False and len(r_bad_crc["crc_errors"]) == 1, "S2-V04 missed PNG CRC error")
    if pil_image is not None:
        pil_rejected_crc = False
        try:
            im4 = pil_image.open(io.BytesIO(png_bad_crc))
            im4.verify()
        except Exception:
            pil_rejected_crc = True
        _require(pil_rejected_crc, "Pillow failed to reject corrupted PNG iCCP CRC32")
    cases.append({"vector_id": "S2-V04", "format": "PNG_CORRUPT_CRC", "status": "PASS", "sha256": _sha256_hex(png_bad_crc)})

    # Check S2-V05 (truncated JPEG missing EOI)
    r_trunc = inspect_image_container(jpg_trunc, "S2-V05_truncated.jpg")
    _require(r_trunc["valid_container"] is False and len(r_trunc["container_errors"]) >= 1, "S2-V05 missed truncated EOI")
    cases.append({"vector_id": "S2-V05", "format": "JPEG_TRUNCATED", "status": "PASS", "sha256": _sha256_hex(jpg_trunc)})

    # Check S2-V06 (non-image plaintext decoy)
    r_decoy = inspect_image_container(text_decoy, "S2-V06_plaintext_decoy.json")
    _require(
        r_decoy["valid_container"] is False and r_decoy["container_format"] == "UNSUPPORTED_OR_NOT_AN_IMAGE",
        "S2-V06 decoy misclassified as image",
    )
    if pil_image is not None and pil_unidentified is not None:
        decoy_rejected = False
        try:
            pil_image.open(io.BytesIO(text_decoy))
        except pil_unidentified:
            decoy_rejected = True
        _require(decoy_rejected, "Pillow failed to reject plaintext decoy")
    cases.append({"vector_id": "S2-V06", "format": "NON_IMAGE_DECOY", "status": "PASS", "sha256": _sha256_hex(text_decoy)})

    return {
        "suite": "Suite 2 - Structural PNG (RFC 2083), JPEG (ISO 10918-1) & ICC (ISO 15076-1) Verification",
        "external_comparator": "Pillow (PIL.Image)" if has_pillow else "stdlib-reference-only",
        "vectors_tested": len(cases),
        "concordance_rate": 1.0,
        "vectors": cases,
    }


# ---------------------------------------------------------------------------
# Suite 3: Financial IOC Check-Digit & Registry Mathematical Cross-Validation
# ---------------------------------------------------------------------------


def run_suite_3_iocs() -> Dict[str, Any]:
    # 1. ISO/IEC 7812 Luhn vectors (12 positive & negative boundary cases across 13..19 digits)
    luhn_vectors = [
        ("49927398716", False),  # 11 digits (<13 minimum) -> must reject
        ("4000000000006", True),  # 13-digit valid Visa test length
        ("4000000000007", False),  # 13-digit single-bit check error
        ("6200000000000005", True),  # 16-digit valid UnionPay IIN range
        ("6200000000000004", False),  # 16-digit invalid check digit
        ("6200000000000050", False),  # 16-digit adjacent transposition
        ("5105105105105100", True),  # 16-digit valid Mastercard test vector
        ("5105105105105108", False),  # 16-digit invalid Mastercard test vector
        ("4111111111111111", True),  # 16-digit classic test PAN
        ("4111111111111112", False),  # 16-digit invalid classic PAN
        ("6212345678901234562", True) if _ref_luhn_gf10("6212345678901234562") else ("6212345678901234566", True),
        ("40000000000000000000", False),  # 20 digits (>19 maximum) -> must reject
    ]
    # Ensure exact deterministic 19-digit valid PAN
    pan19_prefix = "620000000000000000"
    pan19_valid = next(pan19_prefix + d for d in "0123456789" if _ref_luhn_gf10(pan19_prefix + d))
    luhn_vectors[10] = (pan19_valid, True)

    for candidate, expected in luhn_vectors:
        got_ss = luhn_valid(candidate)
        got_ref = _ref_luhn_gf10(candidate)
        _require(got_ss == expected and got_ss == got_ref, f"Luhn mismatch on {candidate}")

    # Verify separation of luhn_validated_cards vs unvalidated_card_candidates
    ioc_card_mix = extract_validated_iocs(
        f"Valid card 6200-0000-0000-0005 vs typo candidate 6200-0000-0000-0004 and 19-digit {pan19_valid}.",
        redact=False,
    )
    _require(
        ioc_card_mix["luhn_validated_cards"] == ["6200000000000005", pan19_valid]
        and ioc_card_mix["unvalidated_card_candidates"] == ["6200000000000004"],
        "Luhn card separation mismatch in extract_validated_iocs",
    )

    # 2. ISO 13616 IBAN Registry: all 89 jurisdictions (89 valid + 89 check-digit negative + 6 structural negative = 184)
    _require(len(IBAN_LENGTHS) == 89, f"Expected 89 ISO 13616 jurisdictions, got {len(IBAN_LENGTHS)}")
    iban_checked = 0
    for cc, length in sorted(IBAN_LENGTHS.items()):
        valid_iban = _build_valid_iban_for_country(cc, length)
        _require(iban_mod97_valid(valid_iban) is True, f"Valid IBAN rejected for {cc}: {valid_iban}")
        _require(_ref_iban_horner_mod97(valid_iban) is True, f"Ref Horner rejected {valid_iban}")

        bad_chk_num = (int(valid_iban[2:4]) + 1) % 97
        if bad_chk_num < 2:
            bad_chk_num = 2
        bad_iban = f"{cc}{bad_chk_num:02d}{valid_iban[4:]}"
        _require(iban_mod97_valid(bad_iban) is False, f"Corrupted IBAN accepted for {cc}: {bad_iban}")
        _require(_ref_iban_horner_mod97(bad_iban) is False, f"Ref Horner accepted {bad_iban}")
        iban_checked += 2

    structural_neg_ibans = [
        "ZZ82WEST12345698765432",  # Unregistered country code ZZ
        "US82WEST12345698765432",  # Non-IBAN jurisdiction US
        "CN82WEST12345698765432",  # Non-IBAN jurisdiction CN
        "GB82WEST1234569876543",   # 21 chars (GB requires 22)
        "GB82WEST123456987654321", # 23 chars (GB requires 22)
        "NO938601111794",          # 14 chars (below 15-char minimum)
    ]
    for neg in structural_neg_ibans:
        _require(iban_mod97_valid(neg) is False and _ref_iban_horner_mod97(neg) is False, f"Accepted invalid IBAN {neg}")
        iban_checked += 1

    # 3. ISO 9362 SWIFT/BIC: all 250 ISO 3166-1 alpha-2 (+ XK) codes + stopword & context gates
    _require(len(ISO_3166_ALPHA2) == 250, f"Expected 250 ISO 3166-1 + XK codes, got {len(ISO_3166_ALPHA2)}")
    bic_checked = 0
    for cc in sorted(ISO_3166_ALPHA2):
        bic11 = f"NWBK{cc}2LXXX"
        res = extract_validated_iocs(f"Wire routing SWIFT {bic11}", redact=False)
        _require(res["validated_swift_bics"] == [bic11], f"Valid BIC11 rejected for country {cc}")
        bic_checked += 1

    for bad_cc in ("ZZ", "AA", "QM", "99"):
        bad_bic = f"NWBK{bad_cc}2LXXX"
        res_bad = extract_validated_iocs(f"Wire routing SWIFT {bad_bic}", redact=False)
        _require(res_bad["validated_swift_bics"] == [], f"Invalid BIC country accepted: {bad_bic}")
        bic_checked += 1

    for word in sorted(COMMON_ENGLISH_8LETTER_STOPWORDS):
        res_sw = extract_validated_iocs(f"Wire routing SWIFT {word}", redact=False)
        _require(res_sw["validated_swift_bics"] == [], f"English stopword misflagged as BIC: {word}")
        bic_checked += 1

    # Verify 8-letter alpha BIC requires explicit banking context
    no_ctx = extract_validated_iocs("Plain sentence containing DEUTDEFF without banking keywords.", redact=False)
    with_ctx = extract_validated_iocs("Beneficiary SWIFT DEUTDEFF for SEPA settlement.", redact=False)
    _require(
        no_ctx["validated_swift_bics"] == [] and with_ctx["validated_swift_bics"] == ["DEUTDEFF"],
        "8-letter BIC context gate failed",
    )
    bic_checked += 2

    return {
        "suite": "Suite 3 - Financial Indicator Check-Digit & Registry Validation (ISO 7812 / 13616 / 9362)",
        "external_comparator": "Independent GF(10) Luhn + Horner Mod 97-10 + ISO Registry Matrix",
        "luhn_vectors_tested": len(luhn_vectors),
        "iban_jurisdictions_tested": len(IBAN_LENGTHS),
        "iban_vectors_tested": iban_checked,
        "swift_bic_iso3166_codes_tested": len(ISO_3166_ALPHA2),
        "swift_bic_vectors_tested": bic_checked,
        "total_vectors_tested": len(luhn_vectors) + iban_checked + bic_checked,
        "concordance_rate": 1.0,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run UK FSR / ISO 17025 dual-tool & specification cross-validation suites."
    )
    parser.add_argument(
        "--require-external",
        action="store_true",
        help="Require Google dfindexeddb and Pillow to be importable in the current Python environment.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write full JSON cross-validation telemetry.",
    )
    args = parser.parse_args(argv)

    has_dfindexeddb, df_ver = _detect_optional_pkg("dfindexeddb", "dfindexeddb.leveldb.log")
    has_pillow, pil_ver = _detect_optional_pkg("Pillow", "PIL.Image")

    if args.require_external and (not has_dfindexeddb or not has_pillow):
        missing = []
        if not has_dfindexeddb:
            missing.append("dfindexeddb")
        if not has_pillow:
            missing.append("Pillow")
        sys.stderr.write(f"ERROR: --require-external set, but missing external comparators: {', '.join(missing)}\n")
        return 2

    t0 = time.perf_counter()
    s1 = run_suite_1_leveldb(has_dfindexeddb=has_dfindexeddb)
    s2 = run_suite_2_containers(has_pillow=has_pillow)
    s3 = run_suite_3_iocs()
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    summary: Dict[str, Any] = {
        "validation_schema": "starshield-cross-tool-validation/v1",
        "alignment_frameworks": [
            "UK Forensic Science Regulator Code of Practice (FSR-C-100 / FSR-C-107)",
            "ISO/IEC 17025:2017 Clause 7.2.2 (Validation of Methods)",
            "SWGDE / NIST SP 800-86 Digital Forensics Tool Testing",
        ],
        "accreditation_disclaimer": (
            "Self-contained open-source tool validation summary structured in alignment with UK FSR Code "
            "of Practice (FSR-C-107) and ISO/IEC 17025 Clause 7.2.2 to assist accredited forensic "
            "laboratories and instructing solicitors in their local validation workflows - not a claim "
            "of laboratory accreditation."
        ),
        "subject_tool": {
            "name": "starshield-forensics",
            "version": __version__,
            "runtime_dependencies": 0,
        },
        "execution_environment": {
            "python_version": platform.python_version(),
            "platform": f"{platform.system()}-{platform.machine()}",
            "dfindexeddb_available": has_dfindexeddb,
            "dfindexeddb_version": df_ver,
            "pillow_available": has_pillow,
            "pillow_version": pil_ver,
            "elapsed_ms": elapsed_ms,
        },
        "suites": {
            "suite_1_leveldb_wal": s1,
            "suite_2_image_containers": s2,
            "suite_3_financial_iocs": s3,
        },
        "overall_status": "PASS",
    }

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    mode_str = (
        f"DUAL-TOOL EXTERNAL (dfindexeddb={df_ver}, Pillow={pil_ver})"
        if (has_dfindexeddb and has_pillow)
        else "STANDALONE STDLIB REFERENCE"
    )
    print(
        f"[PASS] starshield-forensics v{__version__} cross-validation ({mode_str}) completed in {elapsed_ms} ms | "
        f"S1={s1['vectors_tested']} WAL vectors ({s1['valid_records_verified']} valid records, 100% concordance) | "
        f"S2={s2['vectors_tested']} PNG/JPEG vectors (100% concordance) | "
        f"S3={s3['total_vectors_tested']} ISO-7812/13616/9362 vectors (100% concordance)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
