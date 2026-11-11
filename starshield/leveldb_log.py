#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google LevelDB Write-Ahead Log (`.log`) Binary Frame & WriteBatch Parser
for Chromium IndexedDB / Web Messaging Cached JSON Snapshots.

Implements the official LevelDB log format specification:
- 32,768-byte (32 KiB) physical block boundaries with strict zero-padding trailer checks
- 7-byte record header: [masked_crc32c: uint32_le][length: uint16_le][type: uint8]
  where type in {1: FULL, 2: FIRST, 3: MIDDLE, 4: LAST}
- Castagnoli CRC32C (polynomial 0x82F63B78) + LevelDB mask delta 0xA282EAD8
- Strict LevelDB WriteBatch validation: [sequence: uint64_le][count: uint32_le] followed
  by varint-prefixed kTypeValue (0x01) and kTypeDeletion (0x00) entries, rejecting
  truncated payloads, op-count mismatches, trailing garbage bytes, and unclosed EOF fragments.
- Top-level `json.JSONDecoder.raw_decode` scanning (never regex carving nested child dicts).

Scope & Honest Limitations:
- Research prototype targeting uncompressed LevelDB `.log` write-ahead logs and embedded
  UTF-8/UTF-16LE JSON message slices inside Chromium IndexedDB WriteBatch values.
- Does NOT decompress Snappy-compressed `.ldb` SSTable data blocks or decode non-JSON
  Blink V8 StructuredClone primitives.
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Dict, List, Tuple

BLOCK_SIZE = 32768
HEADER_SIZE = 7
MAX_LOGICAL_RECORD_BYTES = 32 * 1024 * 1024  # 32 MiB anti-DoS cap per reassembled batch

REC_ZERO = 0
REC_FULL = 1
REC_FIRST = 2
REC_MIDDLE = 3
REC_LAST = 4

MASK_DELTA = 0xA282EAD8


def _build_crc32c_table() -> List[int]:
    poly = 0x82F63B78
    table: List[int] = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table.append(crc)
    return table


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def mask_crc32c(crc: int) -> int:
    return (((crc >> 15) | ((crc << 17) & 0xFFFFFFFF)) + MASK_DELTA) & 0xFFFFFFFF


def encode_leveldb_log_record(rec_type: int, payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("Single physical LevelDB log record payload cannot exceed 65535 bytes")
    raw_crc = crc32c(bytes([rec_type]) + payload)
    masked = mask_crc32c(raw_crc)
    return struct.pack("<IHB", masked, len(payload), rec_type) + payload


def encode_logical_record_across_blocks(payload: bytes, initial_block_used: int = 0) -> bytes:
    """Split a logical WriteBatch across 32KiB physical LevelDB blocks using FULL/FIRST/MIDDLE/LAST."""
    out = bytearray()
    rem_in_block = BLOCK_SIZE - (initial_block_used % BLOCK_SIZE)
    if rem_in_block < HEADER_SIZE:
        out.extend(b"\x00" * rem_in_block)
        rem_in_block = BLOCK_SIZE

    offset = 0
    first_piece = True
    total = len(payload)

    if total == 0:
        return bytes(out) + encode_leveldb_log_record(REC_FULL, b"")

    while offset < total:
        if rem_in_block < HEADER_SIZE:
            out.extend(b"\x00" * rem_in_block)
            rem_in_block = BLOCK_SIZE

        avail_data = rem_in_block - HEADER_SIZE
        take = min(avail_data, total - offset)
        chunk = payload[offset : offset + take]
        is_last = (offset + take) == total

        if first_piece and is_last:
            rtype = REC_FULL
        elif first_piece:
            rtype = REC_FIRST
        elif is_last:
            rtype = REC_LAST
        else:
            rtype = REC_MIDDLE

        frame = encode_leveldb_log_record(rtype, chunk)
        out.extend(frame)
        offset += take
        rem_in_block -= len(frame)
        first_piece = False

    return bytes(out)


def encode_varint(val: int) -> bytes:
    if val < 0:
        raise ValueError("Varint must be non-negative")
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def decode_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    shift = 0
    result = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint overflow")
    raise ValueError("Truncated varint")


def build_writebatch(sequence: int, operations: List[Tuple[int, bytes, bytes]]) -> bytes:
    """Build a spec-compliant LevelDB WriteBatch payload for fixtures & tests."""
    body = bytearray(struct.pack("<QI", sequence, len(operations)))
    for op_type, key, val in operations:
        body.append(op_type)
        body.extend(encode_varint(len(key)))
        body.extend(key)
        if op_type == 1:
            body.extend(encode_varint(len(val)))
            body.extend(val)
        elif op_type != 0:
            raise ValueError(f"Unsupported op_type {op_type}")
    return bytes(body)


def _is_valid_chatsvc_message_obj(obj: Any) -> bool:
    """Ensure carved JSON object is a top-level message record, not an inner sub-dict."""
    if not isinstance(obj, dict):
        return False
    msg_id = obj.get("id")
    if msg_id is None or str(msg_id).strip() == "":
        return False
    has_msg_shape = any(k in obj for k in ("content", "from", "composetime", "messagetype", "conversationid"))
    return has_msg_shape


def _extract_json_objects_from_bytes(raw_val: bytes) -> List[Dict[str, Any]]:
    """
    Scan UTF-8 (and UTF-16LE if NUL bytes exist) using `json.JSONDecoder.raw_decode`.
    Advances past the full span of each decoded top-level JSON object so nested child
    objects (e.g., `properties: {deletetime: ...}`) are NEVER mis-carved as standalone records.
    """
    candidates: List[str] = [raw_val.decode("utf-8", errors="ignore")]
    if b"\x00" in raw_val:
        candidates.append(raw_val.decode("utf-16-le", errors="ignore"))

    decoder = json.JSONDecoder()
    found: List[Dict[str, Any]] = []
    seen_hashes = set()

    for text in candidates:
        pos = 0
        n = len(text)
        while pos < n:
            brace_idx = text.find("{", pos)
            if brace_idx == -1:
                break
            try:
                obj, end_idx = decoder.raw_decode(text, brace_idx)
            except json.JSONDecodeError:
                pos = brace_idx + 1
                continue

            # Advance past the entire top-level JSON object so nested dicts are skipped
            pos = max(end_idx, brace_idx + 1)
            if _is_valid_chatsvc_message_obj(obj):
                canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False)
                h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    found.append(obj)

    return found


def parse_leveldb_wal(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse a Chromium LevelDB `.log` file, verifying CRC32C, WriteBatch bounds, and EOF completeness."""
    total_len = len(raw_bytes)
    physical_records_ok = 0
    corrupted_records: List[Dict[str, Any]] = []
    recovered_entries: List[Dict[str, Any]] = []

    frag_buf = bytearray()
    frag_start_offset: int | None = None

    block_idx = 0
    while block_idx * BLOCK_SIZE < total_len:
        block_start = block_idx * BLOCK_SIZE
        block_end = min(block_start + BLOCK_SIZE, total_len)
        pos = block_start

        while pos + HEADER_SIZE <= block_end:
            stored_crc, length, rec_type = struct.unpack_from("<IHB", raw_bytes, pos)
            if stored_crc == 0 and length == 0 and rec_type == REC_ZERO:
                # Remaining bytes in this 32KiB block must be zero-padded preallocation
                rem = raw_bytes[pos:block_end]
                if any(b != 0 for b in rem):
                    corrupted_records.append(
                        {
                            "byte_offset": pos,
                            "reason": "Non-zero bytes following zero-header preallocation region in 32KiB block",
                        }
                    )
                pos = block_end
                break

            rec_offset = pos
            data_start = pos + HEADER_SIZE
            data_end = data_start + length
            if data_end > block_end:
                corrupted_records.append(
                    {
                        "byte_offset": rec_offset,
                        "reason": "Record length exceeds 32KiB LevelDB block boundary or truncated EOF",
                    }
                )
                frag_buf.clear()
                frag_start_offset = None
                pos = block_end
                break

            chunk = raw_bytes[data_start:data_end]
            pos = data_end

            expected_masked = mask_crc32c(crc32c(bytes([rec_type]) + chunk))
            if stored_crc != expected_masked:
                corrupted_records.append(
                    {
                        "byte_offset": rec_offset,
                        "record_type": rec_type,
                        "reason": f"CRC32C mismatch (stored=0x{stored_crc:08x}, computed=0x{expected_masked:08x})",
                    }
                )
                frag_buf.clear()
                frag_start_offset = None
                continue

            physical_records_ok += 1

            if rec_type == REC_FULL:
                if frag_start_offset is not None:
                    corrupted_records.append(
                        {
                            "byte_offset": frag_start_offset,
                            "reason": "Unclosed FIRST/MIDDLE fragmented record interrupted by FULL record",
                        }
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                logical_bytes = chunk
                logical_offset = rec_offset
            elif rec_type == REC_FIRST:
                if frag_start_offset is not None:
                    corrupted_records.append(
                        {
                            "byte_offset": frag_start_offset,
                            "reason": "Unclosed FIRST/MIDDLE fragmented record interrupted by new FIRST record",
                        }
                    )
                frag_buf = bytearray(chunk)
                frag_start_offset = rec_offset
                continue
            elif rec_type == REC_MIDDLE:
                if frag_start_offset is None:
                    corrupted_records.append(
                        {"byte_offset": rec_offset, "reason": "Orphan MIDDLE fragment without FIRST"}
                    )
                    continue
                if len(frag_buf) + len(chunk) > MAX_LOGICAL_RECORD_BYTES:
                    corrupted_records.append(
                        {"byte_offset": frag_start_offset, "reason": "Fragmented record exceeds 32MiB safety limit"}
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                    continue
                frag_buf.extend(chunk)
                continue
            elif rec_type == REC_LAST:
                if frag_start_offset is None:
                    corrupted_records.append(
                        {"byte_offset": rec_offset, "reason": "Orphan LAST fragment without FIRST"}
                    )
                    continue
                if len(frag_buf) + len(chunk) > MAX_LOGICAL_RECORD_BYTES:
                    corrupted_records.append(
                        {"byte_offset": frag_start_offset, "reason": "Fragmented record exceeds 32MiB safety limit"}
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                    continue
                frag_buf.extend(chunk)
                logical_bytes = bytes(frag_buf)
                logical_offset = frag_start_offset
                frag_buf.clear()
                frag_start_offset = None
            else:
                corrupted_records.append(
                    {"byte_offset": rec_offset, "reason": f"Unknown LevelDB record type {rec_type}"}
                )
                frag_buf.clear()
                frag_start_offset = None
                continue

            _decode_writebatch_into(logical_bytes, logical_offset, recovered_entries, corrupted_records)

        # Check 1..6 byte block trailer: per LevelDB spec, block trailers < 7 bytes must be 0x00
        if pos < block_end:
            trailer = raw_bytes[pos:block_end]
            if any(b != 0 for b in trailer):
                corrupted_records.append(
                    {
                        "byte_offset": pos,
                        "reason": f"Non-zero truncated header/trailer ({len(trailer)} bytes < 7-byte header)",
                    }
                )

        block_idx += 1

    if frag_start_offset is not None:
        corrupted_records.append(
            {
                "byte_offset": frag_start_offset,
                "reason": "Truncated logical record: unclosed FIRST/MIDDLE fragment at EOF",
            }
        )

    return {
        "parser": "leveldb_wal_32k_crc32c_v0.3.5",
        "file_size_bytes": total_len,
        "valid_physical_frames": physical_records_ok,
        "corrupted_frames_count": len(corrupted_records),
        "corrupted_frames": corrupted_records,
        "recovered_chatsvc_records_count": len(recovered_entries),
        "recovered_records": recovered_entries,
    }


def _decode_writebatch_into(
    batch: bytes,
    logical_offset: int,
    out_entries: List[Dict[str, Any]],
    corrupted: List[Dict[str, Any]],
) -> None:
    if len(batch) < 12:
        corrupted.append({"byte_offset": logical_offset, "reason": "WriteBatch shorter than 12-byte header"})
        return

    seq_num, declared_count = struct.unpack_from("<QI", batch, 0)
    idx = 12
    parsed_ops = 0
    staged_entries: List[Dict[str, Any]] = []

    try:
        while idx < len(batch) and parsed_ops < declared_count:
            op_type = batch[idx]
            idx += 1
            key_len, idx = decode_varint(batch, idx)
            if idx + key_len > len(batch):
                raise ValueError(f"Truncated key bytes (declared={key_len}, remaining={len(batch) - idx})")
            key_bytes = batch[idx : idx + key_len]
            idx += key_len

            if op_type == 1:
                val_len, idx = decode_varint(batch, idx)
                if idx + val_len > len(batch):
                    raise ValueError(f"Truncated value bytes (declared={val_len}, remaining={len(batch) - idx})")
                val_bytes = batch[idx : idx + val_len]
                idx += val_len
                for obj in _extract_json_objects_from_bytes(val_bytes):
                    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
                    del_ts = props.get("deletetime") or obj.get("deletetime")
                    edit_ts = props.get("edittime") or obj.get("edittime")
                    staged_entries.append(
                        {
                            "epistemic_tier": "OBSERVED",
                            "leveldb_batch_byte_offset": logical_offset,
                            "leveldb_sequence_number": seq_num,
                            "key_sha256": hashlib.sha256(key_bytes).hexdigest(),
                            "value_sha256": hashlib.sha256(val_bytes).hexdigest(),
                            "message_id": str(obj.get("id", "")),
                            "sender_mri": str(obj.get("from", "")),
                            "composetime": obj.get("composetime"),
                            "deletetime": del_ts,
                            "edittime": edit_ts,
                            "is_soft_deleted_in_ui": bool(del_ts),
                            "note_on_edittime": (
                                "Present value reflects post-edit state unless an earlier sequence_number "
                                "record with the same message_id exists in uncompacted log frames."
                                if edit_ts
                                else None
                            ),
                            "cached_content": str(obj.get("content", "")),
                        }
                    )
            elif op_type == 0:
                pass
            else:
                raise ValueError(f"Unsupported WriteBatch op_type=0x{op_type:02x}")
            parsed_ops += 1

        if parsed_ops != declared_count:
            raise ValueError(f"WriteBatch op count mismatch (declared={declared_count}, parsed={parsed_ops})")
        if idx != len(batch):
            raise ValueError(f"Trailing unparsed bytes in WriteBatch ({len(batch) - idx} bytes remaining)")

    except Exception as exc:
        corrupted.append({"byte_offset": logical_offset, "reason": f"Malformed WriteBatch entry: {exc}"})
        return

    out_entries.extend(staged_entries)
