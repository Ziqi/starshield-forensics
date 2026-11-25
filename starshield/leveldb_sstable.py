#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Pure-Stdlib Google LevelDB SSTable (`.ldb` / `.sst`), Snappy Block Decompressor,
`MANIFEST-*` (`VersionEdit`) Replayer & Cross-Level Tombstone Reconciler.

Implements official LevelDB table and manifest binary formats using Python >=3.10 stdlib only:
- Snappy raw block decompression (`decompress_snappy`) with bounded varint32 target length,
  anti-preallocation bomb protection, and RLE overlapping copy window support (`offset < length`).
- 48-byte SSTable Footer (`[metaindex_handle][index_handle][padding][0xdb4775248b80fb57]`),
  Index Block `BlockHandle (offset, size)` addressing, and 5-byte block trailers
  (`[compression_type: 1B][masked_crc32c: uint32_le]`) supporting `0x00` (uncompressed) and
  `0x01` (Snappy), while honestly counting `0x02` (Zstandard) blocks as unsupported.
- Prefix-compressed Restart-Point block decoding and 8-byte `InternalKey` unpacking
  (`user_key`, `sequence_number = tag >> 8`, `value_type = tag & 0xFF` for `0x01` value vs
  `0x00` deletion tombstone).
- Sequential multi-record `MANIFEST-*` `VersionEdit` state-machine replay separating active
  compaction levels from unreferenced orphan `.ldb` tables still residing on disk.
- Store-wide reconciliation across `.log` WAL + active `.ldb` + orphan `.ldb` classifying
  records as `LIVE_ACTIVE`, `UI_SOFT_DELETED`, or `TOMBSTONED_HISTORICAL_RECOVERED`.

Scope & Honest Limitations:
- Decodes JSON slices (`chatsvc`, `slack_web`, `web_messenger`, `b2b_portal_json`, `generic_json`)
  and lightweight printable UTF-8 / UTF-16LE LocalStorage key-value text (in `generic-json` mode).
- Does NOT implement full binary Blink V8 `StructuredClone` AST deserialization, decompress
  Zstandard (`0x02`) blocks, reconstruct externalized IndexedDB `.blob` files, or parse SQLite.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple

from starshield import __version__
from starshield.leveldb_log import (
    LEVELDB_SSTABLE_MAGIC_LE,
    MAX_CORRUPTED_RECORDS_REPORTED,
    MAX_PRECHECK_SCAN_FILES,
    VALID_SCHEMA_MODES,
    SafeDiagnosticError,
    _extract_json_objects_from_bytes,
    _has_sqlite3_magic,
    crc32c,
    decode_varint,
    encode_varint,
    iter_leveldb_logical_records,
    mask_crc32c,
    normalize_carved_record_fields,
    read_bounded_bytes,
    sanitize_utf8_str,
)

SSTABLE_FOOTER_SIZE = 48
BLOCK_TRAILER_SIZE = 5
COMPRESSION_NONE = 0x00
COMPRESSION_SNAPPY = 0x01
COMPRESSION_ZSTD = 0x02

MAX_SNAPPY_BLOCK_UNCOMPRESSED_BYTES = 16 * 1024 * 1024  # 16 MiB single-block cap
MAX_STORE_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024  # 64 MiB cumulative store Snappy decompression cap
MAX_INTERNAL_KEY_BYTES = 64 * 1024  # 64 KiB single InternalKey cap (defeats O(N^2) prefix-key bombs)
MAX_STORE_MATERIALIZED_BYTES = 128 * 1024 * 1024  # 128 MiB cumulative materialized KV & op-overhead budget
PER_OP_OVERHEAD_BYTES = 256  # CPython dict/tuple/int heap overhead charged per parsed KV/tombstone op
MAX_BLOCK_ENTRIES = 65536  # Max entries per single SSTable block
MAX_STORE_RAW_OPS = 250000  # Store-wide raw KV/tombstone operation ceiling
MAX_RESTARTS_PER_BLOCK = 262144
MAX_KV_TEXT_CHARS = 512

_SOURCE_RANK = {
    "sstable": 2,
    "wal_log": 1,
    "orphan_sstable": 0,
    "orphan_wal_log": 0,
}


def make_store_budget(
    *,
    snappy_bytes: int = MAX_STORE_TOTAL_UNCOMPRESSED_BYTES,
    materialized_bytes: int = MAX_STORE_MATERIALIZED_BYTES,
    max_ops: int = MAX_STORE_RAW_OPS,
) -> Dict[str, int]:
    """Create a fresh store-wide decompression, materialized-memory, and op-count budget dictionary."""
    return {
        "remaining": snappy_bytes,
        "materialized_remaining": materialized_bytes,
        "ops_remaining": max_ops,
    }

# VersionEdit tags from LevelDB db/version_edit.cc
_VE_COMPARATOR = 1
_VE_LOG_NUMBER = 2
_VE_NEXT_FILE_NUMBER = 3
_VE_LAST_SEQUENCE = 4
_VE_COMPACT_POINTER = 5
_VE_DELETED_FILE = 6
_VE_NEW_FILE = 7
_VE_PREV_LOG_NUMBER = 9

_MANIFEST_NAME_RE = re.compile(r"^MANIFEST-([0-9]+)$", re.IGNORECASE)
_PRINTABLE_CTRL_OK = frozenset({9, 10, 13})
KNOWN_SAFE_MANIFEST_COMPARATORS = frozenset({"leveldb.BytewiseComparator", "idb_cmp1"})


def _decode_varint32(buf: bytes | memoryview, pos: int, limit: int) -> Tuple[int, int]:
    """Decode an unsigned 32-bit varint strictly within `buf[pos:limit]`."""
    shift = 0
    result = 0
    while pos < limit:
        b = buf[pos]
        pos += 1
        if shift == 28 and (b & 0xF0) != 0:
            raise ValueError("Varint32 overflow (> 32 bits)")
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 28:
            raise ValueError("Varint32 exceeded 5 bytes")
    raise ValueError("Truncated varint32")


def _decode_varint64_bounded(buf: bytes | memoryview, pos: int, limit: int) -> Tuple[int, int]:
    """Decode an unsigned 64-bit varint strictly within `buf[pos:limit]`."""
    shift = 0
    result = 0
    while pos < limit:
        b = buf[pos]
        pos += 1
        if shift == 63 and b > 1:
            raise ValueError("Varint64 overflow (> 64 bits)")
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint64 exceeded 10 bytes")
    raise ValueError("Truncated varint64")


def decompress_snappy(
    data: bytes | memoryview,
    max_uncompressed_bytes: int = MAX_SNAPPY_BLOCK_UNCOMPRESSED_BYTES,
) -> bytes:
    """
    Decompress a raw Google Snappy block in pure Python stdlib.

    Enforces `max_uncompressed_bytes` BEFORE and DURING decoding without upfront allocation of
    `declared_len` (preventing 5-byte varint memory-exhaustion bombs) and expands overlapping
    RLE copy windows (`offset < copy_len`) accurately.
    """
    if max_uncompressed_bytes < 0:
        raise ValueError("Snappy decompression budget exhausted")
    n = len(data)
    if n == 0:
        raise ValueError("Empty Snappy stream (missing varint32 uncompressed length)")

    declared_len, pos = _decode_varint32(data, 0, n)
    if declared_len > max_uncompressed_bytes:
        raise BufferError(
            f"Declared Snappy uncompressed size ({declared_len} bytes) exceeds {max_uncompressed_bytes}-byte safety cap"
        )
    if declared_len == 0:
        if pos != n:
            raise ValueError("Trailing bytes in zero-length Snappy block")
        return b""

    out = bytearray()
    while pos < n:
        tag = data[pos]
        pos += 1
        tag_type = tag & 0x03

        if tag_type == 0:  # Literal (`0b00`)
            len_minus_1 = tag >> 2
            if len_minus_1 < 60:
                lit_len = len_minus_1 + 1
            else:
                extra = len_minus_1 - 59  # 1..4 bytes little-endian
                if pos + extra > n:
                    raise ValueError("Truncated Snappy literal length header")
                lit_len = int.from_bytes(data[pos : pos + extra], "little") + 1
                pos += extra

            if pos + lit_len > n:
                raise ValueError("Truncated Snappy literal payload")
            if len(out) + lit_len > declared_len:
                raise ValueError("Snappy literal output exceeds declared uncompressed length")
            out.extend(data[pos : pos + lit_len])
            pos += lit_len
            continue

        if tag_type == 1:  # Copy with 1-byte offset (`0b01`: len 4..11, 11-bit offset)
            if pos >= n:
                raise ValueError("Truncated Snappy 1-byte copy offset")
            b1 = data[pos]
            pos += 1
            copy_len = ((tag >> 2) & 0x07) + 4
            offset = ((tag & 0xE0) << 3) | b1
        elif tag_type == 2:  # Copy with 2-byte LE offset (`0b10`: len 1..64, 16-bit offset)
            if pos + 2 > n:
                raise ValueError("Truncated Snappy 2-byte copy offset")
            copy_len = (tag >> 2) + 1
            offset = int.from_bytes(data[pos : pos + 2], "little")
            pos += 2
        else:  # Copy with 4-byte LE offset (`0b11`: len 1..64, 32-bit offset)
            if pos + 4 > n:
                raise ValueError("Truncated Snappy 4-byte copy offset")
            copy_len = (tag >> 2) + 1
            offset = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4

        cur_len = len(out)
        if offset <= 0 or offset > cur_len:
            raise ValueError(f"Invalid Snappy copy offset {offset} at output position {cur_len}")
        if cur_len + copy_len > declared_len:
            raise ValueError("Snappy copy output exceeds declared uncompressed length")

        if offset >= copy_len:
            start = cur_len - offset
            out.extend(out[start : start + copy_len])
        elif offset == 1:
            out.extend(bytes([out[-1]]) * copy_len)
        else:
            pat = bytes(out[cur_len - offset :])
            reps, rem = divmod(copy_len, offset)
            out.extend(pat * reps)
            if rem:
                out.extend(pat[:rem])

    if len(out) != declared_len:
        raise ValueError(
            f"Truncated Snappy stream: decoded {len(out)} bytes vs declared {declared_len} bytes"
        )
    return bytes(out)


def _emit_snappy_literal(out: bytearray, lit: bytes | memoryview) -> None:
    lit_len = len(lit)
    if lit_len == 0:
        return
    n_minus_1 = lit_len - 1
    if n_minus_1 < 60:
        out.append(n_minus_1 << 2)
    elif n_minus_1 <= 0xFF:
        out.append(60 << 2)
        out.append(n_minus_1)
    elif n_minus_1 <= 0xFFFF:
        out.append(61 << 2)
        out.extend(n_minus_1.to_bytes(2, "little"))
    elif n_minus_1 <= 0xFFFFFF:
        out.append(62 << 2)
        out.extend(n_minus_1.to_bytes(3, "little"))
    else:
        out.append(63 << 2)
        out.extend(n_minus_1.to_bytes(4, "little"))
    out.extend(lit)


def _emit_snappy_copy(out: bytearray, offset: int, length: int) -> None:
    while length > 0:
        if 4 <= length <= 11 and offset < 2048:
            out.append(0x01 | ((length - 4) << 2) | ((offset >> 3) & 0xE0))
            out.append(offset & 0xFF)
            return
        step = min(length, 64)
        # Keep remaining tail >= 4 if possible when using 1-byte copy next, though 2-byte supports 1..64
        if offset <= 0xFFFF:
            out.append(0x02 | ((step - 1) << 2))
            out.extend(offset.to_bytes(2, "little"))
        else:
            out.append(0x03 | ((step - 1) << 2))
            out.extend(offset.to_bytes(4, "little"))
        length -= step


def compress_snappy(raw: bytes) -> bytes:
    """
    Deterministic pure-stdlib Snappy compressor emitting genuine literals (`0b00`) and
    1-byte/2-byte/4-byte LZ77 back-reference copies (`0b01`/`0b10`/`0b11`) for fixtures & tests.
    """
    n = len(raw)
    out = bytearray(encode_varint(n))
    if n == 0:
        return bytes(out)
    if n < 16:
        _emit_snappy_literal(out, raw)
        return bytes(out)

    table: Dict[bytes, int] = {}
    lit_start = 0
    pos = 0
    while pos + 4 <= n:
        key4 = raw[pos : pos + 4]
        cand = table.get(key4)
        table[key4] = pos
        if cand is not None and 0 < (pos - cand) <= 0xFFFF and raw[cand : cand + 4] == key4:
            _emit_snappy_literal(out, raw[lit_start:pos])
            offset = pos - cand
            m_len = 4
            while pos + m_len < n and raw[cand + m_len] == raw[pos + m_len]:
                m_len += 1
            _emit_snappy_copy(out, offset, m_len)
            pos += m_len
            lit_start = pos
            if pos + 4 <= n:
                table[raw[pos - 1 : pos + 3]] = pos - 1
        else:
            pos += 1

    if lit_start < n:
        _emit_snappy_literal(out, raw[lit_start:n])
    return bytes(out)


def pack_internal_key(user_key: bytes, sequence_number: int, value_type: int) -> bytes:
    """Pack LevelDB 8-byte `(sequence_number << 8) | value_type` trailer onto `user_key`."""
    if value_type not in (0, 1):
        raise ValueError(f"Unsupported LevelDB InternalKey value_type={value_type}")
    if sequence_number < 0 or sequence_number > ((1 << 56) - 1):
        raise ValueError(f"Sequence number out of 56-bit LevelDB range: {sequence_number}")
    tag = (sequence_number << 8) | (value_type & 0xFF)
    return user_key + struct.pack("<Q", tag)


def unpack_internal_key(internal_key: bytes) -> Tuple[bytes, int, int]:
    """Unpack LevelDB `InternalKey` into `(user_key, sequence_number, value_type)`."""
    if len(internal_key) < 8:
        raise ValueError(f"Malformed LevelDB InternalKey shorter than 8 bytes ({len(internal_key)}B)")
    user_key = internal_key[:-8]
    tag = struct.unpack_from("<Q", internal_key, len(internal_key) - 8)[0]
    return user_key, (tag >> 8), (tag & 0xFF)


def _encode_sstable_block(kv_pairs: List[Tuple[bytes, bytes]], restart_interval: int = 16) -> bytes:
    """Encode a prefix-compressed LevelDB SSTable block with trailing restart offset array."""
    if restart_interval < 1:
        restart_interval = 1
    buf = bytearray()
    restarts: List[int] = [0]
    prev_key = b""

    for idx, (key, val) in enumerate(kv_pairs):
        if idx > 0 and (idx % restart_interval) == 0:
            restarts.append(len(buf))
            prev_key = b""
        shared = 0
        max_shared = min(len(prev_key), len(key))
        while shared < max_shared and prev_key[shared] == key[shared]:
            shared += 1
        non_shared = len(key) - shared
        buf.extend(encode_varint(shared))
        buf.extend(encode_varint(non_shared))
        buf.extend(encode_varint(len(val)))
        buf.extend(key[shared:])
        buf.extend(val)
        prev_key = key

    for r_off in restarts:
        buf.extend(struct.pack("<I", r_off))
    buf.extend(struct.pack("<I", len(restarts)))
    return bytes(buf)


def _wrap_block_with_trailer(raw_block: bytes, compress: bool = True) -> bytes:
    """Attach LevelDB 5-byte `[compression_type][masked_crc32c_le]` trailer to a block."""
    if compress:
        payload = compress_snappy(raw_block)
        ctype = COMPRESSION_SNAPPY
    else:
        payload = raw_block
        ctype = COMPRESSION_NONE
    masked_crc = mask_crc32c(crc32c(payload + bytes([ctype])))
    return payload + struct.pack("<BI", ctype, masked_crc)


def build_leveldb_sstable(
    entries: List[Tuple[bytes, int, int, bytes]],
    *,
    compress: bool = True,
    restart_interval: int = 16,
    block_target_bytes: int = 4096,
) -> bytes:
    """
    Build a spec-compliant LevelDB `.ldb` SSTable from `(user_key, seq, value_type, value)` tuples.

    Sorts keys per LevelDB `InternalKeyComparator` (`user_key ASC`, `sequence_number DESC`,
    `value_type DESC`) and writes Data Blocks, MetaIndex Block, Index Block, and 48B Footer.
    """
    sorted_entries = sorted(entries, key=lambda item: (item[0], -item[1], -item[2]))
    out = bytearray()
    index_entries: List[Tuple[bytes, bytes]] = []

    cur_kv: List[Tuple[bytes, bytes]] = []
    cur_est = 0

    def flush_data_block() -> None:
        nonlocal cur_est
        if not cur_kv:
            return
        raw_blk = _encode_sstable_block(cur_kv, restart_interval=restart_interval)
        wrapped = _wrap_block_with_trailer(raw_blk, compress=compress)
        blk_off = len(out)
        blk_size = len(wrapped) - BLOCK_TRAILER_SIZE
        out.extend(wrapped)
        last_ikey = cur_kv[-1][0]
        handle_bytes = encode_varint(blk_off) + encode_varint(blk_size)
        index_entries.append((last_ikey, handle_bytes))
        cur_kv.clear()
        cur_est = 0

    for ukey, seq, vtype, val in sorted_entries:
        ikey = pack_internal_key(ukey, seq, vtype)
        cur_kv.append((ikey, b"" if vtype == 0 else val))
        cur_est += len(ikey) + len(val) + 6
        if cur_est >= block_target_bytes:
            flush_data_block()
    flush_data_block()

    # MetaIndex block (empty table with 1 restart point `[0, 1]`)
    meta_raw = _encode_sstable_block([], restart_interval=1)
    meta_wrapped = _wrap_block_with_trailer(meta_raw, compress=False)
    meta_off = len(out)
    meta_size = len(meta_wrapped) - BLOCK_TRAILER_SIZE
    out.extend(meta_wrapped)

    # Index block
    idx_raw = _encode_sstable_block(index_entries, restart_interval=1)
    idx_wrapped = _wrap_block_with_trailer(idx_raw, compress=compress)
    idx_off = len(out)
    idx_size = len(idx_wrapped) - BLOCK_TRAILER_SIZE
    out.extend(idx_wrapped)

    handles = (
        encode_varint(meta_off)
        + encode_varint(meta_size)
        + encode_varint(idx_off)
        + encode_varint(idx_size)
    )
    footer = handles + (b"\x00" * (40 - len(handles))) + LEVELDB_SSTABLE_MAGIC_LE
    out.extend(footer)
    return bytes(out)


def _iter_sstable_block_entries(
    block_bytes: bytes,
    budget_state: Dict[str, int] | None = None,
) -> Iterator[Tuple[int, bytes, bytes]]:
    """
    Stream prefix-compressed `(rel_offset, key, value)` entries from an uncompressed SSTable block.

    Enforces `MAX_INTERNAL_KEY_BYTES` (`64 KiB`) per key and charges `len(key) + len(val)` against
    `budget_state["materialized_remaining"]` prior to allocation to defeat O(N^2) prefix-key bombs.
    """
    blen = len(block_bytes)
    if blen < 4:
        raise ValueError(f"SSTable block shorter than 4-byte restart trailer ({blen}B)")
    num_restarts = struct.unpack_from("<I", block_bytes, blen - 4)[0]
    if num_restarts == 0 or num_restarts > MAX_RESTARTS_PER_BLOCK:
        raise ValueError(f"Invalid SSTable block restart count {num_restarts}")
    trailer_bytes = 4 * (num_restarts + 1)
    if trailer_bytes > blen:
        raise ValueError("SSTable restart array exceeds block length")

    entries_limit = blen - trailer_bytes
    for r_idx in range(num_restarts):
        r_off = struct.unpack_from("<I", block_bytes, entries_limit + r_idx * 4)[0]
        if r_off > entries_limit:
            raise ValueError(f"Restart offset {r_off} exceeds entries boundary {entries_limit}")
        if r_idx == 0 and entries_limit > 0 and r_off != 0:
            raise ValueError(f"First restart offset must be 0, got {r_off}")

    per_block_mat_cap = min(32 * blen + 1024 * 1024, 32 * 1024 * 1024)
    block_mat_used = 0
    block_entries = 0
    pos = 0
    prev_key = b""
    while pos < entries_limit:
        entry_off = pos
        shared, pos = _decode_varint32(block_bytes, pos, entries_limit)
        non_shared, pos = _decode_varint32(block_bytes, pos, entries_limit)
        val_len, pos = _decode_varint32(block_bytes, pos, entries_limit)
        if shared > len(prev_key):
            raise ValueError(
                f"Prefix-compressed key shared length {shared} exceeds previous key length {len(prev_key)}"
            )
        key_total = shared + non_shared
        if key_total > MAX_INTERNAL_KEY_BYTES:
            raise ValueError(
                f"SSTable InternalKey length ({key_total}B) exceeds {MAX_INTERNAL_KEY_BYTES}-byte safety cap"
            )
        if pos + non_shared + val_len > entries_limit:
            raise ValueError("Truncated key/value payload inside SSTable block")
        block_entries += 1
        if block_entries > MAX_BLOCK_ENTRIES:
            raise ValueError(f"SSTable block entry count exceeds {MAX_BLOCK_ENTRIES}-entry safety cap")
        entry_cost = key_total + val_len + PER_OP_OVERHEAD_BYTES
        block_mat_used += entry_cost
        if block_mat_used > per_block_mat_cap:
            raise ValueError(
                "SSTable block prefix-key/entry expansion exceeds per-block amplification safety bound"
            )
        if budget_state is not None:
            ops_rem = budget_state.get("ops_remaining", MAX_STORE_RAW_OPS)
            if ops_rem <= 0:
                raise BufferError(
                    f"Cumulative LevelDB operation count exceeded {MAX_STORE_RAW_OPS}-op store safety budget"
                )
            mat_rem = budget_state.get("materialized_remaining", MAX_STORE_MATERIALIZED_BYTES)
            if entry_cost > mat_rem:
                raise BufferError(
                    "Cumulative LevelDB materialized key/value bytes exceeded 128 MiB store safety budget"
                )
            budget_state["ops_remaining"] = ops_rem - 1
            budget_state["materialized_remaining"] = mat_rem - entry_cost
        key = prev_key[:shared] + block_bytes[pos : pos + non_shared]
        pos += non_shared
        val = block_bytes[pos : pos + val_len]
        pos += val_len
        prev_key = key
        yield (entry_off, key, val)


def _read_and_verify_sstable_block(
    raw_mv: memoryview,
    file_limit: int,
    offset: int,
    size: int,
    budget_state: Dict[str, int],
) -> Tuple[str, bytes, str]:
    """
    Verify 5-byte CRC32C trailer and decode an SSTable block (`0x00` raw, `0x01` Snappy, `0x02` Zstd).

    Returns `(status, uncompressed_bytes, reason)` where `status` is one of:
    `"ok"`, `"zstd_unsupported"`, `"budget_exceeded"`, or `"corrupt"`.
    """
    if offset < 0 or size < 0 or offset + size + BLOCK_TRAILER_SIZE > file_limit:
        return "corrupt", b"", f"BlockHandle (offset={offset}, size={size}) out of SSTable bounds"

    block_slice = raw_mv[offset : offset + size]
    ctype = raw_mv[offset + size]
    stored_crc = struct.unpack_from("<I", raw_mv, offset + size + 1)[0]

    # Verify Castagnoli CRC32C over `block_contents + compression_type` before touching Snappy
    expected_crc = mask_crc32c(crc32c(raw_mv[offset : offset + size + 1]))
    if stored_crc != expected_crc:
        return (
            "corrupt",
            b"",
            f"SSTable block CRC32C mismatch (stored=0x{stored_crc:08x}, computed=0x{expected_crc:08x})",
        )

    if ctype == COMPRESSION_NONE:
        return "ok", bytes(block_slice), ""

    if ctype == COMPRESSION_SNAPPY:
        if len(block_slice) == 0:
            return "corrupt", b"", "Empty Snappy compressed SSTable block"
        try:
            declared_len, _ = _decode_varint32(block_slice, 0, len(block_slice))
        except ValueError as exc:
            return "corrupt", b"", f"Malformed Snappy header varint32: {exc}"

        if declared_len > MAX_SNAPPY_BLOCK_UNCOMPRESSED_BYTES:
            return (
                "corrupt",
                b"",
                f"Declared Snappy block size ({declared_len}B) exceeds {MAX_SNAPPY_BLOCK_UNCOMPRESSED_BYTES}-byte block safety cap",
            )
        # Snappy's theoretical max compression ratio is 64 output bytes per 3-byte 0b10 copy tag (~21.33x)
        if declared_len > (24 * len(block_slice) + 64):
            return (
                "corrupt",
                b"",
                f"Declared Snappy block size ({declared_len}B) exceeds theoretical Snappy expansion bound for {len(block_slice)}-byte input",
            )

        remaining = budget_state.get("remaining", MAX_STORE_TOTAL_UNCOMPRESSED_BYTES)
        if declared_len > remaining:
            return (
                "budget_exceeded",
                b"",
                "Cumulative Snappy decompression exceeded 64 MiB store safety budget",
            )
        try:
            unpacked = decompress_snappy(block_slice, max_uncompressed_bytes=declared_len)
        except (BufferError, ValueError) as exc:
            fail_charge = min(declared_len, max(len(block_slice) * 2, 65536))
            budget_state["remaining"] = max(0, remaining - fail_charge)
            return "corrupt", b"", f"Malformed Snappy compressed block: {exc}"
        budget_state["remaining"] = max(0, remaining - len(unpacked))
        return "ok", unpacked, ""

    if ctype == COMPRESSION_ZSTD:
        return "zstd_unsupported", b"", "Zstandard (0x02) compressed block not supported in pure-stdlib runtime"

    return "corrupt", b"", f"Unknown SSTable block compression type 0x{ctype:02x}"


def _decode_chromium_string_prefixed(buf: bytes) -> str | None:
    """
    Decode Chromium LocalStorage / DOMStorage value or key segment (`\\x01` UTF-8/Latin-1,
    `\\x00` UTF-16LE, or clean printable UTF-8) while rejecting binary Blink V8 `0xFF` blobs.
    """
    if not buf:
        return None
    if buf[0] == 0xFF or (len(buf) >= 2 and buf[0] == 0x00 and buf[1] == 0xFF):
        return None

    cand: str | None = None
    if buf[0] == 0x01 and len(buf) > 1:
        try:
            cand = buf[1:].decode("utf-8")
        except UnicodeDecodeError:
            cand = buf[1:].decode("latin-1")
    elif buf[0] == 0x00 and len(buf) >= 3 and (len(buf) - 1) % 2 == 0:
        try:
            cand = buf[1:].decode("utf-16-le")
        except UnicodeDecodeError:
            cand = None
    else:
        try:
            cand = buf.decode("utf-8")
        except UnicodeDecodeError:
            cand = None

    if not cand:
        return None
    cleaned = sanitize_utf8_str(cand).strip("\x00 \t\r\n")
    if len(cleaned) < 2:
        return None
    printable = sum(1 for ch in cleaned if ch.isprintable() or ord(ch) in _PRINTABLE_CTRL_OK)
    if printable / len(cleaned) < 0.85:
        return None
    return cleaned[:MAX_KV_TEXT_CHARS]


def _extract_lightweight_kv_record(user_key: bytes, val_bytes: bytes) -> Dict[str, Any] | None:
    """
    Lightweight non-V8-AST key-value string extractor for `generic-json` mode (covering Chromium
    LocalStorage `_<origin>\\x00\\x01<key>` and Electron/LevelDB plaintext KV entries).
    """
    val_txt = _decode_chromium_string_prefixed(val_bytes)
    if not val_txt:
        return None

    origin_str = ""
    key_label = ""
    if user_key.startswith(b"_") and b"\x00" in user_key[1:]:
        sep = user_key.index(b"\x00", 1)
        origin_raw = user_key[1:sep]
        rest_key = user_key[sep + 1 :]
        origin_str = origin_raw.decode("utf-8", errors="ignore").strip()
        key_label = _decode_chromium_string_prefixed(rest_key) or rest_key.decode("utf-8", errors="ignore").strip()
    else:
        key_label = _decode_chromium_string_prefixed(user_key) or ""

    if not key_label:
        key_label = f"key_{hashlib.sha256(user_key).hexdigest()[:12]}"

    return {
        "message_id": key_label[:128],
        "sender_mri": origin_str[:128],
        "composetime": None,
        "deletetime": None,
        "edittime": None,
        "cached_content": f"{key_label}: {val_txt}" if key_label else val_txt,
    }


def parse_leveldb_sstable(
    raw_bytes: bytes,
    schema_mode: str = "auto",
    *,
    budget_state: Dict[str, int] | None = None,
    collect_raw_ops: List[Dict[str, Any]] | None = None,
    source_name: str = "000001.ldb",
    sstable_level: int | None = None,
    is_orphan: bool = False,
) -> Dict[str, Any]:
    """
    Parse a single LevelDB `.ldb` / `.sst` SSTable file, verifying Footer magic, Index Block,
    per-block Castagnoli CRC32C trailers, Snappy decompression, and `InternalKey` tombstones.
    """
    if schema_mode not in VALID_SCHEMA_MODES:
        raise ValueError(f"Unsupported schema_mode={schema_mode!r}; expected one of {VALID_SCHEMA_MODES}")

    if budget_state is not None:
        active_budget = budget_state
        active_budget.setdefault("remaining", MAX_STORE_TOTAL_UNCOMPRESSED_BYTES)
        active_budget.setdefault("materialized_remaining", MAX_STORE_MATERIALIZED_BYTES)
        active_budget.setdefault("ops_remaining", MAX_STORE_RAW_OPS)
    else:
        active_budget = make_store_budget()
    total_len = len(raw_bytes)
    corrupted_blocks: List[Dict[str, Any]] = []
    corrupted_count = 0

    def add_corrupt(offset: int, reason: str) -> None:
        nonlocal corrupted_count
        corrupted_count += 1
        if len(corrupted_blocks) < MAX_CORRUPTED_RECORDS_REPORTED:
            corrupted_blocks.append({"byte_offset": offset, "reason": reason})

    if total_len < SSTABLE_FOOTER_SIZE:
        add_corrupt(0, f"File shorter than 48-byte LevelDB SSTable footer ({total_len} bytes)")
        return {
            "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
            "valid_sstable_footer": False,
            "file_size_bytes": total_len,
            "data_blocks_verified": 0,
            "snappy_blocks_decompressed": 0,
            "uncompressed_blocks_read": 0,
            "zstd_unsupported_blocks_count": 0,
            "corrupted_blocks_count": corrupted_count,
            "corrupted_blocks_truncated": False,
            "corrupted_blocks": corrupted_blocks,
            "value_entries_seen": 0,
            "tombstone_entries_seen": 0,
            "blink_v8_non_json_values_skipped": 0,
            "recovered_records_count": 0,
            "recovered_records": [],
        }

    footer_off = total_len - SSTABLE_FOOTER_SIZE
    footer = raw_bytes[footer_off:]
    if footer[40:48] != LEVELDB_SSTABLE_MAGIC_LE:
        add_corrupt(footer_off + 40, "Missing 8-byte LevelDB SSTable footer magic (0xdb4775248b80fb57)")
        return {
            "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
            "valid_sstable_footer": False,
            "file_size_bytes": total_len,
            "data_blocks_verified": 0,
            "snappy_blocks_decompressed": 0,
            "uncompressed_blocks_read": 0,
            "zstd_unsupported_blocks_count": 0,
            "corrupted_blocks_count": corrupted_count,
            "corrupted_blocks_truncated": False,
            "corrupted_blocks": corrupted_blocks,
            "value_entries_seen": 0,
            "tombstone_entries_seen": 0,
            "blink_v8_non_json_values_skipped": 0,
            "recovered_records_count": 0,
            "recovered_records": [],
        }

    try:
        p = 0
        meta_off, p = _decode_varint64_bounded(footer, p, 40)
        meta_size, p = _decode_varint64_bounded(footer, p, 40)
        idx_off, p = _decode_varint64_bounded(footer, p, 40)
        idx_size, p = _decode_varint64_bounded(footer, p, 40)
        if (
            meta_off + meta_size + BLOCK_TRAILER_SIZE > footer_off
            or idx_off + idx_size + BLOCK_TRAILER_SIZE > footer_off
        ):
            raise ValueError("Footer metaindex/index BlockHandle exceeds SSTable payload bounds")
    except ValueError as exc:
        add_corrupt(footer_off, f"Malformed SSTable footer BlockHandles: {exc}")
        return {
            "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
            "valid_sstable_footer": True,
            "file_size_bytes": total_len,
            "data_blocks_verified": 0,
            "snappy_blocks_decompressed": 0,
            "uncompressed_blocks_read": 0,
            "zstd_unsupported_blocks_count": 0,
            "corrupted_blocks_count": corrupted_count,
            "corrupted_blocks_truncated": False,
            "corrupted_blocks": corrupted_blocks,
            "value_entries_seen": 0,
            "tombstone_entries_seen": 0,
            "blink_v8_non_json_values_skipped": 0,
            "recovered_records_count": 0,
            "recovered_records": [],
        }

    raw_mv = memoryview(raw_bytes)
    zstd_blocks = 0
    idx_status, idx_bytes, idx_err = _read_and_verify_sstable_block(
        raw_mv,
        footer_off,
        idx_off,
        idx_size,
        active_budget,
    )
    if idx_status == "zstd_unsupported":
        zstd_blocks += 1
        return {
            "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
            "valid_sstable_footer": True,
            "file_size_bytes": total_len,
            "data_blocks_verified": 0,
            "snappy_blocks_decompressed": 0,
            "uncompressed_blocks_read": 0,
            "zstd_unsupported_blocks_count": zstd_blocks,
            "corrupted_blocks_count": corrupted_count,
            "corrupted_blocks_truncated": False,
            "corrupted_blocks": corrupted_blocks,
            "value_entries_seen": 0,
            "tombstone_entries_seen": 0,
            "blink_v8_non_json_values_skipped": 0,
            "recovered_records_count": 0,
            "recovered_records": [],
        }
    if idx_status != "ok":
        add_corrupt(idx_off, f"Index block verification failed: {idx_err}")
        return {
            "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
            "valid_sstable_footer": True,
            "file_size_bytes": total_len,
            "data_blocks_verified": 0,
            "snappy_blocks_decompressed": 0,
            "uncompressed_blocks_read": 0,
            "zstd_unsupported_blocks_count": zstd_blocks,
            "corrupted_blocks_count": corrupted_count,
            "corrupted_blocks_truncated": False,
            "corrupted_blocks": corrupted_blocks,
            "value_entries_seen": 0,
            "tombstone_entries_seen": 0,
            "blink_v8_non_json_values_skipped": 0,
            "recovered_records_count": 0,
            "recovered_records": [],
        }

    try:
        idx_entries = list(_iter_sstable_block_entries(idx_bytes, active_budget))
    except (ValueError, BufferError) as exc:
        add_corrupt(idx_off, f"Malformed SSTable Index Block structure: {exc}")
        idx_entries = []

    data_region_limit = min(meta_off, idx_off)
    min_next_data_off = 0
    last_handle: Tuple[int, int] | None = None
    data_blocks_ok = 0
    snappy_blocks = 0
    raw_blocks = 0
    val_entries_seen = 0
    tombstones_seen = 0
    v8_binary_skipped = 0
    recovered_records: List[Dict[str, Any]] = []
    standalone_ops: List[Dict[str, Any]] = []
    bad_index_handles = 0

    for _i_rel, _sep_key, handle_val in idx_entries:
        try:
            hp = 0
            d_off, hp = _decode_varint64_bounded(handle_val, hp, len(handle_val))
            d_size, hp = _decode_varint64_bounded(handle_val, hp, len(handle_val))
            if hp != len(handle_val):
                raise ValueError("Trailing unparsed bytes in Data BlockHandle")
        except ValueError as exc:
            add_corrupt(idx_off, f"Malformed Data BlockHandle in Index Block: {exc}")
            bad_index_handles += 1
            if bad_index_handles >= 2:
                break
            continue

        if last_handle == (d_off, d_size):
            continue
        if (
            d_off < min_next_data_off
            or d_size < 0
            or d_off + d_size + BLOCK_TRAILER_SIZE > data_region_limit
        ):
            add_corrupt(
                idx_off,
                f"Non-monotonic, overlapping, or out-of-data-region BlockHandle (offset={d_off}, size={d_size})",
            )
            break
        last_handle = (d_off, d_size)
        min_next_data_off = d_off + d_size + BLOCK_TRAILER_SIZE

        b_status, b_bytes, b_err = _read_and_verify_sstable_block(
            raw_mv,
            data_region_limit,
            d_off,
            d_size,
            active_budget,
        )
        if b_status == "zstd_unsupported":
            zstd_blocks += 1
            continue
        if b_status == "budget_exceeded":
            add_corrupt(d_off, b_err)
            break
        if b_status != "ok":
            add_corrupt(d_off, b_err)
            continue

        ctype = raw_bytes[d_off + d_size]
        data_blocks_ok += 1
        if ctype == COMPRESSION_SNAPPY:
            snappy_blocks += 1
        else:
            raw_blocks += 1

        budget_hit = False
        try:
            for _e_rel, ikey, val_bytes in _iter_sstable_block_entries(b_bytes, active_budget):
                try:
                    user_key, seq_num, val_type = unpack_internal_key(ikey)
                except ValueError as exc:
                    add_corrupt(d_off, str(exc))
                    continue

                if val_type == 0:
                    tombstones_seen += 1
                    op_rec = {
                        "user_key": user_key,
                        "seq_num": seq_num,
                        "op_type": 0,
                        "val_bytes": b"",
                        "source_kind": "orphan_sstable" if is_orphan else "sstable",
                        "source_name": source_name,
                        "byte_offset": d_off,
                        "sstable_level": sstable_level,
                    }
                    if collect_raw_ops is not None:
                        collect_raw_ops.append(op_rec)
                    else:
                        standalone_ops.append(op_rec)
                    continue

                if val_type != 1:
                    add_corrupt(d_off, f"Unsupported SSTable InternalKey value_type=0x{val_type:02x}")
                    continue

                val_entries_seen += 1
                op_val_rec = {
                    "user_key": user_key,
                    "seq_num": seq_num,
                    "op_type": 1,
                    "val_bytes": val_bytes,
                    "source_kind": "orphan_sstable" if is_orphan else "sstable",
                    "source_name": source_name,
                    "byte_offset": d_off,
                    "sstable_level": sstable_level,
                }
                if collect_raw_ops is not None:
                    collect_raw_ops.append(op_val_rec)
                else:
                    standalone_ops.append(op_val_rec)
        except BufferError as exc:
            add_corrupt(d_off, str(exc))
            budget_hit = True
        except ValueError as exc:
            add_corrupt(d_off, f"Malformed SSTable Data Block entries: {exc}")
        if budget_hit:
            break

    if collect_raw_ops is None and standalone_ops:
        by_key: Dict[bytes, List[Dict[str, Any]]] = {}
        for sop in standalone_ops:
            by_key.setdefault(sop["user_key"], []).append(sop)
        for ukey, k_ops in by_key.items():
            k_ops.sort(key=lambda x: (x["seq_num"], x["op_type"]), reverse=True)
            head = k_ops[0]
            head_is_tomb = head["op_type"] == 0
            key_hash = hashlib.sha256(ukey).hexdigest()
            for sop in k_ops:
                if sop["op_type"] != 1:
                    continue
                vbytes = sop["val_bytes"]
                carved_objs = _extract_json_objects_from_bytes(vbytes, schema_mode=schema_mode)
                norm_list: List[Tuple[Dict[str, Any], str]] = [
                    (normalize_carved_record_fields(obj, s_tag), s_tag) for obj, s_tag in carved_objs
                ]
                if not norm_list and schema_mode == "generic-json":
                    kv_rec = _extract_lightweight_kv_record(ukey, vbytes)
                    if kv_rec is not None:
                        norm_list.append((kv_rec, "localstorage_kv_text"))
                if not norm_list and (vbytes.startswith(b"\xff") or vbytes.startswith(b"\x00\xff")):
                    v8_binary_skipped += 1
                if not norm_list:
                    continue
                val_hash = hashlib.sha256(vbytes).hexdigest()
                is_live_entry = (not is_orphan) and (sop is head) and (not head_is_tomb)
                for norm, s_tag in norm_list:
                    del_ts = norm["deletetime"]
                    edit_ts = norm["edittime"]
                    recovered_records.append(
                        {
                            "epistemic_tier": "OBSERVED",
                            "schema_detected": s_tag,
                            "source_kind": "orphan_sstable" if is_orphan else "sstable",
                            "source_file": source_name,
                            "sstable_level": sstable_level,
                            "sstable_block_byte_offset": sop["byte_offset"],
                            "leveldb_sequence_number": sop["seq_num"],
                            "key_sha256": key_hash,
                            "value_sha256": val_hash,
                            "message_id": norm["message_id"],
                            "sender_mri": norm["sender_mri"],
                            "composetime": norm["composetime"],
                            "deletetime": del_ts,
                            "edittime": edit_ts,
                            "is_soft_deleted_in_ui": bool(del_ts),
                            "retention_state": (
                                ("UI_SOFT_DELETED" if del_ts else "LIVE_ACTIVE")
                                if is_live_entry
                                else "TOMBSTONED_HISTORICAL_RECOVERED"
                            ),
                            "superseded_by_sequence": None if is_live_entry or is_orphan else head["seq_num"],
                            "superseded_by_tombstone": False if is_live_entry else head_is_tomb,
                            "cached_content": norm["cached_content"],
                        }
                    )
        recovered_records.sort(key=lambda r: (r["leveldb_sequence_number"], r["sstable_block_byte_offset"]))

    return {
        "parser": f"leveldb_sstable_crc32c_snappy_v{__version__}",
        "valid_sstable_footer": True,
        "file_size_bytes": total_len,
        "data_blocks_verified": data_blocks_ok,
        "snappy_blocks_decompressed": snappy_blocks,
        "uncompressed_blocks_read": raw_blocks,
        "zstd_unsupported_blocks_count": zstd_blocks,
        "corrupted_blocks_count": corrupted_count,
        "corrupted_blocks_truncated": corrupted_count > MAX_CORRUPTED_RECORDS_REPORTED,
        "corrupted_blocks": corrupted_blocks,
        "value_entries_seen": val_entries_seen,
        "tombstone_entries_seen": tombstones_seen,
        "blink_v8_non_json_values_skipped": v8_binary_skipped,
        "recovered_records_count": len(recovered_records),
        "recovered_records": recovered_records,
    }


def _read_length_prefixed_slice(buf: bytes, pos: int) -> Tuple[bytes, int]:
    slen, pos = _decode_varint32(buf, pos, len(buf))
    if pos + slen > len(buf):
        raise ValueError("Truncated length-prefixed slice in VersionEdit")
    return buf[pos : pos + slen], pos + slen


def build_version_edit(
    *,
    comparator: str | None = None,
    log_number: int | None = None,
    next_file_number: int | None = None,
    last_sequence: int | None = None,
    new_files: List[Tuple[int, int, int, bytes, bytes]] | None = None,
    deleted_files: List[Tuple[int, int]] | None = None,
) -> bytes:
    """Encode a spec-compliant LevelDB `VersionEdit` record for `MANIFEST-*` fixtures & tests."""
    out = bytearray()
    if comparator is not None:
        comp_b = comparator.encode("utf-8")
        out.extend(encode_varint(_VE_COMPARATOR))
        out.extend(encode_varint(len(comp_b)))
        out.extend(comp_b)
    if log_number is not None:
        out.extend(encode_varint(_VE_LOG_NUMBER))
        out.extend(encode_varint(log_number))
    if next_file_number is not None:
        out.extend(encode_varint(_VE_NEXT_FILE_NUMBER))
        out.extend(encode_varint(next_file_number))
    if last_sequence is not None:
        out.extend(encode_varint(_VE_LAST_SEQUENCE))
        out.extend(encode_varint(last_sequence))
    for level, fnum in deleted_files or []:
        out.extend(encode_varint(_VE_DELETED_FILE))
        out.extend(encode_varint(level))
        out.extend(encode_varint(fnum))
    for level, fnum, fsize, smallest_ikey, largest_ikey in new_files or []:
        out.extend(encode_varint(_VE_NEW_FILE))
        out.extend(encode_varint(level))
        out.extend(encode_varint(fnum))
        out.extend(encode_varint(fsize))
        out.extend(encode_varint(len(smallest_ikey)))
        out.extend(smallest_ikey)
        out.extend(encode_varint(len(largest_ikey)))
        out.extend(largest_ikey)
    return bytes(out)


def parse_leveldb_manifest(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Replay all `VersionEdit` records in a LevelDB `MANIFEST-*` file sequentially across 32 KiB
    CRC32C blocks to reconstruct the active SSTable level map and evicted table history.
    """
    logical_recs, physical_ok, corrupted, corrupted_total = iter_leveldb_logical_records(raw_bytes)
    comparator_name: str | None = None
    log_number: int | None = None
    prev_log_number: int | None = None
    next_file_number: int | None = None
    last_sequence: int | None = None
    active_by_level_file: Dict[Tuple[int, int], int] = {}
    deleted_events = 0
    version_edits_applied = 0

    for rec_off, edit_bytes in logical_recs:
        pos = 0
        end = len(edit_bytes)
        staged_add: Dict[Tuple[int, int], int] = {}
        staged_del: Set[Tuple[int, int]] = set()
        loc_comp = comparator_name
        loc_log = log_number
        loc_prev_log = prev_log_number
        loc_next = next_file_number
        loc_seq = last_sequence
        loc_del_cnt = 0

        try:
            while pos < end:
                tag, pos = _decode_varint32(edit_bytes, pos, end)
                if tag == _VE_COMPARATOR:
                    comp_slice, pos = _read_length_prefixed_slice(edit_bytes, pos)
                    loc_comp = sanitize_utf8_str(comp_slice.decode("utf-8", errors="replace"))[:128]
                elif tag == _VE_LOG_NUMBER:
                    loc_log, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                elif tag == _VE_PREV_LOG_NUMBER:
                    loc_prev_log, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                elif tag == _VE_NEXT_FILE_NUMBER:
                    loc_next, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                elif tag == _VE_LAST_SEQUENCE:
                    loc_seq, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                elif tag == _VE_COMPACT_POINTER:
                    _lvl, pos = _decode_varint32(edit_bytes, pos, end)
                    _ikey, pos = _read_length_prefixed_slice(edit_bytes, pos)
                elif tag == _VE_DELETED_FILE:
                    lvl, pos = _decode_varint32(edit_bytes, pos, end)
                    fnum, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                    staged_del.add((lvl, fnum))
                    loc_del_cnt += 1
                elif tag == _VE_NEW_FILE:
                    lvl, pos = _decode_varint32(edit_bytes, pos, end)
                    fnum, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                    fsize, pos = _decode_varint64_bounded(edit_bytes, pos, end)
                    _sm, pos = _read_length_prefixed_slice(edit_bytes, pos)
                    _lg, pos = _read_length_prefixed_slice(edit_bytes, pos)
                    staged_add[(lvl, fnum)] = fsize
                else:
                    raise ValueError(f"Unknown VersionEdit tag {tag}")
        except ValueError as exc:
            corrupted_total += 1
            if len(corrupted) < MAX_CORRUPTED_RECORDS_REPORTED:
                corrupted.append({"byte_offset": rec_off, "reason": f"Malformed MANIFEST VersionEdit: {exc}"})
            break

        comparator_name = loc_comp
        log_number = loc_log
        prev_log_number = loc_prev_log
        next_file_number = loc_next
        last_sequence = loc_seq
        deleted_events += loc_del_cnt
        for dl in staged_del:
            active_by_level_file.pop(dl, None)
        for k_lf, sz in staged_add.items():
            active_by_level_file[k_lf] = sz
        version_edits_applied += 1

    file_to_level: Dict[int, int] = {}
    for (lvl, fnum), _sz in sorted(active_by_level_file.items()):
        file_to_level[fnum] = lvl

    return {
        "valid_physical_frames": physical_ok,
        "version_edits_applied": version_edits_applied,
        "comparator_name": comparator_name,
        "log_number": log_number,
        "prev_log_number": prev_log_number,
        "next_file_number": next_file_number,
        "last_sequence": last_sequence,
        "active_file_levels": file_to_level,
        "deleted_file_events_count": deleted_events,
        "corrupted_frames_count": corrupted_total,
        "corrupted_frames": corrupted,
    }


def _extract_wal_raw_ops(
    raw_bytes: bytes,
    source_name: str,
    *,
    source_kind: str = "wal_log",
    budget_state: Dict[str, int] | None = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Extract raw `(user_key, seq_num, op_type, val_bytes)` operations (incl. `0x00` tombstones) from a `.log` WAL."""
    logical_recs, _phys_ok, _corr, _corr_tot = iter_leveldb_logical_records(raw_bytes)
    ops: List[Dict[str, Any]] = []
    budget_exceeded = False

    # Process WAL batches newest-first so higher-sequence deletions are charged before older puts
    for logical_off, batch in reversed(logical_recs):
        if len(batch) < 12:
            continue
        seq_num, declared_count = struct.unpack_from("<QI", batch, 0)
        idx = 12
        parsed_ops = 0
        staged: List[Dict[str, Any]] = []
        staged_cost = 0
        try:
            while idx < len(batch) and parsed_ops < declared_count:
                op_type = batch[idx]
                idx += 1
                key_len, idx = decode_varint(batch, idx)
                if key_len > MAX_INTERNAL_KEY_BYTES:
                    raise ValueError("WAL key exceeds safety cap")
                if idx + key_len > len(batch):
                    raise ValueError("Truncated key")
                key_bytes = batch[idx : idx + key_len]
                idx += key_len
                if op_type == 1:
                    val_len, idx = decode_varint(batch, idx)
                    if idx + val_len > len(batch):
                        raise ValueError("Truncated value")
                    val_bytes = batch[idx : idx + val_len]
                    idx += val_len
                elif op_type == 0:
                    val_bytes = b""
                else:
                    raise ValueError("Unsupported op_type")
                staged_cost += len(key_bytes) + len(val_bytes) + PER_OP_OVERHEAD_BYTES
                if budget_state is not None:
                    cur_ops_rem = budget_state.get("ops_remaining", MAX_STORE_RAW_OPS)
                    cur_mat_rem = budget_state.get("materialized_remaining", MAX_STORE_MATERIALIZED_BYTES)
                    if parsed_ops + 1 > cur_ops_rem or staged_cost > cur_mat_rem:
                        budget_exceeded = True
                        break
                staged.append(
                    {
                        "user_key": key_bytes,
                        "seq_num": seq_num + parsed_ops,
                        "op_type": op_type,
                        "val_bytes": val_bytes,
                        "source_kind": source_kind,
                        "source_name": source_name,
                        "byte_offset": logical_off,
                        "sstable_level": None,
                    }
                )
                parsed_ops += 1
            if budget_exceeded:
                break
            if parsed_ops == declared_count and idx == len(batch):
                if budget_state is not None:
                    budget_state["ops_remaining"] = max(
                        0,
                        budget_state.get("ops_remaining", MAX_STORE_RAW_OPS) - parsed_ops,
                    )
                    budget_state["materialized_remaining"] = max(
                        0,
                        budget_state.get("materialized_remaining", MAX_STORE_MATERIALIZED_BYTES) - staged_cost,
                    )
                ops.extend(staged)
        except ValueError:
            continue
    return ops, budget_exceeded


def _parse_numeric_file_stem(name: str) -> int | None:
    stem = Path(name.rstrip(" .")).stem
    if stem.isdigit() and stem.isascii():
        return int(stem)
    return None


def parse_leveldb_store(
    target: Path,
    max_mb: int = 64,
    schema_mode: str = "auto",
    redact: bool = True,
) -> Dict[str, Any]:
    """
    Parse a Chromium/Electron LevelDB directory (`CURRENT` + `MANIFEST-*` + `*.ldb` + `*.log`) or
    standalone `.ldb`/`.sst` file, reconciling live values against `0x00` deletion tombstones and
    pre-overwrite SSTable history.
    """
    if max_mb < 1:
        raise SafeDiagnosticError("--max-mb safety limit must be >= 1 MiB")
    if schema_mode not in VALID_SCHEMA_MODES:
        raise SafeDiagnosticError(f"Unsupported schema_mode={schema_mode!r}")

    try:
        st = os.lstat(target)
    except OSError as exc:
        if redact:
            raise OSError("Unable to access target path (OS path suppressed in masked mode)") from None
        raise FileNotFoundError(f"Target path does not exist: {target}") from exc

    if stat.S_ISLNK(st.st_mode):
        if redact:
            raise OSError("Refusing symbolic-link target path (OS path suppressed in masked mode)")
        raise OSError(f"Target path is a symbolic link: {target}")

    store_buckets: Dict[Path, Dict[str, Any]] = {}

    def _bucket_for(dir_p: Path) -> Dict[str, Any]:
        b = store_buckets.get(dir_p)
        if b is None:
            b = {
                "ldb_files": [],
                "log_files": [],
                "forced_orphan_ldbs": [],
                "forced_orphan_logs": [],
                "manifest_files": [],
                "current_file": None,
            }
            store_buckets[dir_p] = b
        return b

    blob_entries = 0
    sqlite_entries = 0
    scanned_files = 0
    scan_truncated = False

    if stat.S_ISREG(st.st_mode):
        clean_name = target.name.rstrip(" .")
        suf = Path(clean_name).suffix.lower()
        b_single = _bucket_for(target.parent)
        if suf in (".ldb", ".sst"):
            b_single["ldb_files"].append(target)
        elif suf == ".log":
            b_single["log_files"].append(target)
        else:
            raise SafeDiagnosticError("Single-file target must be a .ldb, .sst, or .log regular file")
    elif stat.S_ISDIR(st.st_mode):
        target_is_blob = target.name.rstrip(" .").lower().endswith(".blob")
        for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
            dirnames.sort()
            filenames.sort()
            cur_dir = Path(dirpath)
            try:
                rel_parts = cur_dir.relative_to(target).parts
            except ValueError:
                rel_parts = ()
            in_blob = target_is_blob or any(pt.rstrip(" .").lower().endswith(".blob") for pt in rel_parts)

            for fname in filenames:
                if scanned_files >= MAX_PRECHECK_SCAN_FILES:
                    scan_truncated = True
                    dirnames[:] = []
                    break
                p = cur_dir / fname
                try:
                    pst = os.lstat(p)
                except OSError:
                    continue
                scanned_files += 1
                if not stat.S_ISREG(pst.st_mode):
                    continue
                clean_fname = fname.rstrip(" .")
                suf = Path(clean_fname).suffix.lower()
                low_name = clean_fname.lower()
                if in_blob or suf == ".blob":
                    blob_entries += 1
                elif clean_fname.upper() == "CURRENT":
                    _bucket_for(cur_dir)["current_file"] = p
                elif m_man := _MANIFEST_NAME_RE.match(clean_fname):
                    _bucket_for(cur_dir)["manifest_files"].append((int(m_man.group(1)), p))
                elif suf in (".ldb", ".sst"):
                    if cur_dir != target and cur_dir.name.rstrip(" .").lower() == "lost":
                        _bucket_for(cur_dir.parent)["forced_orphan_ldbs"].append(p)
                    else:
                        _bucket_for(cur_dir)["ldb_files"].append(p)
                elif suf == ".log":
                    if cur_dir != target and cur_dir.name.rstrip(" .").lower() == "lost":
                        _bucket_for(cur_dir.parent)["forced_orphan_logs"].append(p)
                    else:
                        _bucket_for(cur_dir)["log_files"].append(p)
                elif low_name.endswith((".sqlite", ".sqlite3", "-wal", "-shm")) or _has_sqlite3_magic(p):
                    sqlite_entries += 1
            if scan_truncated:
                break

            for dname in list(dirnames):
                if dname.rstrip(" .").lower().endswith(".blob"):
                    blob_entries += 1
                if scanned_files >= MAX_PRECHECK_SCAN_FILES:
                    scan_truncated = True
                    dirnames[:] = []
                    break
                scanned_files += 1
            if scan_truncated:
                break
    else:
        if redact:
            raise OSError("Target path must be a regular file or directory (OS path suppressed in masked mode)")
        raise OSError(f"Target path is neither a regular file nor a directory: {target}")

    budget_state = make_store_budget()
    corrupted_items: List[Dict[str, Any]] = []
    corrupted_total = 0
    sstable_blocks_verified = 0
    snappy_blocks_decompressed = 0
    zstd_unsupported_blocks = 0
    v8_binary_skipped = 0
    active_sstables_parsed = 0
    orphan_sstables_parsed = 0
    wal_logs_parsed = 0
    tombstones_total = 0
    reconciled_records: List[Dict[str, Any]] = []
    live_count = 0
    ui_soft_deleted_count = 0
    tombstoned_recovered_count = 0

    any_manifest_present = False
    manifest_comparators_seen: List[str] = []
    total_version_edits = 0
    total_deleted_events = 0

    # Fold MANIFEST-less child buckets nested beneath a MANIFEST-bearing ancestor store into that ancestor as orphans
    for cand_dir in sorted(list(store_buckets.keys()), key=lambda sp: len(sp.parts), reverse=True):
        cb = store_buckets[cand_dir]
        if cb["current_file"] is not None or cb["manifest_files"]:
            continue
        anc = cand_dir.parent
        merged_into_anc = False
        while anc in store_buckets or (anc != anc.parent and str(anc).startswith(str(target))):
            ab = store_buckets.get(anc)
            if ab is not None and (ab["current_file"] is not None or ab["manifest_files"]):
                ab["forced_orphan_ldbs"].extend(cb["ldb_files"])
                ab["forced_orphan_ldbs"].extend(cb["forced_orphan_ldbs"])
                ab["forced_orphan_logs"].extend(cb["log_files"])
                ab["forced_orphan_logs"].extend(cb["forced_orphan_logs"])
                del store_buckets[cand_dir]
                merged_into_anc = True
                break
            if anc == target or anc == anc.parent:
                break
            anc = anc.parent
        if merged_into_anc:
            continue

    for store_dir in sorted(store_buckets.keys(), key=lambda sp: str(sp)):
        bucket = store_buckets[store_dir]
        b_current: Path | None = bucket["current_file"]
        b_manifests: List[Tuple[int, Path]] = bucket["manifest_files"]
        b_logs: List[Tuple[Path, bool]] = [(p, False) for p in bucket["log_files"]] + [
            (p, True) for p in bucket["forced_orphan_logs"]
        ]
        b_ldbs_raw: List[Tuple[Path, bool]] = [(p, False) for p in bucket["ldb_files"]] + [
            (p, True) for p in bucket["forced_orphan_ldbs"]
        ]

        manifest_summary: Dict[str, Any] | None = None
        active_levels: Dict[int, int] = {}
        selected_manifest: Path | None = None
        manifest_expected = b_current is not None or bool(b_manifests)
        manifest_unreliable = False

        if b_current is not None:
            try:
                cur_txt = read_bounded_bytes(b_current, max_mb=1, redact=redact).decode("utf-8", errors="ignore").strip()
                for _m_num, mp in b_manifests:
                    if mp.name == cur_txt:
                        selected_manifest = mp
                        break
                if selected_manifest is None:
                    manifest_unreliable = True
                    corrupted_total += 1
                    if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                        corrupted_items.append(
                            {
                                "byte_offset": 0,
                                "reason": "CURRENT pointer references missing or unrecognized MANIFEST file",
                                "source_file": "[REDACTED_MANIFEST_FILE]" if redact else b_current.name,
                            }
                        )
            except (OSError, ValueError):
                manifest_unreliable = True
                corrupted_total += 1
                if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                    corrupted_items.append(
                        {
                            "byte_offset": 0,
                            "reason": "Unable to read CURRENT pointer within safety bounds",
                            "source_file": "[REDACTED_MANIFEST_FILE]" if redact else b_current.name,
                        }
                    )
        elif b_manifests:
            b_manifests.sort(key=lambda x: x[0])
            selected_manifest = b_manifests[-1][1]

        if selected_manifest is not None:
            try:
                man_bytes = read_bounded_bytes(selected_manifest, max_mb=max_mb, redact=redact)
                manifest_summary = parse_leveldb_manifest(man_bytes)
                corrupted_total += manifest_summary["corrupted_frames_count"]
                for m_corr in manifest_summary["corrupted_frames"]:
                    if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                        mc_copy = dict(m_corr)
                        mc_copy["source_file"] = "[REDACTED_MANIFEST_FILE]" if redact else selected_manifest.name
                        corrupted_items.append(mc_copy)
                if manifest_summary["version_edits_applied"] == 0:
                    manifest_unreliable = True
                else:
                    active_levels = dict(manifest_summary["active_file_levels"])
            except (OSError, ValueError):
                manifest_summary = None
                manifest_unreliable = True
                corrupted_total += 1
                if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                    corrupted_items.append(
                        {
                            "byte_offset": 0,
                            "reason": "Unable to read or verify MANIFEST file within safety bounds",
                            "source_file": "[REDACTED_MANIFEST_FILE]" if redact else selected_manifest.name,
                        }
                    )

        if manifest_expected:
            any_manifest_present = True
        if manifest_summary is not None:
            total_version_edits += manifest_summary["version_edits_applied"]
            total_deleted_events += manifest_summary["deleted_file_events_count"]
            if manifest_summary["comparator_name"] is not None:
                manifest_comparators_seen.append(manifest_summary["comparator_name"])

        has_manifest = manifest_expected
        man_log_num = (
            manifest_summary["log_number"]
            if (manifest_summary is not None and not manifest_unreliable)
            else None
        )
        man_prev_log_num = (
            manifest_summary["prev_log_number"]
            if (manifest_summary is not None and not manifest_unreliable)
            else None
        )

        raw_ops: List[Dict[str, Any]] = []

        active_wals: List[Path] = []
        stale_wals: List[Path] = []
        for lf, forced_orph_log in b_logs:
            lf_num = _parse_numeric_file_stem(lf.name)
            is_stale_wal = (
                forced_orph_log
                or manifest_unreliable
                or (
                    has_manifest
                    and man_log_num is not None
                    and lf_num is not None
                    and lf_num < man_log_num
                    and lf_num != man_prev_log_num
                )
            )
            if is_stale_wal:
                stale_wals.append(lf)
            else:
                active_wals.append(lf)

        # Newest active WAL first so newest tombstones/values win budget before older frames
        active_wals.sort(key=lambda p: (_parse_numeric_file_stem(p.name) or -1, p.name), reverse=True)
        stale_wals.sort(key=lambda p: (_parse_numeric_file_stem(p.name) or -1, p.name), reverse=True)

        active_ldbs: List[Tuple[Path, int | None]] = []
        orphan_ldbs: List[Path] = []
        for sf, forced_orph_ldb in b_ldbs_raw:
            fnum = _parse_numeric_file_stem(sf.name)
            if (
                not forced_orph_ldb
                and not manifest_unreliable
                and has_manifest
                and fnum is not None
                and fnum in active_levels
            ):
                active_ldbs.append((sf, active_levels[fnum]))
            elif forced_orph_ldb or has_manifest:
                orphan_ldbs.append(sf)
            else:
                active_ldbs.append((sf, None))

        # Newest SSTables (Level 0 / highest file number) first so newest tombstones win budget first
        active_ldbs.sort(
            key=lambda item: (
                item[1] if item[1] is not None else -1,
                -(_parse_numeric_file_stem(item[0].name) or -1),
                item[0].name,
            )
        )
        orphan_ldbs.sort(key=lambda p: (_parse_numeric_file_stem(p.name) or -1, p.name), reverse=True)

        active_liveness_truncated = False

        def _ingest_wal_list(
            wal_paths: List[Path], kind: str, out_ops: List[Dict[str, Any]], is_active_tier: bool
        ) -> None:
            nonlocal wal_logs_parsed, corrupted_total, active_liveness_truncated
            for lf in wal_paths:
                try:
                    lbytes = read_bounded_bytes(lf, max_mb=max_mb, redact=redact)
                except (OSError, ValueError):
                    continue
                wal_logs_parsed += 1
                _lrecs, _pok, lcorr, lcorr_tot = iter_leveldb_logical_records(lbytes)
                corrupted_total += lcorr_tot
                for c_it in lcorr:
                    if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                        c_copy = dict(c_it)
                        c_copy["source_file"] = "[REDACTED_LOG_FILE]" if redact else lf.name
                        corrupted_items.append(c_copy)
                wal_ops, wal_budget_hit = _extract_wal_raw_ops(
                    lbytes,
                    lf.name,
                    source_kind=kind,
                    budget_state=budget_state,
                )
                out_ops.extend(wal_ops)
                if wal_budget_hit:
                    if is_active_tier:
                        active_liveness_truncated = True
                    corrupted_total += 1
                    if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                        corrupted_items.append(
                            {
                                "byte_offset": 0,
                                "reason": "Cumulative LevelDB operation/materialized safety budget exceeded in WAL",
                                "source_file": "[REDACTED_LOG_FILE]" if redact else lf.name,
                            }
                        )
                    break

        def _ingest_sstable_item(
            sf: Path, lvl: int | None, is_orph: bool, out_ops: List[Dict[str, Any]]
        ) -> None:
            nonlocal active_sstables_parsed, orphan_sstables_parsed, active_liveness_truncated
            nonlocal sstable_blocks_verified, snappy_blocks_decompressed, zstd_unsupported_blocks, corrupted_total
            try:
                sbytes = read_bounded_bytes(sf, max_mb=max_mb, redact=redact)
            except (OSError, ValueError):
                return
            if is_orph:
                orphan_sstables_parsed += 1
            else:
                active_sstables_parsed += 1
            s_res = parse_leveldb_sstable(
                sbytes,
                schema_mode=schema_mode,
                budget_state=budget_state,
                collect_raw_ops=out_ops,
                source_name=sf.name,
                sstable_level=lvl,
                is_orphan=is_orph,
            )
            sstable_blocks_verified += s_res["data_blocks_verified"]
            snappy_blocks_decompressed += s_res["snappy_blocks_decompressed"]
            zstd_unsupported_blocks += s_res["zstd_unsupported_blocks_count"]
            corrupted_total += s_res["corrupted_blocks_count"]
            if not is_orph and any("safety budget" in str(c.get("reason", "")) for c in s_res["corrupted_blocks"]):
                active_liveness_truncated = True
            for c_blk in s_res["corrupted_blocks"]:
                if len(corrupted_items) < MAX_CORRUPTED_RECORDS_REPORTED:
                    c_copy = dict(c_blk)
                    c_copy["source_file"] = "[REDACTED_SSTABLE_FILE]" if redact else sf.name
                    corrupted_items.append(c_copy)

        # Strict 4-tier ingestion priority: Active WALs -> Active SSTables -> Stale WALs -> Orphan SSTables
        _ingest_wal_list(active_wals, "wal_log", raw_ops, True)
        for sf_act, lvl_act in active_ldbs:
            _ingest_sstable_item(sf_act, lvl_act, False, raw_ops)
        _ingest_wal_list(stale_wals, "orphan_wal_log", raw_ops, False)
        for sf_orph in orphan_ldbs:
            _ingest_sstable_item(sf_orph, None, True, raw_ops)

        # Reconcile keys strictly within `store_dir` so independent sub-stores never mix key spaces
        ops_by_key: Dict[bytes, List[Dict[str, Any]]] = {}
        for op in raw_ops:
            if op["op_type"] == 0:
                tombstones_total += 1
            ops_by_key.setdefault(op["user_key"], []).append(op)

        for ukey, key_ops in ops_by_key.items():
            key_ops.sort(
                key=lambda x: (
                    x["seq_num"],
                    x["op_type"],
                    _SOURCE_RANK.get(x["source_kind"], 0),
                    _parse_numeric_file_stem(x["source_name"]) or -1,
                ),
                reverse=True,
            )
            active_key_ops = (
                [x for x in key_ops if x["source_kind"] not in ("orphan_sstable", "orphan_wal_log")]
                if has_manifest
                else key_ops
            )
            newest_overall = key_ops[0]
            active_head = active_key_ops[0] if active_key_ops else None
            effective_is_tombstone = (
                active_head["op_type"] == 0 if active_head is not None else newest_overall["op_type"] == 0
            )
            sup_ref_seq = active_head["seq_num"] if active_head is not None else newest_overall["seq_num"]
            live_val_hash = (
                hashlib.sha256(active_head["val_bytes"]).hexdigest()
                if (active_head is not None and active_head["op_type"] == 1 and not effective_is_tombstone)
                else ""
            )
            key_hash = hashlib.sha256(ukey).hexdigest()

            seen_val_hashes_for_key: Set[Tuple[str, bool]] = set()
            for op in key_ops:
                if op["op_type"] != 1:
                    continue
                val_bytes = op["val_bytes"]
                val_hash = hashlib.sha256(val_bytes).hexdigest()
                is_live_head = (
                    active_head is not None
                    and op is active_head
                    and not effective_is_tombstone
                    and not active_liveness_truncated
                )
                is_evicted_orphan_only = (has_manifest and active_head is None) or (
                    op["source_kind"] in ("orphan_sstable", "orphan_wal_log") and active_head is None
                )

                # Deduplicate compacted/orphan mirrors of the same value unless retention differs
                dedup_sig = (val_hash, is_live_head)
                if dedup_sig in seen_val_hashes_for_key:
                    continue
                if not is_live_head and live_val_hash and val_hash == live_val_hash:
                    continue
                seen_val_hashes_for_key.add(dedup_sig)

                carved_objs = _extract_json_objects_from_bytes(val_bytes, schema_mode=schema_mode)
                norm_items: List[Tuple[Dict[str, Any], str]] = [
                    (normalize_carved_record_fields(obj, s_tag), s_tag) for obj, s_tag in carved_objs
                ]
                if not norm_items and schema_mode == "generic-json":
                    kv_rec = _extract_lightweight_kv_record(ukey, val_bytes)
                    if kv_rec is not None:
                        norm_items.append((kv_rec, "localstorage_kv_text"))

                if not norm_items and (val_bytes.startswith(b"\xff") or val_bytes.startswith(b"\x00\xff")):
                    v8_binary_skipped += 1

                for norm, s_tag in norm_items:
                    del_ts = norm["deletetime"]
                    edit_ts = norm["edittime"]
                    if not is_live_head:
                        ret_state = "TOMBSTONED_HISTORICAL_RECOVERED"
                        sup_seq: int | None = (
                            None
                            if (is_evicted_orphan_only or op["seq_num"] > sup_ref_seq)
                            else sup_ref_seq
                        )
                        sup_tomb = effective_is_tombstone
                        tombstoned_recovered_count += 1
                    elif del_ts:
                        ret_state = "UI_SOFT_DELETED"
                        sup_seq = None
                        sup_tomb = False
                        ui_soft_deleted_count += 1
                    else:
                        ret_state = "LIVE_ACTIVE"
                        sup_seq = None
                        sup_tomb = False
                        live_count += 1

                    reconciled_records.append(
                        {
                            "epistemic_tier": "OBSERVED",
                            "schema_detected": s_tag,
                            "source_kind": op["source_kind"],
                            "source_file": "[REDACTED_SOURCE_FILE]" if redact else op["source_name"],
                            "sstable_level": op["sstable_level"],
                            "byte_offset": op["byte_offset"],
                            "leveldb_sequence_number": op["seq_num"],
                            "key_sha256": key_hash,
                            "value_sha256": val_hash,
                            "message_id": norm["message_id"],
                            "sender_mri": norm["sender_mri"],
                            "composetime": norm["composetime"],
                            "deletetime": del_ts,
                            "edittime": edit_ts,
                            "is_soft_deleted_in_ui": bool(del_ts),
                            "retention_state": ret_state,
                            "evicted_from_manifest": is_evicted_orphan_only,
                            "superseded_by_sequence": sup_seq,
                            "superseded_by_tombstone": sup_tomb,
                            "cached_content": norm["cached_content"],
                        }
                    )

    reconciled_records.sort(key=lambda r: (r["leveldb_sequence_number"], r["byte_offset"]))

    blob_warning = (
        "External IndexedDB .blob directory/entries detected alongside LevelDB tables; oversized "
        "externalized values live outside .ldb SSTables and are not reconstructed by this parser."
        if blob_entries > 0
        else None
    )

    raw_comp: str | None = None
    if manifest_comparators_seen:
        uniq_comps = list(dict.fromkeys(manifest_comparators_seen))
        if redact:
            safe_comps = [
                c if c in KNOWN_SAFE_MANIFEST_COMPARATORS else "[REDACTED_CUSTOM_COMPARATOR]"
                for c in uniq_comps
            ]
            raw_comp = safe_comps[0] if len(set(safe_comps)) == 1 else ",".join(dict.fromkeys(safe_comps))
        else:
            raw_comp = uniq_comps[0] if len(uniq_comps) == 1 else ",".join(uniq_comps)

    return {
        "parser": f"leveldb_store_reconciler_v{__version__}",
        "target_label": "[REDACTED_TARGET_PATH]" if redact else str(target),
        "schema_mode": schema_mode,
        "scan_capped_at_max_files": scan_truncated,
        "leveldb_stores_reconciled": len(store_buckets),
        "manifest_present": any_manifest_present,
        "manifest_comparator": raw_comp,
        "manifest_version_edits_applied": total_version_edits,
        "manifest_deleted_file_events": total_deleted_events,
        "wal_logs_parsed": wal_logs_parsed,
        "active_sstables_parsed": active_sstables_parsed,
        "orphan_sstables_parsed": orphan_sstables_parsed,
        "sstable_data_blocks_verified": sstable_blocks_verified,
        "snappy_blocks_decompressed": snappy_blocks_decompressed,
        "zstd_unsupported_blocks_count": zstd_unsupported_blocks,
        "blink_v8_non_json_values_skipped": v8_binary_skipped,
        "indexeddb_blob_entries_detected": blob_entries,
        "sqlite_co_located_files_detected": sqlite_entries,
        "external_blob_warning": blob_warning,
        "tombstone_markers_seen": tombstones_total,
        "corrupted_blocks_or_frames_count": corrupted_total,
        "corrupted_blocks_or_frames_truncated": corrupted_total > MAX_CORRUPTED_RECORDS_REPORTED,
        "corrupted_blocks_or_frames": corrupted_items,
        "recovered_records_count": len(reconciled_records),
        "live_active_records_count": live_count,
        "ui_soft_deleted_records_count": ui_soft_deleted_count,
        "tombstoned_historical_recovered_count": tombstoned_recovered_count,
        "recovered_records": reconciled_records,
    }
