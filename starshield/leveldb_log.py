#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google LevelDB Write-Ahead Log (`.log`) Binary Frame, Multi-Schema JSON Carver
& Local Storage Precheck Gate for Chromium IndexedDB / Web Application Caches.

Implements the official LevelDB log format specification:
- 32,768-byte (32 KiB) physical block boundaries with strict zero-padding trailer checks
- 7-byte record header: [masked_crc32c: uint32_le][length: uint16_le][type: uint8]
  where type in {1: FULL, 2: FIRST, 3: MIDDLE, 4: LAST}
- Castagnoli CRC32C (polynomial 0x82F63B78) + LevelDB mask delta 0xA282EAD8
- Strict LevelDB WriteBatch validation: [sequence: uint64_le][count: uint32_le] followed
  by varint-prefixed kTypeValue (0x01) and kTypeDeletion (0x00) entries, rejecting
  truncated payloads, op-count mismatches, trailing garbage bytes, and unclosed EOF fragments.
- Top-level `json.JSONDecoder.raw_decode` scanning across `chatsvc` (Teams/Skype), Slack Web,
  WhatsApp/Web Messenger, and B2B supplier/invoice portal JSON schemas (`--schema auto`).
- Offline `inspect_chromium_storage_path` feasibility precheck (`GO` / `PARTIAL` /
  `NO_GO_COMPACTED_OR_UNSUPPORTED`) detecting `.ldb` SSTable footers (`0xdb4775248b80fb57`),
  IndexedDB `.blob` directories, and Blink V8 `0xFF` headers with zero PII leakage.

Scope & Honest Limitations:
- Targets uncompressed LevelDB `.log` write-ahead logs and embedded UTF-8/UTF-16LE JSON
  slices inside Chromium IndexedDB / Local Storage WriteBatch values.
- Does NOT decompress Snappy-compressed `.ldb` SSTable data blocks or decode binary-only
  Blink V8 StructuredClone primitives (scheduled for v0.4).
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

BLOCK_SIZE = 32768
HEADER_SIZE = 7
MAX_LOGICAL_RECORD_BYTES = 32 * 1024 * 1024  # 32 MiB anti-DoS cap per reassembled batch
LEVELDB_SSTABLE_MAGIC_LE = struct.pack("<Q", 0xDB4775248B80FB57)

REC_ZERO = 0
REC_FULL = 1
REC_FIRST = 2
REC_MIDDLE = 3
REC_LAST = 4

MASK_DELTA = 0xA282EAD8

VALID_SCHEMA_MODES = ("auto", "chatsvc", "generic-json")

_PORTAL_ID_KEYS = (
    "id",
    "message_id",
    "msg_id",
    "client_msg_id",
    "invoice_id",
    "payment_id",
    "tx_id",
    "transaction_id",
    "reference",
    "uuid",
    "record_id",
    "event_id",
    "order_id",
)

_PORTAL_CONTENT_KEYS = (
    "content",
    "text",
    "body",
    "message",
    "memo",
    "note",
    "description",
    "payment_instructions",
    "iban",
    "beneficiary_iban",
    "account_number",
    "sort_code",
    "beneficiary",
    "payee",
    "amount",
)


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
    """Ensure carved JSON object is a top-level chatsvc message record, not a non-chatsvc messenger or inner sub-dict."""
    if not isinstance(obj, dict):
        return False
    msg_id = obj.get("id")
    if msg_id is None or str(msg_id).strip() == "":
        return False
    if any(k in obj for k in ("content", "composetime", "messagetype", "conversationid")):
        return True
    if "from" in obj and not any(k in obj for k in ("body", "text", "t", "ts")):
        return True
    return False


def classify_carved_json_object(obj: Any, schema_mode: str = "auto") -> str | None:
    """
    Classify a top-level JSON dictionary under the requested `schema_mode`
    (`auto`, `chatsvc`, or `generic-json`). Returns schema tag or None if filtered out.
    """
    if schema_mode not in VALID_SCHEMA_MODES:
        raise ValueError(f"Unsupported schema_mode={schema_mode!r}; expected one of {VALID_SCHEMA_MODES}")
    if not isinstance(obj, dict) or not obj:
        return None

    if _is_valid_chatsvc_message_obj(obj):
        return "chatsvc"

    if schema_mode == "chatsvc":
        return None

    lower_keys = {str(k).lower() for k in obj.keys()}

    # Slack Web / Electron IndexedDB & Redux cache shape
    if ("ts" in lower_keys or "client_msg_id" in lower_keys) and (
        lower_keys & {"text", "user", "blocks", "subtype", "deleted_ts", "channel"}
    ):
        return "slack_web"

    # WhatsApp Web / Signal / Generic Web Messenger shape
    if (lower_keys & {"id", "msg_id", "t", "timestamp"}) and (
        lower_keys & {"body", "text", "message", "author", "from", "sender", "ack"}
    ):
        return "web_messenger"

    # B2B supplier, ERP, or banking invoice/payment portal shape
    if (lower_keys & set(_PORTAL_ID_KEYS)) and (lower_keys & set(_PORTAL_CONTENT_KEYS)):
        return "b2b_portal_json"

    if schema_mode == "generic-json":
        return "generic_json"

    return None


def _collect_string_scalars(node: Any, cap: int = 64) -> List[str]:
    """Deterministically collect bounded string/number leaves for generic-json IOC & content normalization."""
    acc: List[str] = []

    def _walk(cur: Any) -> None:
        if len(acc) >= cap or cur is None or isinstance(cur, bool):
            return
        if isinstance(cur, str):
            s = cur.strip()
            if s:
                acc.append(s)
        elif isinstance(cur, (int, float)):
            acc.append(str(cur))
        elif isinstance(cur, dict):
            for k in sorted(cur.keys(), key=str):
                kl = str(k).lower()
                if kl in ("blob_pad", "avatar", "thumbnail", "raw_html"):
                    continue
                v = cur[k]
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    vs = str(v).strip()
                    if vs:
                        acc.append(f"{k}: {vs}")
                        if len(acc) >= cap:
                            return
                else:
                    _walk(v)
        elif isinstance(cur, list):
            for item in cur:
                _walk(item)

    _walk(node)
    return acc


def normalize_carved_record_fields(obj: Dict[str, Any], schema_tag: str) -> Dict[str, Any]:
    """Map multi-platform web cache JSON fields onto StarShield's canonical record layout."""
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {}
    edited_sub = obj.get("edited") if isinstance(obj.get("edited"), dict) else {}

    msg_id = ""
    for k in _PORTAL_ID_KEYS + ("ts", "t"):
        v = obj.get(k)
        if v is not None and str(v).strip() != "":
            msg_id = str(v).strip()
            break

    sender = ""
    for k in ("from", "user", "sender", "author", "actor", "vendor", "supplier", "beneficiary"):
        v = obj.get(k)
        if v is not None and str(v).strip() != "":
            sender = str(v).strip()
            break

    compose_ts = None
    for k in ("composetime", "ts", "t", "timestamp", "created_at", "issued_at", "date"):
        if obj.get(k) not in (None, ""):
            compose_ts = obj.get(k)
            break

    del_ts = (
        props.get("deletetime")
        or obj.get("deletetime")
        or obj.get("deleted_ts")
        or obj.get("deleted_at")
        or obj.get("retracted_at")
        or ("true" if obj.get("subtype") == "message_deleted" or obj.get("is_deleted") is True else None)
    )
    edit_ts = (
        props.get("edittime")
        or obj.get("edittime")
        or edited_sub.get("ts")
        or obj.get("edited_at")
        or obj.get("updated_at")
    )

    if schema_tag == "chatsvc":
        content_str = str(obj.get("content", ""))
    else:
        primary_parts: List[str] = []
        for k in ("content", "text", "body", "message", "payment_instructions", "memo", "note", "description"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                primary_parts.append(v.strip())
        # Append structured banking/routing fields if present outside free-text body
        for k in ("beneficiary", "payee", "iban", "beneficiary_iban", "sort_code", "account_number", "swift", "bic", "amount"):
            v = obj.get(k)
            if v is not None and str(v).strip():
                primary_parts.append(f"{k}={str(v).strip()}")
        if primary_parts:
            content_str = " | ".join(primary_parts)
        else:
            content_str = " | ".join(_collect_string_scalars(obj))

    return {
        "message_id": msg_id,
        "sender_mri": sender,
        "composetime": compose_ts,
        "deletetime": del_ts,
        "edittime": edit_ts,
        "cached_content": content_str,
    }


def _extract_json_objects_from_bytes(
    raw_val: bytes,
    schema_mode: str = "auto",
) -> List[Tuple[Dict[str, Any], str]]:
    """
    Scan UTF-8 (and UTF-16LE if NUL bytes exist) using `json.JSONDecoder.raw_decode`.
    Advances past the full span of each decoded top-level JSON object so nested child
    objects (e.g., `properties: {deletetime: ...}`) are NEVER mis-carved as standalone records.
    """
    candidates: List[str] = [raw_val.decode("utf-8", errors="ignore")]
    if b"\x00" in raw_val:
        candidates.append(raw_val.decode("utf-16-le", errors="ignore"))

    decoder = json.JSONDecoder()
    found: List[Tuple[Dict[str, Any], str]] = []
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
            schema_tag = classify_carved_json_object(obj, schema_mode=schema_mode)
            if schema_tag is not None:
                canonical = json.dumps(obj, sort_keys=True, ensure_ascii=False)
                h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    found.append((obj, schema_tag))

    return found


def parse_leveldb_wal(raw_bytes: bytes, schema_mode: str = "auto") -> Dict[str, Any]:
    """Parse a Chromium LevelDB `.log` file, verifying CRC32C, WriteBatch bounds, and EOF completeness."""
    if schema_mode not in VALID_SCHEMA_MODES:
        raise ValueError(f"Unsupported schema_mode={schema_mode!r}; expected one of {VALID_SCHEMA_MODES}")

    total_len = len(raw_bytes)
    physical_records_ok = 0
    corrupted_records: List[Dict[str, Any]] = []
    recovered_entries: List[Dict[str, Any]] = []
    stats: Dict[str, int] = {"value_ops_total": 0, "blink_v8_binary_only_values": 0}

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

            _decode_writebatch_into(
                logical_bytes,
                logical_offset,
                recovered_entries,
                corrupted_records,
                schema_mode=schema_mode,
                stats=stats,
            )

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

    chatsvc_count = sum(1 for r in recovered_entries if r.get("schema_detected") == "chatsvc")
    return {
        "parser": "leveldb_wal_32k_crc32c_v0.3.6",
        "schema_mode": schema_mode,
        "file_size_bytes": total_len,
        "valid_physical_frames": physical_records_ok,
        "writebatch_value_ops_seen": stats["value_ops_total"],
        "blink_v8_non_json_values_skipped": stats["blink_v8_binary_only_values"],
        "corrupted_frames_count": len(corrupted_records),
        "corrupted_frames": corrupted_records,
        "recovered_records_count": len(recovered_entries),
        "recovered_chatsvc_records_count": chatsvc_count if schema_mode == "chatsvc" else len(recovered_entries),
        "recovered_records": recovered_entries,
    }


def _decode_writebatch_into(
    batch: bytes,
    logical_offset: int,
    out_entries: List[Dict[str, Any]],
    corrupted: List[Dict[str, Any]],
    schema_mode: str = "auto",
    stats: Dict[str, int] | None = None,
) -> None:
    if len(batch) < 12:
        corrupted.append({"byte_offset": logical_offset, "reason": "WriteBatch shorter than 12-byte header"})
        return

    seq_num, declared_count = struct.unpack_from("<QI", batch, 0)
    idx = 12
    parsed_ops = 0
    staged_entries: List[Dict[str, Any]] = []
    local_value_ops = 0
    local_v8_binary_only = 0

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
                local_value_ops += 1

                carved_objs = _extract_json_objects_from_bytes(val_bytes, schema_mode=schema_mode)
                if not carved_objs and b"\xff" in val_bytes[:8]:
                    local_v8_binary_only += 1

                for obj, schema_tag in carved_objs:
                    norm = normalize_carved_record_fields(obj, schema_tag)
                    del_ts = norm["deletetime"]
                    edit_ts = norm["edittime"]
                    staged_entries.append(
                        {
                            "epistemic_tier": "OBSERVED",
                            "schema_detected": schema_tag,
                            "leveldb_batch_byte_offset": logical_offset,
                            "leveldb_sequence_number": seq_num,
                            "key_sha256": hashlib.sha256(key_bytes).hexdigest(),
                            "value_sha256": hashlib.sha256(val_bytes).hexdigest(),
                            "message_id": norm["message_id"],
                            "sender_mri": norm["sender_mri"],
                            "composetime": norm["composetime"],
                            "deletetime": del_ts,
                            "edittime": edit_ts,
                            "is_soft_deleted_in_ui": bool(del_ts),
                            "note_on_edittime": (
                                "Present value reflects post-edit state unless an earlier sequence_number "
                                "record with the same message_id exists in uncompacted log frames."
                                if edit_ts
                                else None
                            ),
                            "cached_content": norm["cached_content"],
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

    if stats is not None:
        stats["value_ops_total"] = stats.get("value_ops_total", 0) + local_value_ops
        stats["blink_v8_binary_only_values"] = stats.get("blink_v8_binary_only_values", 0) + local_v8_binary_only
    out_entries.extend(staged_entries)


def _has_leveldb_sstable_magic(path: Path) -> bool:
    """Verify the 8-byte LevelDB SSTable footer magic (`0xdb4775248b80fb57`) at `EOF - 8`."""
    try:
        size = path.stat().st_size
        if size < 48:
            return False
        with path.open("rb") as fh:
            fh.seek(size - 8)
            return fh.read(8) == LEVELDB_SSTABLE_MAGIC_LE
    except OSError:
        return False


def inspect_chromium_storage_path(
    target: Path,
    max_mb: int = 64,
    schema_mode: str = "auto",
    redact: bool = True,
) -> Dict[str, Any]:
    """
    Zero-PII local precheck gate (`GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED`)
    for law-firm IT or forensic intake teams before instructing a paid triage pilot.
    Never emits plaintext message content, filenames, or raw hashes in default masked mode.
    """
    if max_mb < 1:
        raise ValueError("--max-mb safety limit must be >= 1 MiB")
    if not target.exists():
        if redact:
            raise OSError(
                "Unable to access target path (OS path suppressed in masked mode; "
                "pass --unredacted in an offline lab for path diagnostics)"
            )
        raise FileNotFoundError(f"Target path does not exist: {target}")

    limit_bytes = max_mb * 1024 * 1024
    log_files: List[Path] = []
    ldb_files: List[Path] = []
    blob_files_count = 0

    if target.is_file():
        suf = target.suffix.lower()
        if suf == ".log":
            log_files.append(target)
        elif suf in (".ldb", ".sst"):
            ldb_files.append(target)
    elif target.is_dir():
        for p in sorted(target.rglob("*")):
            if not p.is_file():
                continue
            suf = p.suffix.lower()
            if suf == ".log":
                log_files.append(p)
            elif suf in (".ldb", ".sst"):
                ldb_files.append(p)
            elif ".blob" in str(p.parent).lower() or suf == ".blob":
                blob_files_count += 1

    valid_wal_frames = 0
    carvable_records = 0
    soft_deleted_records = 0
    v8_binary_only_values = 0
    oversize_logs_skipped = 0
    schemas_seen: Dict[str, int] = {}

    for lf in log_files:
        try:
            sz = lf.stat().st_size
        except OSError:
            continue
        if sz > limit_bytes:
            oversize_logs_skipped += 1
            continue
        if sz == 0:
            continue
        parsed = parse_leveldb_wal(lf.read_bytes(), schema_mode=schema_mode)
        valid_wal_frames += parsed["valid_physical_frames"]
        carvable_records += parsed["recovered_records_count"]
        v8_binary_only_values += parsed["blink_v8_non_json_values_skipped"]
        for rec in parsed["recovered_records"]:
            st = str(rec.get("schema_detected", "unknown"))
            schemas_seen[st] = schemas_seen.get(st, 0) + 1
            if rec.get("is_soft_deleted_in_ui"):
                soft_deleted_records += 1

    verified_sstables = sum(1 for f in ldb_files if _has_leveldb_sstable_magic(f))

    if carvable_records > 0 and verified_sstables == 0 and v8_binary_only_values == 0 and blob_files_count == 0:
        verdict = "GO"
        guidance = (
            "Uncompacted LevelDB .log frames contain carvable JSON records. "
            "Eligible for immediate byte-offset-cited extraction under v0.3.6."
        )
    elif carvable_records > 0:
        verdict = "PARTIAL"
        guidance = (
            "Carvable JSON records are recoverable from uncompacted .log frames, alongside compacted "
            ".ldb SSTables, external .blob files, or binary-only Blink V8 values that fall outside v0.3.6 scope."
        )
    else:
        verdict = "NO_GO_COMPACTED_OR_UNSUPPORTED"
        guidance = (
            "Zero carvable JSON records found in uncompacted .log files (storage may already be compacted "
            "into Snappy .ldb SSTables, encoded solely in binary Blink V8 StructuredClone, or empty). "
            "Under StarShield SOW terms, £0 pilot fee applies."
        )

    return {
        "epistemic_tier": "OBSERVED",
        "tool_version": "starshield-forensics/0.3.6",
        "target_label": "[REDACTED_TARGET_PATH]" if redact else str(target),
        "schema_mode": schema_mode,
        "feasibility_verdict": verdict,
        "wal_log_files_detected": len(log_files),
        "wal_oversize_files_skipped": oversize_logs_skipped,
        "valid_wal_physical_frames": valid_wal_frames,
        "carvable_json_records_count": carvable_records,
        "soft_deleted_json_records_count": soft_deleted_records,
        "schemas_detected_counts": schemas_seen,
        "compacted_sstable_files_detected": len(ldb_files),
        "verified_leveldb_sstables_count": verified_sstables,
        "indexeddb_blob_files_detected": blob_files_count,
        "blink_v8_non_json_values_detected": v8_binary_only_values,
        "intake_guidance": guidance,
    }
