#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
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
  slices inside Chromium IndexedDB / Local Storage WriteBatch values (compacted Snappy `.ldb`
  SSTables and `MANIFEST-*` logs are handled by `starshield.leveldb_sstable`).
- Does NOT decompress Zstandard (`0x02`) SSTable blocks, follow external `.blob`
  files, or decode binary-only Blink V8 StructuredClone primitives.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
from pathlib import Path
from typing import Any, Dict, List, Tuple

from starshield import __version__

BLOCK_SIZE = 32768
HEADER_SIZE = 7
MAX_LOGICAL_RECORD_BYTES = 32 * 1024 * 1024  # 32 MiB anti-DoS cap per reassembled batch
MAX_PRECHECK_SCAN_FILES = 4096  # Bounded directory walk cap for precheck
MAX_CORRUPTED_RECORDS_REPORTED = 256  # Output-amplification cap on corrupted_frames array
MAX_WAL_RECOVERED_RECORDS = 100_000  # Memory-amplification cap on recovered JSON records per WAL
MAX_JSON_INT_DIGITS = 64  # Bounded JSON integer digit cap preventing >4300-digit conversion errors
MAX_CARVE_DECODE_HEIGHT = 400  # Max balanced `{...}` height passed to CPython recursive raw_decode
MAX_KV_TEXT_CHARS = 512
LEVELDB_SSTABLE_MAGIC_LE = struct.pack("<Q", 0xDB4775248B80FB57)
SQLITE3_HEADER_MAGIC = b"SQLite format 3\x00"
_LONE_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
_JSON_OBJ_START_RE = re.compile(r'\{[ \t\r\n]*"')
_JSON_CARVE_SCAN_RE = re.compile(r'"(?:[^"\\\x00-\x1f]|\\.)*"|(?<![.0-9eE+-])[0-9]{65,}(?![.eE])|["{}]')
_MANIFEST_NAME_RE = re.compile(r"^MANIFEST-([0-9]+)$", re.IGNORECASE)
_PRINTABLE_CTRL_OK = frozenset({9, 10, 13})


def sanitize_utf8_str(val: str) -> str:
    """Replace lone UTF-16 surrogate code points (U+D800..U+DFFF) with U+FFFD for strict UTF-8 encoding."""
    if _LONE_SURROGATE_RE.search(val) is None:
        return val
    return _LONE_SURROGATE_RE.sub("\ufffd", val)


def sanitize_json_value(node: Any) -> Any:
    """Iteratively normalize JSON structures of arbitrary depth: scrub lone surrogates and convert NaN/Inf to None."""
    if node is None or isinstance(node, (bool, int)):
        return node
    if isinstance(node, float):
        return None if (math.isnan(node) or math.isinf(node)) else node
    if isinstance(node, str):
        return sanitize_utf8_str(node)

    if isinstance(node, dict):
        root_out: Any = {}
        stack: List[Tuple[Any, Any, bool]] = [(root_out, iter(node.items()), True)]
    elif isinstance(node, (list, tuple)):
        root_out = []
        stack = [(root_out, iter(node), False)]
    else:
        return sanitize_utf8_str(str(node))

    while stack:
        dst, it, is_dict = stack[-1]
        try:
            item = next(it)
        except StopIteration:
            stack.pop()
            continue

        if is_dict:
            raw_k, v = item
            k = sanitize_utf8_str(raw_k) if isinstance(raw_k, str) else sanitize_utf8_str(str(raw_k))
            if v is None or isinstance(v, (bool, int)):
                dst[k] = v
            elif isinstance(v, float):
                dst[k] = None if (math.isnan(v) or math.isinf(v)) else v
            elif isinstance(v, str):
                dst[k] = sanitize_utf8_str(v)
            elif isinstance(v, dict):
                child_d: Dict[str, Any] = {}
                dst[k] = child_d
                stack.append((child_d, iter(v.items()), True))
            elif isinstance(v, (list, tuple)):
                child_l: List[Any] = []
                dst[k] = child_l
                stack.append((child_l, iter(v), False))
            else:
                dst[k] = sanitize_utf8_str(str(v))
        else:
            v = item
            if v is None or isinstance(v, (bool, int)):
                dst.append(v)
            elif isinstance(v, float):
                dst.append(None if (math.isnan(v) or math.isinf(v)) else v)
            elif isinstance(v, str):
                dst.append(sanitize_utf8_str(v))
            elif isinstance(v, dict):
                child_d = {}
                dst.append(child_d)
                stack.append((child_d, iter(v.items()), True))
            elif isinstance(v, (list, tuple)):
                child_l = []
                dst.append(child_l)
                stack.append((child_l, iter(v), False))
            else:
                dst.append(sanitize_utf8_str(str(v)))

    return root_out


def dumps_strict_json(
    payload: Any,
    *,
    indent: int | None = 2,
    separators: tuple[str, str] | None = None,
    sort_keys: bool = False,
) -> str:
    """Serialize any Python structure to strict RFC 8259 UTF-8 JSON (allow_nan=False, zero surrogates)."""
    clean = sanitize_json_value(payload)
    return json.dumps(
        clean,
        indent=indent,
        separators=separators,
        sort_keys=sort_keys,
        ensure_ascii=False,
        allow_nan=False,
    )


class SafeDiagnosticError(ValueError):
    """Explicit whitelist ValueError carrying a static, zero-PII diagnostic message safe for masked mode."""

    def __init__(self, safe_message: str) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message


def read_bounded_bytes(
    path: Path,
    max_mb: int = 64,
    redact: bool = True,
    *,
    nofollow: bool = True,
) -> bytes:
    """Read a regular file strictly within `max_mb` MiB using O_RDONLY | O_NONBLOCK | O_NOFOLLOW."""
    if max_mb < 1:
        raise SafeDiagnosticError("--max-mb safety limit must be >= 1 MiB")
    safe_max_mb = int(max_mb)
    limit = safe_max_mb * 1024 * 1024

    fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        if nofollow:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        st = os.fstat(fd)
    except (OSError, ValueError) as exc:
        if fd is not None:
            os.close(fd)
        if redact:
            raise OSError(
                "Unable to access input file (filename and OS path suppressed in masked mode)"
            ) from None
        raise exc

    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        if redact:
            raise OSError(
                "Input path must be a regular file (filename and OS path suppressed in masked mode)"
            )
        raise OSError(f"Input path {path.name} is not a regular file")

    if st.st_size > limit:
        os.close(fd)
        if redact:
            raise SafeDiagnosticError(
                f"Input file exceeds --max-mb={safe_max_mb} safety limit "
                "(filename and exact byte length suppressed in masked mode)"
            )
        raise ValueError(f"File {path.name} ({st.st_size} bytes) exceeds --max-mb={safe_max_mb} safety limit")

    try:
        chunks: List[bytes] = []
        total = 0
        with os.fdopen(fd, "rb") as fh:
            while True:
                want = min(1024 * 1024, (limit + 1) - total)
                buf = fh.read(want)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                if total > limit:
                    if redact:
                        raise SafeDiagnosticError(
                            f"Input file exceeds --max-mb={safe_max_mb} safety limit "
                            "(filename and exact byte length suppressed in masked mode)"
                        )
                    raise ValueError(
                        f"File {path.name} ({total}+ bytes) exceeds --max-mb={safe_max_mb} safety limit"
                    )
        return b"".join(chunks)
    except OSError as exc:
        if redact:
            raise OSError(
                "Unable to read input file bytes (filename and OS path suppressed in masked mode)"
            ) from None
        raise exc

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
    "invoiceid",
    "payment_id",
    "paymentid",
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
    "paymentinstructions",
    "iban",
    "beneficiary_iban",
    "beneficiaryiban",
    "account_number",
    "accountnumber",
    "sort_code",
    "sortcode",
    "beneficiary",
    "payee",
    "amount",
    "total_due",
    "totaldue",
    "price",
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
        if shift == 63 and b > 1:
            raise ValueError("Varint overflow")
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("Varint overflow")
    raise ValueError("Truncated varint")


def is_blink_v8_serialized_value(buf: bytes) -> bool:
    """
    Detect Blink / V8 `SerializedScriptValue` headers (`0xFF + wire_version`, `0x00 0xFF <ver> 0xFF`,
    or 1..2 leading Chromium IndexedDB varints followed by `0xFF + wire_version`).
    """
    if not buf:
        return False
    if buf[0] == 0xFF:
        return len(buf) >= 2 and (0x09 <= buf[1] <= 0x40 or buf[1] == 0xFF)
    if buf[0] == 0x00:
        return (
            len(buf) >= 4
            and buf[1] == 0xFF
            and 0x09 <= buf[2] <= 0x28
            and buf[3] == 0xFF
        )
    pos = 0
    for _hop in range(2):
        try:
            _v, pos = decode_varint(buf, pos)
        except ValueError:
            return False
        if pos > 8 or pos + 2 > len(buf):
            return False
        if buf[pos] == 0xFF and (0x09 <= buf[pos + 1] <= 0x40 or buf[pos + 1] == 0xFF):
            return True
        if pos + 3 <= len(buf) and buf[pos : pos + 2] == b"\x00\xff" and 0x09 <= buf[pos + 2] <= 0x40:
            return True
    return False


def _is_chromium_domstorage_key(user_key: bytes) -> bool:
    """Identify Chromium DOMStorage / LocalStorage keys (`_<origin>\\x00<tag><key>` or `META:<origin>`)."""
    if user_key.startswith(b"META:") and len(user_key) > 5:
        return True
    if not user_key.startswith(b"_"):
        return False
    sep = user_key.find(b"\x00", 1)
    if sep <= 1 or sep + 1 >= len(user_key):
        return False
    origin_part = user_key[1:sep]
    return b"://" in origin_part or origin_part in (b"null", b"file://")


def _decode_chromium_string_prefixed(buf: bytes, *, allow_single_char: bool = False) -> str | None:
    """
    Decode Chromium LocalStorage / DOMStorage value or key segment (`\\x01` UTF-8/Latin-1,
    `\\x00` UTF-16LE, or clean printable UTF-8) while rejecting binary Blink V8 `0xFF` blobs.
    """
    if not buf or is_blink_v8_serialized_value(buf):
        return None

    cand: str | None = None
    prefixed = False
    if buf[0] == 0x01 and len(buf) > 1:
        prefixed = True
        try:
            cand = buf[1:].decode("utf-8")
        except UnicodeDecodeError:
            cand = buf[1:].decode("latin-1")
    elif buf[0] == 0x00 and len(buf) >= 3 and (len(buf) - 1) % 2 == 0:
        prefixed = True
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
    min_chars = 1 if (prefixed or allow_single_char) else 2
    if len(cleaned) < min_chars:
        return None
    printable = sum(1 for ch in cleaned if ch.isprintable() or ord(ch) in _PRINTABLE_CTRL_OK)
    if printable / len(cleaned) < 0.85:
        return None
    return cleaned[:MAX_KV_TEXT_CHARS]


def _extract_lightweight_kv_record(user_key: bytes, val_bytes: bytes) -> Dict[str, Any] | None:
    """
    Lightweight non-V8-AST key-value string extractor covering Chromium LocalStorage
    `_<origin>\\x00\\x01<key>` (in `auto` & `generic-json`) and plaintext KV entries (`generic-json`).
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
        key_label = (
            _decode_chromium_string_prefixed(rest_key, allow_single_char=True)
            or rest_key.lstrip(b"\x00\x01").decode("utf-8", errors="ignore").strip()
        )
    elif user_key.startswith(b"META:") and len(user_key) > 5:
        origin_str = user_key[5:].decode("utf-8", errors="ignore").strip()
        key_label = "META"
    else:
        key_label = _decode_chromium_string_prefixed(user_key, allow_single_char=True) or ""

    if not key_label:
        key_label = f"key_{hashlib.sha256(user_key).hexdigest()[:12]}"

    rec: Dict[str, Any] = {
        "message_id": key_label[:128],
        "sender_mri": "",
        "composetime": None,
        "deletetime": None,
        "edittime": None,
        "cached_content": f"{key_label}: {val_txt}" if key_label else val_txt,
    }
    if origin_str:
        rec["storage_origin"] = origin_str[:128]
    return rec


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


_CHATSVC_SIGNATURE_KEYS = frozenset(
    {
        "composetime",
        "messagetype",
        "conversationid",
        "imdisplayname",
        "clientmessageid",
        "originalarrivaltime",
        "amsreferences",
    }
)
_B2B_INVOICE_EXCLUSIVE_KEYS = frozenset(
    {
        "invoice_id",
        "invoiceid",
        "payment_id",
        "paymentid",
        "beneficiary_iban",
        "beneficiaryiban",
        "iban",
        "sort_code",
        "sortcode",
        "account_number",
        "accountnumber",
        "routing_number",
        "routingnumber",
        "swift",
        "bic",
        "beneficiary",
        "payee",
        "vendor",
        "supplier",
        "payment_instructions",
        "paymentinstructions",
        "amount",
        "total_due",
        "totaldue",
        "price",
        "payment_ref",
        "paymentref",
    }
)
_SLACK_EXCLUSIVE_KEYS = frozenset({"channel", "blocks", "subtype", "deleted_ts", "client_msg_id"})
_SKYPE_TEAMS_MRI_PREFIXES = ("8:", "live:", "28:", "4:")


def _has_direct_financial_keys(props: Any) -> bool:
    """Check direct keys of `properties` for invoice/financial routing fields."""
    if not isinstance(props, dict):
        return False
    return any(str(k).lower() in _B2B_INVOICE_EXCLUSIVE_KEYS for k in props.keys())


def _is_valid_chatsvc_message_obj(obj: Any, *, allow_generic_id_content: bool = False) -> bool:
    """Ensure carved JSON object is a top-level chatsvc message record, not a B2B invoice, Slack/Web messenger, or inner sub-dict."""
    if not isinstance(obj, dict):
        return False
    lower_map: Dict[str, Any] = {}
    for k, v in obj.items():
        kl = str(k).lower()
        if kl not in lower_map:
            lower_map[kl] = v
    msg_id = obj.get("id", lower_map.get("id"))
    if msg_id is None or str(msg_id).strip() == "":
        return False
    lower_keys = set(lower_map.keys())
    props = obj.get("properties", lower_map.get("properties"))
    # Top-level invoice routing keys always veto chatsvc
    if lower_keys & _B2B_INVOICE_EXCLUSIVE_KEYS:
        return False
    # Genuine Teams/Skype records carrying explicit chatsvc signature keys are preserved even if
    # nested Adaptive Card payloads contain `amount` / `beneficiary` fields inside sub-objects
    if lower_keys & _CHATSVC_SIGNATURE_KEYS:
        return True
    if _has_direct_financial_keys(props):
        return False
    if lower_keys & _SLACK_EXCLUSIVE_KEYS:
        return False
    if isinstance(props, dict) and any(
        str(pk).lower() in ("deletetime", "edittime", "emotions", "links") for pk in props.keys()
    ):
        return True
    from_val = obj.get("from", lower_map.get("from"))
    if from_val is not None and not (lower_keys & {"body", "text", "t", "ts"}):
        if isinstance(from_val, str) and from_val.strip().lower().startswith(_SKYPE_TEAMS_MRI_PREFIXES):
            return True
        if allow_generic_id_content:
            return True
    if allow_generic_id_content and "content" in lower_keys:
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

    if _is_valid_chatsvc_message_obj(obj, allow_generic_id_content=(schema_mode == "chatsvc")):
        return "chatsvc"

    if schema_mode == "chatsvc":
        return None

    lower_keys = {str(k).lower() for k in obj.keys()}

    # Slack Web / Electron IndexedDB & Redux cache shape
    if ("ts" in lower_keys or "client_msg_id" in lower_keys) and (
        lower_keys & {"text", "user", "blocks", "subtype", "deleted_ts", "channel"}
    ):
        return "slack_web"

    # Explicit B2B supplier, ERP, or banking invoice/payment portal shape when financial keys are present
    props_sub = obj.get("properties")
    has_fin = bool(lower_keys & _B2B_INVOICE_EXCLUSIVE_KEYS) or _has_direct_financial_keys(props_sub)
    if (lower_keys & set(_PORTAL_ID_KEYS)) and has_fin:
        return "b2b_portal_json"

    # WhatsApp Web / Signal / Generic Web Messenger shape
    if (lower_keys & {"id", "msg_id", "t", "timestamp"}) and (
        lower_keys & {"body", "text", "message", "author", "from", "sender", "ack"}
    ):
        return "web_messenger"

    # B2B supplier, ERP, or banking invoice/payment portal fallback shape (e.g. id + content/memo/note)
    if (lower_keys & set(_PORTAL_ID_KEYS)) and (lower_keys & set(_PORTAL_CONTENT_KEYS)):
        return "b2b_portal_json"

    if schema_mode == "generic-json":
        return "generic_json"

    return None


_NON_IOC_METADATA_KEYS = frozenset(
    {
        "blob_pad",
        "avatar",
        "thumbnail",
        "raw_html",
        "id",
        "message_id",
        "messageid",
        "clientmessageid",
        "client_msg_id",
        "conversationid",
        "threadid",
        "channel_id",
        "team_id",
        "user_id",
        "ts",
        "thread_ts",
        "latest_reply",
        "composetime",
        "originalarrivaltime",
        "edittime",
        "deletetime",
        "created_at",
        "updated_at",
        "timestamp",
        "version",
        "sequence",
        "seq",
    }
)


def _collect_string_scalars(node: Any, cap: int = 64) -> List[str]:
    """Iteratively collect bounded string/number leaves for generic-json IOC & content normalization."""
    acc: List[str] = []
    work: List[Any] = [node]
    while work and len(acc) < cap:
        cur = work.pop()
        if cur is None or isinstance(cur, bool):
            continue
        if isinstance(cur, str):
            s = cur.strip()
            if s:
                acc.append(s)
        elif isinstance(cur, (int, float)):
            if not (isinstance(cur, float) and (math.isnan(cur) or math.isinf(cur))):
                acc.append(str(cur))
        elif isinstance(cur, dict):
            nested_children: List[Any] = []
            for k in sorted(cur.keys(), key=str):
                kl = str(k).lower()
                if kl in ("blob_pad", "avatar", "thumbnail", "raw_html"):
                    continue
                v = cur[k]
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                        continue
                    vs = str(v).strip()
                    if vs:
                        acc.append(f"{k}: {vs}")
                        if len(acc) >= cap:
                            break
                else:
                    nested_children.append(v)
            if len(acc) < cap and nested_children:
                work.extend(reversed(nested_children))
        elif isinstance(cur, list):
            work.extend(reversed(cur))
    return acc


def _collect_ioc_scalars(
    node: Any,
    *,
    cap: int = 4096,
    max_chars: int = 262_144,
) -> Tuple[List[str], bool]:
    """
    Collect structured scalar values for per-message IOC extraction while excluding synthetic
    message-ID / epoch-timestamp metadata keys (`clientmessageid`, `ts`, etc.) and reporting
    whether `cap` or `max_chars` truncated traversal.
    """
    acc: List[str] = []
    total_chars = 0
    truncated = False
    work: List[Any] = [node]
    while work:
        if len(acc) >= cap or total_chars >= max_chars:
            truncated = True
            break
        cur = work.pop()
        if cur is None or isinstance(cur, bool):
            continue
        if isinstance(cur, str):
            s = cur.strip()
            if s:
                acc.append(s)
                total_chars += len(s)
        elif isinstance(cur, (int, float)):
            if not (isinstance(cur, float) and (math.isnan(cur) or math.isinf(cur))):
                s_num = str(cur)
                acc.append(s_num)
                total_chars += len(s_num)
        elif isinstance(cur, dict):
            nested_children: List[Any] = []
            keys_sorted = sorted(cur.keys(), key=str)
            for idx_k, k in enumerate(keys_sorted):
                kl = str(k).lower()
                if kl in _NON_IOC_METADATA_KEYS:
                    continue
                v = cur[k]
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                        continue
                    vs = str(v).strip()
                    if vs:
                        item_s = f"{k}: {vs}"
                        acc.append(item_s)
                        total_chars += len(item_s)
                        if len(acc) >= cap or total_chars >= max_chars:
                            if idx_k + 1 < len(keys_sorted) or nested_children or work:
                                truncated = True
                            break
                else:
                    nested_children.append(v)
            if not truncated and nested_children:
                work.extend(reversed(nested_children))
        elif isinstance(cur, list):
            work.extend(reversed(cur))
    return acc, truncated


def _clean_ts_field(val: Any) -> Any:
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return None
    if isinstance(val, str):
        return sanitize_utf8_str(val)
    return val


def normalize_carved_record_fields(obj: Dict[str, Any], schema_tag: str) -> Dict[str, Any]:
    """Map multi-platform web cache JSON fields onto StarShield's canonical record layout (with case-insensitive fallback)."""
    lower_map: Dict[str, Any] = {}
    for k, v in obj.items():
        kl = str(k).lower()
        if kl not in lower_map:
            lower_map[kl] = v

    def _get_ci(d: Dict[str, Any], d_low: Dict[str, Any], key: str, default: Any = None) -> Any:
        if key in d:
            return d[key]
        return d_low.get(key, default)

    raw_props = _get_ci(obj, lower_map, "properties")
    props = raw_props if isinstance(raw_props, dict) else {}
    props_low: Dict[str, Any] = {}
    for pk, pv in props.items():
        pkl = str(pk).lower()
        if pkl not in props_low:
            props_low[pkl] = pv

    raw_edited = _get_ci(obj, lower_map, "edited")
    edited_sub = raw_edited if isinstance(raw_edited, dict) else {}
    edited_low: Dict[str, Any] = {str(ek).lower(): ev for ek, ev in edited_sub.items()}

    msg_id = ""
    for k in _PORTAL_ID_KEYS + ("ts", "t"):
        v = _get_ci(obj, lower_map, k)
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            continue
        if v is not None and str(v).strip() != "":
            msg_id = sanitize_utf8_str(str(v).strip())
            break

    sender = ""
    for k in (
        "from",
        "imdisplayname",
        "displayname",
        "user",
        "sender",
        "author",
        "actor",
        "vendor",
        "supplier",
        "beneficiary",
    ):
        v = _get_ci(obj, lower_map, k)
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            continue
        if v is not None and str(v).strip() != "":
            sender = sanitize_utf8_str(str(v).strip())
            break

    compose_ts = None
    for k in ("composetime", "originalarrivaltime", "ts", "t", "timestamp", "created_at", "issued_at", "date"):
        cand = _clean_ts_field(_get_ci(obj, lower_map, k))
        if cand not in (None, ""):
            compose_ts = cand
            break

    del_ts = _clean_ts_field(
        _get_ci(props, props_low, "deletetime")
        or _get_ci(obj, lower_map, "deletetime")
        or _get_ci(obj, lower_map, "deleted_ts")
        or _get_ci(obj, lower_map, "deleted_at")
        or _get_ci(obj, lower_map, "retracted_at")
        or (
            "true"
            if _get_ci(obj, lower_map, "subtype") == "message_deleted" or _get_ci(obj, lower_map, "is_deleted") is True
            else None
        )
    )
    edit_ts = _clean_ts_field(
        _get_ci(props, props_low, "edittime")
        or _get_ci(obj, lower_map, "edittime")
        or _get_ci(edited_sub, edited_low, "ts")
        or _get_ci(obj, lower_map, "edited_at")
        or _get_ci(obj, lower_map, "updated_at")
    )

    if schema_tag == "chatsvc":
        raw_c = _get_ci(obj, lower_map, "content", "")
        if raw_c is None or (isinstance(raw_c, float) and (math.isnan(raw_c) or math.isinf(raw_c))):
            content_str = ""
        else:
            content_str = sanitize_utf8_str(str(raw_c))
        extra_chat_leaves: List[str] = []
        for sub_k in ("cards", "attachments"):
            sub_v = _get_ci(props, props_low, sub_k)
            if sub_v is None:
                sub_v = _get_ci(obj, lower_map, sub_k)
            if isinstance(sub_v, (dict, list)) and sub_v:
                extra_chat_leaves.extend(_collect_string_scalars(sub_v, cap=64))
        if extra_chat_leaves:
            ext_txt = sanitize_utf8_str(" | ".join(extra_chat_leaves))
            content_str = f"{content_str} | {ext_txt}" if content_str else ext_txt
    else:
        primary_parts: List[str] = []
        for k in ("content", "text", "body", "message", "payment_instructions", "memo", "note", "description"):
            v = _get_ci(obj, lower_map, k)
            if isinstance(v, str) and v.strip():
                primary_parts.append(sanitize_utf8_str(v.strip()))
        # Append structured banking/routing fields if present outside free-text body
        for k in (
            "beneficiary",
            "payee",
            "iban",
            "beneficiary_iban",
            "beneficiaryiban",
            "sort_code",
            "sortcode",
            "account_number",
            "accountnumber",
            "routing_number",
            "routingnumber",
            "swift",
            "bic",
            "amount",
            "total_due",
            "totaldue",
            "price",
            "payment_ref",
            "paymentref",
        ):
            v = _get_ci(obj, lower_map, k)
            if v is None:
                v = _get_ci(props, props_low, k)
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                continue
            if v is not None and str(v).strip():
                primary_parts.append(f"{k}={sanitize_utf8_str(str(v).strip())}")
        # Also include nested container fields (e.g. Slack `blocks`/`attachments` or nested `wire_details`)
        envelope_skip = {
            "id",
            "from",
            "user",
            "sender",
            "author",
            "ts",
            "t",
            "timestamp",
            "composetime",
            "originalarrivaltime",
            "deletetime",
            "deleted_ts",
            "edittime",
            "edited",
            "properties",
            "blob_pad",
            "avatar",
            "thumbnail",
            "raw_html",
        }
        for raw_ok, raw_ov in obj.items():
            if str(raw_ok).lower() in envelope_skip:
                continue
            if isinstance(raw_ov, (dict, list)) and raw_ov:
                for leaf in _collect_string_scalars(raw_ov, cap=64):
                    clean_leaf = sanitize_utf8_str(leaf)
                    if clean_leaf and clean_leaf not in primary_parts:
                        primary_parts.append(clean_leaf)
        if primary_parts:
            content_str = " | ".join(primary_parts)
        else:
            content_str = sanitize_utf8_str(" | ".join(_collect_string_scalars(obj)))

    return {
        "message_id": msg_id,
        "sender_mri": sender,
        "composetime": compose_ts,
        "deletetime": del_ts,
        "edittime": edit_ts,
        "cached_content": content_str,
    }


class _CarveIntLimitError(ValueError):
    """Raised when a JSON integer token inside a carved slice exceeds `MAX_JSON_INT_DIGITS`."""


def _bounded_carve_int(num_str: str) -> int:
    if len(num_str.lstrip("+-")) > MAX_JSON_INT_DIGITS:
        raise _CarveIntLimitError("JSON integer exceeds bounded 64-digit safety limit")
    return int(num_str)


def _extract_json_objects_from_bytes(
    raw_val: bytes,
    schema_mode: str = "auto",
    *,
    max_objects: int = MAX_WAL_RECOVERED_RECORDS,
) -> List[Tuple[Dict[str, Any], str]]:
    """
    Linear O(N) UTF-8 / UTF-16LE JSON object carver with bounded integers and surrogate isolation.

    Searches only candidate `{ "..."` object starts (`_JSON_OBJ_START_RE`) so bare `{` floods take
    O(N) without invoking `raw_decode`, walks decoded outer container dicts iteratively without
    double-carving inner `properties` sub-dicts, and recovers maximal balanced `{...}` spans from
    truncated or poison-prefixed wrappers without quadratic retries.
    """
    if max_objects <= 0:
        return []
    candidates: List[str] = []
    u8_txt = raw_val.decode("utf-8", errors="ignore")
    if "{" in u8_txt:
        candidates.append(u8_txt)
    if b"\x00" in raw_val:
        even_u16 = raw_val.decode("utf-16-le", errors="ignore")
        if "{" in even_u16:
            candidates.append(even_u16)
        if len(raw_val) >= 3:
            odd_u16 = raw_val[1:].decode("utf-16-le", errors="ignore")
            if "{" in odd_u16:
                candidates.append(odd_u16)
    if not candidates:
        return []

    decoder = json.JSONDecoder(parse_int=_bounded_carve_int)
    found: List[Tuple[Dict[str, Any], str]] = []
    seen_hashes: set[str] = set()

    def _ingest_decoded_value(root_val: Any) -> None:
        work: List[Any] = [root_val]
        while work and len(found) < max_objects:
            cur = work.pop()
            if isinstance(cur, dict):
                schema_tag = classify_carved_json_object(cur, schema_mode=schema_mode)
                if schema_tag is not None:
                    clean_obj = sanitize_json_value(cur)
                    canonical = json.dumps(clean_obj, sort_keys=True, ensure_ascii=False, allow_nan=False)
                    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        found.append((clean_obj, schema_tag))
                else:
                    vals = list(cur.values())
                    for v in reversed(vals):
                        if isinstance(v, (dict, list)):
                            work.append(v)
            elif isinstance(cur, list):
                for item in reversed(cur):
                    if isinstance(item, (dict, list)):
                        work.append(item)

    for text in candidates:
        pos = 0
        n = len(text)
        max_retry_fail_pos = -1

        while pos < n and len(found) < max_objects:
            m_start = _JSON_OBJ_START_RE.search(text, pos)
            if m_start is None:
                break
            brace_idx = m_start.start()
            is_bigint_abort = False
            try:
                obj, end_idx = decoder.raw_decode(text, brace_idx)
                pos = max(end_idx, brace_idx + 1)
                _ingest_decoded_value(obj)
                continue
            except json.JSONDecodeError as exc:
                fail_limit = min(n, max(brace_idx + 1, exc.pos))
                is_hard_abort = False
            except _CarveIntLimitError:
                fail_limit = n
                is_hard_abort = True
                is_bigint_abort = True
            except (RecursionError, ValueError):
                fail_limit = n
                is_hard_abort = True

            # Single-pass scan over `[brace_idx + 1, fail_limit)` collecting disjoint maximal closed `{...}` spans
            stack: List[Tuple[int, List[Any], int]] = [(brace_idx, [], 1)]
            root_closed_children: List[Any] = []
            last_str_brace: int | None = None
            last_str_end = -1
            early_next: int | None = None

            for m in _JSON_CARVE_SCAN_RE.finditer(text, brace_idx + 1, fail_limit):
                ms, me = m.start(), m.end()
                ch = text[ms]
                if ch == '"':
                    if me - ms >= 2:
                        b_in = text.find("{", ms + 1, me - 1)
                        if b_in != -1:
                            last_str_brace = b_in
                            last_str_end = me
                    else:
                        if is_hard_abort:
                            early_next = ms + 1
                        break
                elif ch == "{":
                    stack.append((ms, [], 1))
                elif ch == "}":
                    if stack:
                        open_pos, cur_children, cur_height = stack.pop()
                        if not stack:
                            root_closed_children.extend(cur_children)
                            early_next = me
                            break
                        p_pos, p_children, p_height = stack[-1]
                        p_children.append((open_pos, me, cur_children, cur_height))
                        if cur_height + 1 > p_height:
                            stack[-1] = (p_pos, p_children, cur_height + 1)
                else:
                    # Matched unquoted 65+-digit integer token
                    if is_bigint_abort:
                        early_next = me
                        break

            pending_spans: List[Any] = list(root_closed_children)
            for _f_pos, f_children, _f_h in stack:
                pending_spans.extend(f_children)

            span_stack: List[Any] = list(reversed(pending_spans))
            while span_stack:
                s_lo, s_hi, s_children, s_height = span_stack.pop()
                if (s_hi - s_lo) < 10:
                    continue
                if s_height > MAX_CARVE_DECODE_HEIGHT:
                    span_stack.extend(reversed(s_children))
                    continue
                try:
                    sub_obj, sub_end = decoder.raw_decode(text, s_lo)
                    if sub_end <= s_hi:
                        _ingest_decoded_value(sub_obj)
                    else:
                        span_stack.extend(reversed(s_children))
                except (json.JSONDecodeError, RecursionError, ValueError):
                    span_stack.extend(reversed(s_children))

            if early_next is not None:
                pos = max(brace_idx + 1, early_next)
            elif (
                not is_hard_abort
                and last_str_brace is not None
                and (fail_limit - last_str_end) <= 4
                and fail_limit > max_retry_fail_pos
            ):
                max_retry_fail_pos = fail_limit
                pos = max(brace_idx + 1, last_str_brace)
            else:
                pos = max(brace_idx + 1, fail_limit)

    return found


def iter_leveldb_logical_records(
    raw_bytes: bytes,
) -> Tuple[List[Tuple[int, bytes]], int, List[Dict[str, Any]], int]:
    """
    Parse 32 KiB LevelDB log-framed records (shared by `.log` WAL and `MANIFEST-*`).

    Returns `(logical_records, valid_physical_frames, corrupted_frames, corrupted_total_count)`.
    """
    total_len = len(raw_bytes)
    logical_out: List[Tuple[int, bytes]] = []
    physical_records_ok = 0
    corrupted_records: List[Dict[str, Any]] = []
    corrupted_total_count = 0

    def add_corrupted(entry: Dict[str, Any]) -> None:
        nonlocal corrupted_total_count
        corrupted_total_count += 1
        if len(corrupted_records) < MAX_CORRUPTED_RECORDS_REPORTED:
            corrupted_records.append(entry)

    frag_buf = bytearray()
    frag_start_offset: int | None = None

    block_idx = 0
    while block_idx * BLOCK_SIZE < total_len:
        block_start = block_idx * BLOCK_SIZE
        block_end = min(block_start + BLOCK_SIZE, total_len)
        pos = block_start

        while pos + HEADER_SIZE <= block_end:
            stored_crc, length, rec_type = struct.unpack_from("<IHB", raw_bytes, pos)
            if rec_type == REC_ZERO and length == 0:
                if frag_start_offset is not None:
                    add_corrupted(
                        {
                            "byte_offset": frag_start_offset,
                            "reason": "Unclosed FIRST/MIDDLE fragmented record interrupted by zero-header block region",
                        }
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                if stored_crc != 0:
                    add_corrupted(
                        {
                            "byte_offset": pos,
                            "reason": f"Non-zero CRC32C (0x{stored_crc:08x}) on zero-type length-0 block header",
                        }
                    )
                else:
                    rem = raw_bytes[pos:block_end]
                    if rem.count(0) != len(rem):
                        add_corrupted(
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
                add_corrupted(
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
                add_corrupted(
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
                    add_corrupted(
                        {
                            "byte_offset": frag_start_offset,
                            "reason": "Unclosed FIRST/MIDDLE fragmented record interrupted by FULL record",
                        }
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                logical_out.append((rec_offset, chunk))
            elif rec_type == REC_FIRST:
                if frag_start_offset is not None:
                    add_corrupted(
                        {
                            "byte_offset": frag_start_offset,
                            "reason": "Unclosed FIRST/MIDDLE fragmented record interrupted by new FIRST record",
                        }
                    )
                frag_buf = bytearray(chunk)
                frag_start_offset = rec_offset
            elif rec_type == REC_MIDDLE:
                if frag_start_offset is None:
                    add_corrupted({"byte_offset": rec_offset, "reason": "Orphan MIDDLE fragment without FIRST"})
                    continue
                if len(frag_buf) + len(chunk) > MAX_LOGICAL_RECORD_BYTES:
                    add_corrupted(
                        {"byte_offset": frag_start_offset, "reason": "Fragmented record exceeds 32MiB safety limit"}
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                    continue
                frag_buf.extend(chunk)
            elif rec_type == REC_LAST:
                if frag_start_offset is None:
                    add_corrupted({"byte_offset": rec_offset, "reason": "Orphan LAST fragment without FIRST"})
                    continue
                if len(frag_buf) + len(chunk) > MAX_LOGICAL_RECORD_BYTES:
                    add_corrupted(
                        {"byte_offset": frag_start_offset, "reason": "Fragmented record exceeds 32MiB safety limit"}
                    )
                    frag_buf.clear()
                    frag_start_offset = None
                    continue
                frag_buf.extend(chunk)
                logical_out.append((frag_start_offset, bytes(frag_buf)))
                frag_buf.clear()
                frag_start_offset = None
            else:
                add_corrupted({"byte_offset": rec_offset, "reason": f"Unknown LevelDB record type {rec_type}"})
                frag_buf.clear()
                frag_start_offset = None

        if pos < block_end:
            trailer = raw_bytes[pos:block_end]
            if trailer.count(0) != len(trailer):
                add_corrupted(
                    {
                        "byte_offset": pos,
                        "reason": f"Non-zero truncated header/trailer ({len(trailer)} bytes < 7-byte header)",
                    }
                )

        block_idx += 1

    if frag_start_offset is not None:
        add_corrupted(
            {
                "byte_offset": frag_start_offset,
                "reason": "Truncated logical record: unclosed FIRST/MIDDLE fragment at EOF",
            }
        )

    return logical_out, physical_records_ok, corrupted_records, corrupted_total_count


def parse_leveldb_wal(
    raw_bytes: bytes,
    schema_mode: str = "auto",
    *,
    probe_generic_fallback: bool = False,
) -> Dict[str, Any]:
    """Parse a Chromium LevelDB `.log` file, verifying CRC32C, WriteBatch bounds, and EOF completeness."""
    if schema_mode not in VALID_SCHEMA_MODES:
        raise ValueError(f"Unsupported schema_mode={schema_mode!r}; expected one of {VALID_SCHEMA_MODES}")

    logical_records, physical_records_ok, corrupted_records, corrupted_total_count = iter_leveldb_logical_records(
        raw_bytes
    )
    recovered_entries: List[Dict[str, Any]] = []
    stats: Dict[str, int] = {
        "value_ops_total": 0,
        "tombstone_ops_total": 0,
        "blink_v8_binary_only_values": 0,
        "recovered_truncated": 0,
        "generic_fallback_records": 0,
    }
    tombstones_by_key_hash: Dict[str, int] = {}

    for logical_offset, logical_bytes in logical_records:
        batch_corrupt: List[Dict[str, Any]] = []
        _decode_writebatch_into(
            logical_bytes,
            logical_offset,
            recovered_entries,
            batch_corrupt,
            schema_mode=schema_mode,
            stats=stats,
            tombstones_by_key_hash=tombstones_by_key_hash,
            probe_generic_fallback=probe_generic_fallback,
        )
        for c_item in batch_corrupt:
            corrupted_total_count += 1
            if len(corrupted_records) < MAX_CORRUPTED_RECORDS_REPORTED:
                corrupted_records.append(c_item)

    if tombstones_by_key_hash:
        for rec in recovered_entries:
            kh = rec.get("key_sha256", "")
            max_del_seq = tombstones_by_key_hash.get(kh)
            rec["superseded_by_wal_tombstone"] = (
                max_del_seq is not None and max_del_seq > rec["leveldb_sequence_number"]
            )
    else:
        for rec in recovered_entries:
            rec["superseded_by_wal_tombstone"] = False

    chatsvc_count = sum(1 for r in recovered_entries if r.get("schema_detected") == "chatsvc")
    res_wal: Dict[str, Any] = {
        "parser": f"leveldb_wal_32k_crc32c_v{__version__}",
        "schema_mode": schema_mode,
        "file_size_bytes": len(raw_bytes),
        "valid_physical_frames": physical_records_ok,
        "writebatch_value_ops_seen": stats["value_ops_total"],
        "writebatch_tombstone_ops_seen": stats["tombstone_ops_total"],
        "blink_v8_non_json_values_skipped": stats["blink_v8_binary_only_values"],
        "corrupted_frames_count": corrupted_total_count,
        "corrupted_frames_truncated": corrupted_total_count > MAX_CORRUPTED_RECORDS_REPORTED,
        "corrupted_frames": corrupted_records,
        "recovered_records_count": len(recovered_entries),
        "recovered_records_truncated": bool(stats["recovered_truncated"]),
        "recovered_chatsvc_records_count": chatsvc_count,
        "recovered_records": recovered_entries,
    }
    if probe_generic_fallback:
        res_wal["generic_fallback_records_count"] = stats["generic_fallback_records"]
    return res_wal


def _decode_writebatch_into(
    batch: bytes,
    logical_offset: int,
    out_entries: List[Dict[str, Any]],
    corrupted: List[Dict[str, Any]],
    schema_mode: str = "auto",
    stats: Dict[str, int] | None = None,
    tombstones_by_key_hash: Dict[str, int] | None = None,
    *,
    probe_generic_fallback: bool = False,
) -> None:
    if len(batch) < 12:
        corrupted.append({"byte_offset": logical_offset, "reason": "WriteBatch shorter than 12-byte header"})
        return

    seq_num, declared_count = struct.unpack_from("<QI", batch, 0)
    idx = 12
    parsed_ops = 0
    staged_entries: List[Dict[str, Any]] = []
    staged_tombstones: List[Tuple[str, int]] = []
    local_value_ops = 0
    local_tombstone_ops = 0
    local_v8_binary_only = 0
    local_generic_fallback = 0
    local_truncated = False

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

                rem_cap = MAX_WAL_RECOVERED_RECORDS - (len(out_entries) + len(staged_entries))
                if rem_cap <= 0:
                    local_truncated = True
                else:
                    carved_objs = _extract_json_objects_from_bytes(
                        val_bytes, schema_mode=schema_mode, max_objects=rem_cap + 1
                    )
                    is_dom_key = _is_chromium_domstorage_key(key_bytes)
                    if not carved_objs and schema_mode == "auto" and is_dom_key:
                        carved_objs = _extract_json_objects_from_bytes(
                            val_bytes, schema_mode="generic-json", max_objects=rem_cap + 1
                        )
                    if len(carved_objs) > rem_cap:
                        carved_objs = carved_objs[:rem_cap]
                        local_truncated = True

                    norm_pairs: List[Tuple[Dict[str, Any], str]] = [
                        (normalize_carved_record_fields(obj, schema_tag), schema_tag)
                        for obj, schema_tag in carved_objs
                    ]
                    if not norm_pairs and (schema_mode == "generic-json" or (schema_mode == "auto" and is_dom_key)):
                        kv_rec = _extract_lightweight_kv_record(key_bytes, val_bytes)
                        if kv_rec is not None:
                            norm_pairs.append((kv_rec, "localstorage_kv_text"))

                    if not norm_pairs and probe_generic_fallback and schema_mode == "auto" and not is_dom_key:
                        gen_objs = _extract_json_objects_from_bytes(
                            val_bytes, schema_mode="generic-json", max_objects=64
                        )
                        if gen_objs:
                            local_generic_fallback += len(gen_objs)
                        elif _extract_lightweight_kv_record(key_bytes, val_bytes) is not None:
                            local_generic_fallback += 1

                    if not norm_pairs and is_blink_v8_serialized_value(val_bytes):
                        local_v8_binary_only += 1

                    for norm, schema_tag in norm_pairs:
                        del_ts = norm["deletetime"]
                        edit_ts = norm["edittime"]
                        entry_dict: Dict[str, Any] = {
                            "epistemic_tier": "OBSERVED",
                            "schema_detected": schema_tag,
                            "leveldb_batch_byte_offset": logical_offset,
                            "leveldb_batch_sequence_number": seq_num,
                            "leveldb_sequence_number": seq_num + parsed_ops,
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
                        if "storage_origin" in norm:
                            entry_dict["storage_origin"] = norm["storage_origin"]
                        staged_entries.append(entry_dict)
            elif op_type == 0:
                local_tombstone_ops += 1
                if tombstones_by_key_hash is not None and len(staged_tombstones) < MAX_WAL_RECOVERED_RECORDS:
                    staged_tombstones.append((hashlib.sha256(key_bytes).hexdigest(), seq_num + parsed_ops))
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
        stats["tombstone_ops_total"] = stats.get("tombstone_ops_total", 0) + local_tombstone_ops
        stats["blink_v8_binary_only_values"] = stats.get("blink_v8_binary_only_values", 0) + local_v8_binary_only
        stats["generic_fallback_records"] = stats.get("generic_fallback_records", 0) + local_generic_fallback
        if local_truncated:
            stats["recovered_truncated"] = 1
    if tombstones_by_key_hash is not None:
        for kh, tseq in staged_tombstones:
            prev_t = tombstones_by_key_hash.get(kh)
            if prev_t is None or tseq > prev_t:
                tombstones_by_key_hash[kh] = tseq
    out_entries.extend(staged_entries)


def _has_leveldb_sstable_magic(path: Path) -> bool:
    """Verify the 8-byte LevelDB SSTable footer magic (`0xdb4775248b80fb57`) at `EOF - 8` via O_NOFOLLOW."""
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size < 48:
            return False
        os.lseek(fd, st.st_size - 8, os.SEEK_SET)
        tail = os.read(fd, 8)
        return tail == LEVELDB_SSTABLE_MAGIC_LE
    except OSError:
        return False
    finally:
        if fd >= 0:
            os.close(fd)


def _has_sqlite3_magic(path: Path) -> bool:
    """Verify the 16-byte SQLite 3 header magic (`b'SQLite format 3\\x00'`) at offset 0 via O_NOFOLLOW."""
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size < 16:
            return False
        head = os.read(fd, 16)
        return head == SQLITE3_HEADER_MAGIC
    except OSError:
        return False
    finally:
        if fd >= 0:
            os.close(fd)


def inspect_chromium_storage_path(
    target: Path,
    max_mb: int = 64,
    schema_mode: str = "auto",
    redact: bool = True,
) -> Dict[str, Any]:
    """
    Zero-PII local precheck gate (`GO` / `PARTIAL` / `NO_GO_COMPACTED_OR_UNSUPPORTED`)
    for offline endpoint or forensic intake pre-screening.
    Never emits plaintext message content, filenames, or raw hashes in default masked mode.
    """
    if max_mb < 1:
        raise SafeDiagnosticError("--max-mb safety limit must be >= 1 MiB")
    try:
        target_st = os.lstat(target)
    except OSError as exc:
        if redact:
            raise OSError("Unable to access target path (OS path suppressed in masked mode)") from None
        raise FileNotFoundError(f"Target path does not exist: {target}") from exc

    if stat.S_ISLNK(target_st.st_mode):
        if redact:
            raise OSError("Refusing symbolic-link target path (OS path suppressed in masked mode)")
        raise OSError(f"Target path is a symbolic link: {target}")

    log_files: List[Path] = []
    ldb_files: List[Path] = []
    manifest_dirs: Dict[Path, Dict[str, Any]] = {}
    non_regular_sstable_entries = 0
    unreadable_or_symlink_logs = 0
    blob_files_count = 0
    sqlite_files_count = 0
    scanned_files = 0
    scan_truncated = False

    def _man_dir_entry(dp: Path) -> Dict[str, Any]:
        ent = manifest_dirs.get(dp)
        if ent is None:
            ent = {"current": None, "manifests": []}
            manifest_dirs[dp] = ent
        return ent

    def _is_sqlite_artifact(name_lower: str, suffix_lower: str) -> bool:
        return (
            suffix_lower in (".sqlite", ".sqlite3")
            or name_lower.endswith(("-wal", "-shm", ".sqlite-wal", ".sqlite3-wal"))
        )

    if stat.S_ISREG(target_st.st_mode):
        clean_target_name = target.name.rstrip(" .")
        suf = Path(clean_target_name).suffix.lower()
        name_low = clean_target_name.lower()
        if suf == ".log":
            log_files.append(target)
        elif suf in (".ldb", ".sst"):
            ldb_files.append(target)
        elif _is_sqlite_artifact(name_low, suf) or _has_sqlite3_magic(target):
            sqlite_files_count += 1
    elif stat.S_ISDIR(target_st.st_mode):
        target_is_blob_dir = target.name.rstrip(" .").lower().endswith(".blob")
        for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
            dirnames.sort()
            filenames.sort()
            cur_dp = Path(dirpath)
            try:
                rel_parts = cur_dp.relative_to(target).parts
            except ValueError:
                rel_parts = ()
            in_blob_subdir = target_is_blob_dir or any(
                pt.rstrip(" .").lower().endswith(".blob") for pt in rel_parts
            )

            for fname in filenames:
                if scanned_files >= MAX_PRECHECK_SCAN_FILES:
                    scan_truncated = True
                    dirnames[:] = []
                    break
                p = cur_dp / fname
                try:
                    pst = os.lstat(p)
                except OSError:
                    continue
                scanned_files += 1
                clean_fname = fname.rstrip(" .")
                suf = Path(clean_fname).suffix.lower()
                name_low = clean_fname.lower()
                if not stat.S_ISREG(pst.st_mode):
                    if suf == ".log":
                        unreadable_or_symlink_logs += 1
                    elif suf in (".ldb", ".sst"):
                        non_regular_sstable_entries += 1
                    elif in_blob_subdir or suf == ".blob":
                        blob_files_count += 1
                    elif _is_sqlite_artifact(name_low, suf):
                        sqlite_files_count += 1
                    elif clean_fname.upper() == "CURRENT" or _MANIFEST_NAME_RE.match(clean_fname):
                        _man_dir_entry(cur_dp)["non_regular"] = True
                    continue
                if suf == ".log":
                    log_files.append(p)
                elif suf in (".ldb", ".sst"):
                    ldb_files.append(p)
                elif clean_fname.upper() == "CURRENT":
                    _man_dir_entry(cur_dp)["current"] = p
                elif m_man := _MANIFEST_NAME_RE.match(clean_fname):
                    _man_dir_entry(cur_dp)["manifests"].append((int(m_man.group(1)), p))
                elif in_blob_subdir or suf == ".blob":
                    blob_files_count += 1
                elif _is_sqlite_artifact(name_low, suf) or _has_sqlite3_magic(p):
                    sqlite_files_count += 1
            if scan_truncated:
                break

            kept_dirs: List[str] = []
            for dname in list(dirnames):
                clean_dname = dname.rstrip(" .")
                dlow = clean_dname.lower()
                dsuf = Path(clean_dname).suffix.lower()
                if dsuf in (".ldb", ".sst"):
                    non_regular_sstable_entries += 1
                    scanned_files += 1
                elif dsuf == ".blob" or dlow.endswith(".blob"):
                    blob_files_count += 1
                    scanned_files += 1
                    kept_dirs.append(dname)
                elif _is_sqlite_artifact(dlow, dsuf):
                    sqlite_files_count += 1
                    scanned_files += 1
                else:
                    if scanned_files >= MAX_PRECHECK_SCAN_FILES:
                        scan_truncated = True
                        break
                    scanned_files += 1
                    kept_dirs.append(dname)
            if scan_truncated:
                dirnames[:] = []
                break
            dirnames[:] = kept_dirs
    else:
        if redact:
            raise OSError("Target path must be a regular file or directory (OS path suppressed in masked mode)")
        raise OSError(f"Target path is neither a regular file nor a directory: {target}")

    valid_wal_frames = 0
    wal_corrupted_frames = 0
    wal_tombstone_ops = 0
    carvable_records = 0
    soft_deleted_records = 0
    v8_binary_only_values = 0
    oversize_logs_skipped = 0
    schemas_seen: Dict[str, int] = {}

    generic_fallback_total = 0
    probe_generic = schema_mode == "auto"

    for lf in log_files:
        try:
            raw_log = read_bounded_bytes(lf, max_mb=max_mb, redact=redact, nofollow=True)
        except ValueError:
            oversize_logs_skipped += 1
            continue
        except OSError:
            unreadable_or_symlink_logs += 1
            continue
        if not raw_log:
            continue
        parsed = parse_leveldb_wal(raw_log, schema_mode=schema_mode, probe_generic_fallback=probe_generic)
        valid_wal_frames += parsed["valid_physical_frames"]
        wal_corrupted_frames += parsed["corrupted_frames_count"]
        wal_tombstone_ops += parsed["writebatch_tombstone_ops_seen"]
        carvable_records += parsed["recovered_records_count"]
        v8_binary_only_values += parsed["blink_v8_non_json_values_skipped"]
        generic_fallback_total += parsed.get("generic_fallback_records_count", 0)
        for rec in parsed["recovered_records"]:
            st = str(rec.get("schema_detected", "unknown"))
            schemas_seen[st] = schemas_seen.get(st, 0) + 1
            if rec.get("is_soft_deleted_in_ui"):
                soft_deleted_records += 1

    from starshield.leveldb_sstable import (
        MAX_SUBSTORES_RECONCILED,
        _parse_numeric_file_stem,
        make_store_budget,
        parse_leveldb_manifest,
        parse_leveldb_sstable,
    )

    present_ldb_nums_by_dir: Dict[Path, set[int]] = {}
    for sf_p in ldb_files:
        fnum_p = _parse_numeric_file_stem(sf_p.name)
        if fnum_p is not None:
            present_ldb_nums_by_dir.setdefault(sf_p.parent, set()).add(fnum_p)

    present_log_nums_by_dir: Dict[Path, set[int]] = {}
    for lf_p in log_files:
        lnum_p = _parse_numeric_file_stem(lf_p.name)
        if lnum_p is not None:
            present_log_nums_by_dir.setdefault(lf_p.parent, set()).add(lnum_p)

    manifest_corrupted_or_missing = 0
    for _m_dp, m_ent in manifest_dirs.items():
        if m_ent.get("non_regular"):
            manifest_corrupted_or_missing += 1
            continue
        cur_p = m_ent["current"]
        mans: List[Tuple[int, Path]] = m_ent["manifests"]
        chosen_man: Path | None = None
        if cur_p is not None:
            try:
                cur_target = (
                    read_bounded_bytes(cur_p, max_mb=1, redact=redact, nofollow=True)
                    .decode("utf-8", errors="ignore")
                    .rstrip("\r\n")
                    .rstrip(" .")
                )
                for _mn, mp in mans:
                    if mp.name.rstrip(" .") == cur_target:
                        chosen_man = mp
                        break
                if chosen_man is None:
                    manifest_corrupted_or_missing += 1
            except (OSError, ValueError):
                manifest_corrupted_or_missing += 1
        elif mans:
            mans.sort(key=lambda x: x[0])
            chosen_man = mans[-1][1]

        if chosen_man is not None:
            try:
                m_raw = read_bounded_bytes(chosen_man, max_mb=max_mb, redact=redact, nofollow=True)
                m_sum = parse_leveldb_manifest(m_raw)
                if m_sum["corrupted_frames_count"] > 0 or m_sum["version_edits_applied"] == 0:
                    manifest_corrupted_or_missing += max(1, m_sum["corrupted_frames_count"])
                else:
                    act_fnums = set(m_sum["active_file_levels"].keys())
                    missing_fnums = act_fnums - present_ldb_nums_by_dir.get(_m_dp, set())
                    if missing_fnums:
                        manifest_corrupted_or_missing += len(missing_fnums)
                    m_log_num = m_sum["log_number"]
                    if m_log_num is not None and m_log_num > 0:
                        dir_logs = present_log_nums_by_dir.get(_m_dp, set())
                        if not any(ln >= m_log_num for ln in dir_logs):
                            manifest_corrupted_or_missing += 1
            except (OSError, ValueError):
                manifest_corrupted_or_missing += 1

    verified_sstables = 0
    unreadable_or_oversize_sstables = 0
    sstable_blocks_verified = 0
    sstable_corrupted_blocks = 0
    sstable_zstd_blocks = 0
    sstable_carvable_records = 0
    sstable_tombstone_entries = 0
    sst_budgets_by_dir: Dict[Path, Dict[str, int]] = {}
    global_precheck_budget = make_store_budget(
        snappy_bytes=128 * 1024 * 1024,
        materialized_bytes=256 * 1024 * 1024,
        max_ops=500_000,
    )
    seen_sst_inodes: Dict[Tuple[int, int, str], Dict[str, Any]] = {}

    for sf in ldb_files:
        if _has_leveldb_sstable_magic(sf):
            verified_sstables += 1
        if sf.parent not in sst_budgets_by_dir and len(sst_budgets_by_dir) >= MAX_SUBSTORES_RECONCILED:
            scan_truncated = True
            continue
        if (
            global_precheck_budget["remaining"] <= 0
            or global_precheck_budget["materialized_remaining"] <= 0
            or global_precheck_budget["ops_remaining"] <= 0
        ):
            scan_truncated = True
            continue
        try:
            sf_st = os.lstat(sf)
            inode_key = (sf_st.st_dev, sf_st.st_ino, schema_mode)
        except OSError:
            unreadable_or_oversize_sstables += 1
            continue
        if inode_key in seen_sst_inodes:
            sst_parsed = seen_sst_inodes[inode_key]
        else:
            try:
                raw_sst = read_bounded_bytes(sf, max_mb=max_mb, redact=redact, nofollow=True)
            except (ValueError, OSError):
                unreadable_or_oversize_sstables += 1
                continue
            sst_budget = sst_budgets_by_dir.get(sf.parent)
            if sst_budget is None:
                sst_budget = make_store_budget(
                    snappy_bytes=min(64 * 1024 * 1024, global_precheck_budget["remaining"]),
                    materialized_bytes=min(128 * 1024 * 1024, global_precheck_budget["materialized_remaining"]),
                    max_ops=min(250_000, global_precheck_budget["ops_remaining"]),
                )
                sst_budgets_by_dir[sf.parent] = sst_budget
            rem_before = sst_budget["remaining"]
            mat_before = sst_budget["materialized_remaining"]
            ops_before = sst_budget["ops_remaining"]
            sst_parsed = parse_leveldb_sstable(
                raw_sst,
                schema_mode=schema_mode,
                budget_state=sst_budget,
                probe_generic_fallback=probe_generic,
            )
            global_precheck_budget["remaining"] -= max(0, rem_before - sst_budget["remaining"])
            global_precheck_budget["materialized_remaining"] -= max(0, mat_before - sst_budget["materialized_remaining"])
            global_precheck_budget["ops_remaining"] -= max(0, ops_before - sst_budget["ops_remaining"])
            if not sst_parsed["budget_exceeded"]:
                seen_sst_inodes[inode_key] = sst_parsed
        sstable_blocks_verified += sst_parsed["data_blocks_verified"]
        sstable_corrupted_blocks += sst_parsed["corrupted_blocks_count"]
        sstable_zstd_blocks += sst_parsed["zstd_unsupported_blocks_count"]
        sstable_tombstone_entries += sst_parsed["tombstone_entries_seen"]
        sstable_carvable_records += sst_parsed["recovered_records_count"]
        carvable_records += sst_parsed["recovered_records_count"]
        v8_binary_only_values += sst_parsed["blink_v8_non_json_values_skipped"]
        generic_fallback_total += sst_parsed.get("generic_fallback_records_count", 0)
        for rec in sst_parsed["recovered_records"]:
            st = str(rec.get("schema_detected", "unknown"))
            schemas_seen[st] = schemas_seen.get(st, 0) + 1
            if rec.get("is_soft_deleted_in_ui"):
                soft_deleted_records += 1

    generic_json_records_available = (
        generic_fallback_total if (schema_mode == "auto" and carvable_records == 0) else 0
    )

    total_sstables_detected = len(ldb_files) + non_regular_sstable_entries
    all_sstables_healthy = (
        non_regular_sstable_entries == 0
        and verified_sstables == len(ldb_files)
        and unreadable_or_oversize_sstables == 0
        and sstable_corrupted_blocks == 0
        and sstable_zstd_blocks == 0
        and manifest_corrupted_or_missing == 0
    )

    if (
        carvable_records > 0
        and wal_corrupted_frames == 0
        and all_sstables_healthy
        and v8_binary_only_values == 0
        and blob_files_count == 0
        and sqlite_files_count == 0
        and oversize_logs_skipped == 0
        and unreadable_or_symlink_logs == 0
        and not scan_truncated
    ):
        verdict = "GO"
        guidance = (
            "LevelDB .log / Snappy .ldb tables contain verified carvable records. "
            f"Eligible for immediate byte-offset-cited extraction under v{__version__}."
        )
    elif carvable_records > 0:
        verdict = "PARTIAL"
        guidance = (
            "Carvable records are recoverable from LevelDB .log / Snappy .ldb tables, alongside "
            "damaged/Zstandard SSTable blocks, MANIFEST/WAL corruption, external .blob entries, "
            "co-located SQLite storage files, binary-only Blink V8 values, oversize files, or "
            f"capped directory scans outside v{__version__} scope."
        )
    elif generic_json_records_available > 0:
        verdict = "PARTIAL"
        guidance = (
            f"Zero messaging/B2B auto-schema records found, but {generic_json_records_available} generic JSON "
            "or key-value record(s) (e.g. browser extension storage or custom app state) are carvable by "
            "re-running with `--schema generic-json` (`schema_mode='generic-json'`)."
        )
    else:
        verdict = "NO_GO_COMPACTED_OR_UNSUPPORTED"
        guidance = (
            "Zero carvable records found in LevelDB .log or Snappy .ldb files (storage may contain "
            "corrupted/Zstandard SSTables, be encoded solely in binary Blink V8 StructuredClone, be backed by "
            "co-located SQLite storage files such as newly created Chrome 156+ SQLite IndexedDB while "
            "existing LevelDB stores remain in LevelDB, or be empty). For binary Blink IndexedDB stores, "
            "use full Blink deserializers such as dfindexeddb or ccl_chromium_reader; for SQLite-backed "
            "stores, inspect with sqlite3."
        )

    out_report: Dict[str, Any] = {
        "epistemic_tier": "OBSERVED",
        "tool_version": f"starshield-forensics/{__version__}",
        "target_label": "[REDACTED_TARGET_PATH]" if redact else str(target),
        "schema_mode": schema_mode,
        "feasibility_verdict": verdict,
        "scan_capped_at_max_files": scan_truncated,
        "wal_log_files_detected": len(log_files),
        "wal_oversize_files_skipped": oversize_logs_skipped,
        "valid_wal_physical_frames": valid_wal_frames,
        "wal_corrupted_frames_count": wal_corrupted_frames,
        "wal_tombstone_ops_count": wal_tombstone_ops,
        "manifest_corrupted_or_missing_count": manifest_corrupted_or_missing,
        "carvable_json_records_count": carvable_records,
        "generic_json_records_available": generic_json_records_available,
        "soft_deleted_json_records_count": soft_deleted_records,
        "schemas_detected_counts": schemas_seen,
        "compacted_sstable_files_detected": total_sstables_detected,
        "verified_leveldb_sstables_count": verified_sstables,
        "sstable_data_blocks_verified": sstable_blocks_verified,
        "sstable_corrupted_blocks_count": sstable_corrupted_blocks,
        "sstable_zstd_unsupported_blocks_count": sstable_zstd_blocks,
        "sstable_carvable_records_count": sstable_carvable_records,
        "sstable_tombstone_entries_count": sstable_tombstone_entries,
        "indexeddb_blob_files_detected": blob_files_count,
        "sqlite_files_detected": sqlite_files_count,
        "blink_v8_non_json_values_detected": v8_binary_only_values,
        "intake_guidance": guidance,
    }
    return out_report
