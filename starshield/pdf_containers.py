# SPDX-FileCopyrightText: 2026 Ziqi Xiao
#
# SPDX-License-Identifier: MIT
"""
Structural PDF Container & Incremental Revision Provenance Inspector (`pdf_containers.py`).

Designed for offline ISO 32000-1 PDF container structure and incremental-revision inspection:
- Verifies `%PDF-x.y` container header within the leading 1024-byte window (ISO 32000-1).
- Records bounded `%%EOF` markers, `xref` table offsets, `/Type /XRef` stream offsets, and
  64-bit-bounded `startxref` pointers to surface multi-revision incremental saves
  (`incremental_revision_count`, `has_multiple_revisions`).
- Extracts `/Producer`, `/Creator`, `/Author`, `/Title`, `/Subject`, `/CreationDate`, `/ModDate`
  from raw Info dictionaries and decoded streams (`/Type /ObjStm`, unfiltered, `/FlateDecode`,
  `/ASCIIHexDecode`, `/ASCII85Decode`) via a C-accelerated O(N) lexical scanner (honoring `%`
  comments, ISO 32000-1 §7.3.5 `#xx` Name hex escapes, §7.3.4.2 balanced nested parentheses,
  octal/backslash escapes, and UTF-16BE / UTF-16LE / UTF-8 BOMs), capped at
  `MAX_INFO_VALUES_PER_KEY = 64`.
- Validates `/Length N` against structural `endstream`/`endobj` boundaries and post-EOF trailing
  data so lying `/Length` values cannot swallow subsequent PDF objects into skipped binary spans.
- Flags structural risk indicators (`/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFiles`,
  `/OpenAction`, `/AcroForm`, `obfuscated_name_tokens`, and `undecoded_filter_streams`) with
  mandatory benign `alternative_explanations`.
- Masked-mode privacy invariant (`apply_pdf_redaction(..., redact=True)`): returns a deep copy
  suppressing `artifact`, `file_size_bytes`, `header_offset`, `trailing_bytes_after_final_eof`,
  structural offset arrays (`eof_offsets`, `startxref_offsets`, `xref_offsets`,
  `xref_stream_offsets`), XMP/error offsets, timestamps, and raw metadata strings.
"""

from __future__ import annotations

import base64
import codecs
import copy
import re
import zlib
from typing import Any, Callable, Dict, List

from starshield.ioc_validators import DEFAULT_EPHEMERAL_SALT, mask_identifier

MAX_PDF_STREAM_BYTES = 16 * 1024 * 1024  # 16 MiB single-stream anti-zip-bomb limit
MAX_TOTAL_DECOMPRESSED_BYTES = 32 * 1024 * 1024  # 32 MiB cumulative per-file decompression budget
DECOMPRESS_STEP_BYTES = 64 * 1024  # 64 KiB incremental inflate step for mid-stream error accounting
MAX_FILTER_CHAIN_DEPTH = 8  # Maximum chained stream filters per stream dictionary
MAX_XMP_PACKET_BYTES = 1 * 1024 * 1024  # 1 MiB single XMP packet scan limit
MAX_XMP_PACKETS = 256  # Object-graph amplification cap across raw + compressed XMP packets
MAX_INFO_VALUES_PER_KEY = 64  # Output-amplification cap per Info metadata key
MAX_PDF_STRING_SCAN_BYTES = 4096  # Bounded per-value Info literal/hex string scan window
MAX_STREAM_DICT_BYTES = 1 * 1024 * 1024  # 1 MiB safety cap on enclosing `<< ... >>` stream dictionaries
MAX_UNCLOSED_RECOVERY_BUDGET = 4 * 1024 * 1024  # 4 MiB cumulative amortized budget for unclosed-`(` recovery
MAX_CONTAINER_MARKERS = 2048  # Bounded cap on stored structural offset arrays
MAX_CONTAINER_ERRORS = 128  # Bounded cap on stored container_errors entries
MAX_STARTXREF_DIGITS = 18  # Bounded <= 18 significant decimal digits (< 2^63 - 1)

# ISO 32000-1 §7.2.2 lexical character classes
_PDF_WS_BYTES = frozenset(b"\x00\t\n\x0c\r ")
_PDF_WS_STRIP = b"\x00\t\n\x0c\r "
_PDF_DELIM_BYTES = frozenset(b"()<>[]{}/%")
_PDF_WS_OR_DELIM = _PDF_WS_BYTES | _PDF_DELIM_BYTES
_HEX_DIGIT_BYTES = frozenset(b"0123456789ABCDEFabcdef")
_HEX_OR_WS_BYTES = _HEX_DIGIT_BYTES | _PDF_WS_BYTES
_ASCII_WORD_BYTES = frozenset(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")

_ESC_MAP = {
    ord("n"): 10,
    ord("r"): 13,
    ord("t"): 9,
    ord("b"): 8,
    ord("f"): 12,
    ord("("): ord("("),
    ord(")"): ord(")"),
    ord("\\"): ord("\\"),
}

_PDF_HEADER_RE = re.compile(rb"%PDF-(\d+\.\d+)")
_XREF_STREAM_RE = re.compile(
    rb"/(?:T|#54)(?:y|#79)(?:p|#70)(?:e|#65)"
    rb"[\x00\t\n\x0c\r ]*"
    rb"/(?:X|#58)(?:R|#52)(?:e|#65)(?:f|#66)"
    rb"(?=[\x00\t\n\x0c\r ()<>\[\]{}/%]|$)"
)
_TOP_PDF_LEX_RE = re.compile(
    rb"\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|\b(?:endobj|xref|trailer|startxref)\b|<<|>>|[()%\[\]<>]"
)
_OBJ_BOUND_LEX_RE = re.compile(
    rb"(?:%[^\r\n]*[\r\n]?|\([^()\\\r\n]*\))+|"
    rb"\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|\bendobj\b|<<|[%(<]"
)
_REAL_XREF_SUBSECT_RE = re.compile(
    rb"(?:[\x00\t\n\x0c\r ]|%[^\r\n]*[\r\n])+\d{1,10}(?:[\x00\t\n\x0c\r ]|%[^\r\n]*[\r\n])+\d{1,10}(?=[\x00\t\n\x0c\r %])"
)
_STR_PDF_LEX_RE = re.compile(rb"(?:\\.)+|[()]", re.DOTALL)

# C-compiled linear scanners eliminating unbounded dual find(b"\n")+find(b"\r") scans and slice copies
_EOL_RE = re.compile(rb"[\r\n]")
_NON_PDF_WS_RE = re.compile(rb"[^\x00\t\n\x0c\r ]")
_LIT_SPECIAL_RE = re.compile(rb"[\\()]")
_NON_HEX_WS_RE = re.compile(rb"[^0-9A-Fa-f\x00\t\n\x0c\r ]")
_FAST_INTERESTING_RE = re.compile(
    rb"/(?:Producer|Creator|Author|Title|Subject|CreationDate|ModDate|"
    rb"JS|JavaScript|Launch|EmbeddedFiles?|OpenAction|AcroForm)"
    rb"(?=[\x00\t\n\x0c\r ()<>\[\]{}/%]|$)|"
    rb"/[^\x00\t\n\x0c\r ()<>\[\]{}/%#]*#"
)
_LEX_TRIGGER_RE = re.compile(
    rb"(?:%[^\r\n]*[\r\n]?|\([^()\\\r\n]*\))+|"
    rb"<<|>>|\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|\bendobj\b|\bendstream\b|"
    rb"[%(<]|"
    rb"/(?:Producer|Creator|Author|Title|Subject|CreationDate|ModDate|"
    rb"JS|JavaScript|Launch|EmbeddedFiles?|OpenAction|AcroForm)"
    rb"(?=[\x00\t\n\x0c\r ()<>\[\]{}/%]|$)|"
    rb"/[^\x00\t\n\x0c\r ()<>\[\]{}/%#]*#"
)
_TRACKER_LEX_RE = re.compile(
    rb"<<|>>|\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|\bendobj\b|\bendstream\b|"
    rb"(?:\([^()\\\r\n]*\))+|(?:%[^\r\n]*[\r\n])+|[%(<]"
)
_SIMPLE_DICT_RE = re.compile(rb"<<[^<>()%]*>>")
_SUBDICT_SKIP_RE = re.compile(rb"<<|>>|(?:\([^()\\\r\n]*\))+|(?:%[^\r\n]*[\r\n]?)+|[%(<]")
_ARRAY_SKIP_RE = re.compile(rb"<<|>>|\[|\]|(?:\([^()\\\r\n]*\))+|(?:%[^\r\n]*[\r\n]?)+|[%(<]")
_TOP_RESET_RE = re.compile(
    rb"(?:^|[\x00\t\n\x0c\r >)\]])(?P<kw>\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|endobj\b|endstream\b)"
)
_STAGE2_OBJ_RESYNC_RE = re.compile(
    rb"(?:>>[\x00\t\n\x0c\r ]*(?P<stkw>stream\r?\n)|(?:^|[\x00\t\n\x0c\r >)\]])(?P<kw>\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|endobj\b|endstream\b))"
)
_NAME_BODY_END_RE = re.compile(rb"[\x00\t\n\x0c\r ()<>\[\]{}/%]")
_AFTER_ENDSTREAM_STRUCT_RE = re.compile(
    rb"^(?:endobj\b|[0-9]+[\x00\t\n\x0c\r ]+[0-9]+[\x00\t\n\x0c\r ]+obj\b|xref\b|trailer\b|startxref\b|%%EOF)"
)
_EMBEDDED_PDF_OBJ_RE = re.compile(
    rb"(?:^|[\x00\t\n\x0c\r >)\]])(?P<kw>\d{1,10}[\x00\t\n\x0c\r ]+\d{1,5}[\x00\t\n\x0c\r ]+obj\b|endobj\b|trailer\b|startxref\b)"
)

_INFO_KEYS = ("Producer", "Creator", "Author", "Title", "Subject", "CreationDate", "ModDate")
_INFO_KEY_BYTES_MAP: Dict[bytes, str] = {k.encode("ascii"): k for k in _INFO_KEYS}

_RISK_NAME_MAP: Dict[bytes, str] = {
    b"JS": "js_actions",
    b"JavaScript": "js_actions",
    b"Launch": "launch_actions",
    b"EmbeddedFile": "embedded_files",
    b"EmbeddedFiles": "embedded_files",
    b"OpenAction": "open_actions",
    b"AcroForm": "acroforms",
}

_SUPPORTED_DECODE_FILTERS = frozenset(
    {
        b"FlateDecode",
        b"Fl",
        b"ASCIIHexDecode",
        b"AHx",
        b"ASCII85Decode",
        b"A85",
    }
)

_PURE_IMAGE_FILTERS = frozenset(
    {
        b"DCTDecode",
        b"DCT",
        b"JPXDecode",
        b"CCITTFaxDecode",
        b"CCF",
        b"JBIG2Decode",
    }
)

_SENSITIVE_PDF_NAMES = frozenset(
    set(_INFO_KEY_BYTES_MAP.keys())
    | set(_RISK_NAME_MAP.keys())
    | _SUPPORTED_DECODE_FILTERS
    | {
        b"Filter",
        b"Length",
        b"Type",
        b"XRef",
        b"ObjStm",
        b"LZWDecode",
        b"LZW",
        b"RunLengthDecode",
        b"RL",
        b"Crypt",
        b"Action",
        b"AA",
        b"URI",
        b"SubmitForm",
        b"ImportData",
        b"RichMedia",
        b"Names",
    }
)


def _decode_pdf_name_token(raw_name_body: bytes) -> tuple[bytes, bool]:
    """
    Normalize ISO 32000-1 §7.3.5 `#xx` hex escapes inside a PDF `/Name` body (without leading `/`).

    Returns `(normalized_bytes, had_valid_hex_escape)`. `#00` is forbidden in PDF 1.7 names and
    is left unescaped so NUL bytes can never be injected into token comparisons.
    """
    if b"#" not in raw_name_body:
        return raw_name_body, False
    out = bytearray()
    had_esc = False
    i = 0
    n = len(raw_name_body)
    while i < n:
        ch = raw_name_body[i]
        if (
            ch == 0x23  # '#'
            and i + 2 < n
            and raw_name_body[i + 1] in _HEX_DIGIT_BYTES
            and raw_name_body[i + 2] in _HEX_DIGIT_BYTES
        ):
            byte_val = int(raw_name_body[i + 1 : i + 3].decode("ascii"), 16)
            if byte_val != 0:
                out.append(byte_val)
                had_esc = True
                i += 3
                continue
        out.append(ch)
        i += 1
    return bytes(out), had_esc


def _scan_pdf_literal_string(
    buf: bytes,
    open_paren_pos: int,
    max_scan: int = MAX_PDF_STRING_SCAN_BYTES,
) -> tuple[int, bool]:
    """
    C-accelerated scanner for a `(...)` literal string bounded at `max_scan` bytes.

    Returns `(end_offset, closed_ok)` using `_LIT_SPECIAL_RE` to jump directly across plain bytes.
    """
    n = len(buf)
    scan_limit = min(n, open_paren_pos + 1 + max_scan)
    depth = 1
    i = open_paren_pos + 1
    while i < scan_limit:
        m = _LIT_SPECIAL_RE.search(buf, i, scan_limit)
        if m is None:
            return scan_limit, False
        idx = m.start()
        ch = buf[idx]
        if ch == 0x5C:  # backslash escape
            if idx + 1 >= scan_limit:
                return scan_limit, False
            nxt = buf[idx + 1]
            if nxt == 13 and idx + 2 < scan_limit and buf[idx + 2] == 10:
                i = idx + 3
            elif 0x30 <= nxt <= 0x37:
                j = idx + 2
                end_oct = min(idx + 4, scan_limit)
                while j < end_oct and 0x30 <= buf[j] <= 0x37:
                    j += 1
                i = j
            else:
                i = idx + 2
            continue
        if ch == 0x28:  # '('
            depth += 1
            i = idx + 1
        else:  # ')'
            depth -= 1
            if depth == 0:
                return idx + 1, True
            i = idx + 1
    return i, False


def _skip_pdf_literal_string(buf: bytes, open_paren_pos: int, max_scan: int = MAX_PDF_STRING_SCAN_BYTES) -> int:
    """Return the post-literal byte offset from `_scan_pdf_literal_string`."""
    end_pos, _closed = _scan_pdf_literal_string(buf, open_paren_pos, max_scan=max_scan)
    return end_pos


def _decompress_flate_stream(
    comp_data: bytes | memoryview,
    max_len: int = MAX_PDF_STREAM_BYTES,
) -> tuple[str, int, int, bytes]:
    """
    Incremental input-and-output-chunked zlib decompressor that never allocates `max_len + 1`.

    Feeds `comp_data` in progressive slices (`1 KiB` initial, then `64 KiB`) so CPython's
    `dobj.unused_data` never copies multi-megabyte trailing buffers on nested/unclosed streams.
    """
    dobj = zlib.decompressobj()
    total_in = len(comp_data)
    has_zlib_hdr = (
        total_in >= 2
        and (comp_data[0] & 0x0F) == 8
        and (((comp_data[0] << 8) | comp_data[1]) % 31) == 0
    )
    produced_total = 0

    try:
        if max_len <= 0:
            first_slice = comp_data[: min(total_in, 256)]
            probe = dobj.decompress(first_slice, 1)
            if probe or dobj.unconsumed_tail:
                consumed = len(first_slice) - len(dobj.unconsumed_tail)
                return "limit", len(probe), consumed, b""
            if not dobj.eof:
                tail = dobj.flush()
                if tail:
                    return "limit", len(tail), len(first_slice), b""
                return "corrupt", (DECOMPRESS_STEP_BYTES if has_zlib_hdr else 0), total_in, b""
            return "ok", 0, len(first_slice) - len(dobj.unused_data), b""

        # Fast zero-list path for small streams finishing within the initial 64-byte input slice
        first_end = min(total_in, 64)
        first_slice = comp_data[:first_end]
        first_cap = min(DECOMPRESS_STEP_BYTES, max_len)
        first_part = dobj.decompress(first_slice, first_cap)
        produced_total = len(first_part)
        if dobj.eof:
            return "ok", produced_total, first_end - len(dobj.unused_data), first_part

        chunks: List[bytes] = [first_part] if first_part else []
        in_offset = 0
        in_end = first_end
        pending: bytes | memoryview = dobj.unconsumed_tail

        while pending and produced_total < max_len:
            step_cap = min(DECOMPRESS_STEP_BYTES, max_len - produced_total)
            part = dobj.decompress(pending, step_cap)
            if part:
                chunks.append(part)
                produced_total += len(part)
            pending = dobj.unconsumed_tail
            if dobj.eof or (not part and not pending):
                break

        if not pending and not dobj.eof:
            in_offset = first_end
            while in_offset < total_in and not dobj.eof and produced_total < max_len:
                in_end = min(total_in, in_offset + DECOMPRESS_STEP_BYTES)
                pending = comp_data[in_offset:in_end]
                while pending and produced_total < max_len:
                    step_cap = min(DECOMPRESS_STEP_BYTES, max_len - produced_total)
                    part = dobj.decompress(pending, step_cap)
                    if part:
                        chunks.append(part)
                        produced_total += len(part)
                    pending = dobj.unconsumed_tail
                    if dobj.eof or (not part and not pending):
                        break
                if pending or dobj.eof:
                    break
                in_offset = in_end

        if not dobj.eof:
            if pending:
                probe = dobj.decompress(pending, 1)
                if probe or dobj.unconsumed_tail:
                    consumed = in_end - len(dobj.unconsumed_tail)
                    return "limit", produced_total + len(probe), consumed, b""
                in_offset = in_end
            while in_offset < total_in and not dobj.eof:
                in_end = min(total_in, in_offset + 4096)
                nxt_slice = comp_data[in_offset:in_end]
                probe = dobj.decompress(nxt_slice, 1)
                if probe or dobj.unconsumed_tail:
                    consumed = in_end - len(dobj.unconsumed_tail)
                    return "limit", produced_total + len(probe), consumed, b""
                in_offset = in_end

        if not dobj.eof:
            tail = dobj.flush()
            if tail:
                if produced_total + len(tail) > max_len:
                    return "limit", produced_total + len(tail), in_end - len(dobj.unused_data), b""
                chunks.append(tail)
                produced_total += len(tail)

        if not dobj.eof:
            charged = produced_total if produced_total > 0 else (DECOMPRESS_STEP_BYTES if has_zlib_hdr else 0)
            return "corrupt", charged, total_in, b""

        consumed = in_end - len(dobj.unused_data)
        return "ok", produced_total, consumed, b"".join(chunks)
    except zlib.error:
        if produced_total > 0 or has_zlib_hdr:
            in_flight = min(DECOMPRESS_STEP_BYTES, max(1, max_len - produced_total))
            return "corrupt", produced_total + in_flight, 0, b""
        return "corrupt", 0, 0, b""


def _decode_ascii_hex_stream(
    comp_data: bytes | memoryview,
    max_len: int = MAX_PDF_STREAM_BYTES,
    *,
    raw_buf: bytes | None = None,
    raw_start: int = 0,
    raw_end: int = 0,
) -> tuple[str, int, int, bytes]:
    """Decode ISO 32000-1 §7.4.2 `/ASCIIHexDecode` (`/AHx`) stopping at `>` EOD without O(N^2) copies."""
    if raw_buf is not None:
        eod_abs = raw_buf.find(b">", raw_start, raw_end)
        span_end = eod_abs if eod_abs != -1 else raw_end
        consumed = (eod_abs - raw_start + 1) if eod_abs != -1 else (raw_end - raw_start)
        if _NON_HEX_WS_RE.search(raw_buf, raw_start, span_end) is not None:
            return "corrupt", min(span_end - raw_start, DECOMPRESS_STEP_BYTES), 0, b""
        body = raw_buf[raw_start:span_end]
    else:
        raw_b = comp_data if isinstance(comp_data, bytes) else bytes(comp_data)
        eod = raw_b.find(b">")
        body = raw_b[:eod] if eod != -1 else raw_b
        consumed = (eod + 1) if eod != -1 else len(raw_b)
        if _NON_HEX_WS_RE.search(body) is not None:
            return "corrupt", min(len(body), DECOMPRESS_STEP_BYTES), 0, b""

    compact = body.translate(None, _PDF_WS_STRIP)
    out_len = (len(compact) + 1) // 2
    if out_len > max_len:
        return "limit", max_len + 1, consumed, b""
    if not compact:
        return "ok", 0, consumed, b""
    if len(compact) % 2 == 1:
        compact += b"0"
    try:
        dec = bytes.fromhex(compact.decode("ascii"))
    except ValueError:
        return "corrupt", out_len, 0, b""
    return "ok", len(dec), consumed, dec


def _decode_ascii85_stream(
    comp_data: bytes | memoryview,
    max_len: int = MAX_PDF_STREAM_BYTES,
    *,
    raw_buf: bytes | None = None,
    raw_start: int = 0,
    raw_end: int = 0,
) -> tuple[str, int, int, bytes]:
    """Decode ISO 32000-1 §7.4.3 `/ASCII85Decode` (`/A85`) stopping at `~>` EOD without O(N^2) copies."""
    if raw_buf is not None:
        eod_abs = raw_buf.find(b"~>", raw_start, raw_end)
        span_end = eod_abs if eod_abs != -1 else raw_end
        consumed = (eod_abs - raw_start + 2) if eod_abs != -1 else (raw_end - raw_start)
        body = raw_buf[raw_start:span_end]
    else:
        raw_b = comp_data if isinstance(comp_data, bytes) else bytes(comp_data)
        eod = raw_b.find(b"~>")
        body = raw_b[:eod] if eod != -1 else raw_b
        consumed = (eod + 2) if eod != -1 else len(raw_b)

    compact = body.translate(None, _PDF_WS_STRIP)
    if compact.startswith(b"<~"):
        compact = compact[2:]
    if not compact:
        return "ok", 0, consumed, b""

    z_count = compact.count(b"z")
    other_count = len(compact) - z_count
    est_out = z_count * 4 + (other_count * 4) // 5
    if est_out > max_len:
        return "limit", max_len + 1, consumed, b""

    try:
        dec = base64.a85decode(compact, adobe=False)
    except ValueError:
        return "corrupt", min(max(est_out, 1), max_len), 0, b""

    if len(dec) > max_len:
        return "limit", len(dec), consumed, b""
    return "ok", len(dec), consumed, dec


def _decompress_bounded(comp_bytes: bytes, max_len: int = MAX_PDF_STREAM_BYTES) -> bytes:
    """Compatibility helper wrapping `_decompress_flate_stream` without allocating `max_len + 1`."""
    status, _unpacked, _consumed, data = _decompress_flate_stream(comp_bytes, max_len=max_len)
    if status == "limit":
        raise BufferError("Decompressed PDF stream exceeds safety limit")
    if status != "ok":
        raise zlib.error("Corrupted or truncated FlateDecode deflate stream")
    return data


def _skip_ws_and_comments(buf: bytes, start: int, end: int) -> int:
    """Advance past PDF whitespace and `%...EOL` comments in `buf[start:end]` using `_EOL_RE`."""
    p = start
    while p < end:
        ch = buf[p]
        if ch in _PDF_WS_BYTES:
            p += 1
        elif ch == 0x25:  # '%'
            m = _EOL_RE.search(buf, p + 1, end)
            if m is None:
                return end
            p = m.end()
        else:
            break
    return p


def _skip_pdf_dict_value(body: bytes, start: int, end: int) -> int:
    """
    Skip one arbitrary PDF value inside a dictionary body (`(...)`, `<...>`, `<<...>>`, `[...]`,
    `/Name`, primitive, or `N G R` indirect reference) in linear C-accelerated time.
    """
    p = _skip_ws_and_comments(body, start, end)
    if p >= end:
        return end

    ch = body[p]
    if ch == 0x28:  # '(' literal string
        end_lit, _ = _scan_pdf_literal_string(body, p, max_scan=end - p)
        return min(end, end_lit)

    if ch == 0x3C:  # '<<' nested sub-dictionary or '<hex>' string
        if body[p : p + 2] == b"<<":
            sub_depth = 1
            q = p + 2
            while q < end:
                m = _SUBDICT_SKIP_RE.search(body, q, end)
                if m is None:
                    return end
                ts = m.start()
                lead = body[ts]
                if lead == 0x3C:
                    if m.end() - ts == 2 and body[ts : ts + 2] == b"<<":
                        sub_depth += 1
                        q = ts + 2
                    else:
                        gt = body.find(b">", ts + 1, end)
                        q = (gt + 1) if gt != -1 else end
                elif lead == 0x3E:
                    sub_depth -= 1
                    q = ts + 2
                    if sub_depth == 0:
                        return q
                elif lead == 0x25:
                    q = m.end()
                elif tok_end := m.end():  # '(' batched flat `(...)` or nested `(`
                    if tok_end > ts + 1:
                        q = tok_end
                    else:
                        el, _ = _scan_pdf_literal_string(body, ts, max_scan=end - ts)
                        q = min(end, el)
            return end
        gt = body.find(b">", p + 1, end)
        return (gt + 1) if gt != -1 else end

    if ch == 0x5B:  # '[' array
        arr_depth = 1
        q = p + 1
        while q < end:
            m = _ARRAY_SKIP_RE.search(body, q, end)
            if m is None:
                return end
            ts = m.start()
            lead = body[ts]
            if lead == 0x5B:  # '['
                arr_depth += 1
                q = ts + 1
            elif lead == 0x5D:  # ']'
                arr_depth -= 1
                q = ts + 1
                if arr_depth == 0:
                    return q
            elif lead in (0x3C, 0x3E):
                if m.end() - ts == 2:
                    q = ts + 2
                else:
                    gt = body.find(b">", ts + 1, end)
                    q = (gt + 1) if gt != -1 else end
            elif lead == 0x25:
                q = m.end()
            else:  # '('
                el, _ = _scan_pdf_literal_string(body, ts, max_scan=end - ts)
                q = min(end, el)
        return end

    if ch == 0x2F:  # '/Name'
        em = _NAME_BODY_END_RE.search(body, p + 1, end)
        return em.start() if em is not None else end

    # Primitive token (`true`, `false`, `null`, number, or `N G R` indirect reference)
    em = _NAME_BODY_END_RE.search(body, p, end)
    t1_end = em.start() if em is not None else end
    if t1_end > p and all(0x30 <= b <= 0x39 for b in body[p:t1_end]):
        q = _skip_ws_and_comments(body, t1_end, end)
        g_start = q
        while q < end and 0x30 <= body[q] <= 0x39:
            q += 1
        if q > g_start and (q >= end or body[q] in _PDF_WS_OR_DELIM):
            r_pos = _skip_ws_and_comments(body, q, end)
            if r_pos < end and body[r_pos] == ord("R") and (
                r_pos + 1 >= end or body[r_pos + 1] in _PDF_WS_OR_DELIM
            ):
                return r_pos + 1
    return t1_end if t1_end > p else p + 1


def _parse_stream_dict_header(
    dict_bytes: bytes,
) -> tuple[List[bytes], bool, int | None, bool]:
    """
    Parse `/Filter`, `/Length`, and `/Type /ObjStm` strictly at `dict_depth == 0` of `<< ... >>`.

    Skips `%...EOL` comments, `(...)` strings, `<hex>` strings, `[...]` arrays, and nested
    `<< ... >>` sub-dictionaries so `/Note (/Filter /DCTDecode /Length 9999)` or nested `/Sub`
    dictionaries never spoof outer stream header attributes.
    """
    if len(dict_bytes) < 4 or not dict_bytes.startswith(b"<<") or not dict_bytes.endswith(b">>"):
        return [], False, None, False

    body = dict_bytes[2:-2]
    m = len(body)
    filters: List[bytes] = []
    unresolvable_filter = False
    declared_len: int | None = None
    is_objstm = False

    p = 0
    while p < m:
        p = _skip_ws_and_comments(body, p, m)
        if p >= m:
            break
        if body[p] != 0x2F:  # Malformed non-Name token at dict_depth == 0
            nxt = _skip_pdf_dict_value(body, p, m)
            p = nxt if nxt > p else p + 1
            continue

        km = _NAME_BODY_END_RE.search(body, p + 1, m)
        key_end = km.start() if km is not None else m
        norm_key, _ = _decode_pdf_name_token(body[p + 1 : key_end])
        p = _skip_ws_and_comments(body, key_end, m)

        if norm_key == b"Filter":
            if p >= m:
                unresolvable_filter = True
                break
            if body[p] == 0x2F:  # `/Filter /Name`
                fm = _NAME_BODY_END_RE.search(body, p + 1, m)
                f_end = fm.start() if fm is not None else m
                norm_f, _ = _decode_pdf_name_token(body[p + 1 : f_end])
                if norm_f:
                    filters = [norm_f]
                else:
                    unresolvable_filter = True
                p = f_end
            elif body[p] == 0x5B:  # `/Filter [ /F1 /F2 ... ]`
                parsed_f: List[bytes] = []
                q = p + 1
                closed_arr = False
                bad_elem = False
                while q < m:
                    q = _skip_ws_and_comments(body, q, m)
                    if q >= m:
                        break
                    if body[q] == 0x5D:  # ']'
                        closed_arr = True
                        p = q + 1
                        break
                    if body[q] != 0x2F:
                        bad_elem = True
                        p = _skip_pdf_dict_value(body, p, m)
                        closed_arr = True
                        break
                    fm = _NAME_BODY_END_RE.search(body, q + 1, m)
                    f_end = fm.start() if fm is not None else m
                    norm_f, _ = _decode_pdf_name_token(body[q + 1 : f_end])
                    if norm_f:
                        parsed_f.append(norm_f)
                    else:
                        bad_elem = True
                    q = f_end
                if not closed_arr:
                    unresolvable_filter = True
                    p = m
                elif bad_elem:
                    unresolvable_filter = True
                    filters = parsed_f
                else:
                    filters = parsed_f
            else:
                unresolvable_filter = True
                p = _skip_pdf_dict_value(body, p, m)
        elif norm_key == b"Length":
            if p < m and 0x30 <= body[p] <= 0x39:
                d_start = p
                while p < m and 0x30 <= body[p] <= 0x39:
                    p += 1
                if p < m and body[p] not in _PDF_WS_OR_DELIM:
                    declared_len = None
                    p = _skip_pdf_dict_value(body, d_start, m)
                else:
                    q = _skip_ws_and_comments(body, p, m)
                    g_start = q
                    while q < m and 0x30 <= body[q] <= 0x39:
                        q += 1
                    is_indirect = False
                    if q > g_start and (q >= m or body[q] in _PDF_WS_OR_DELIM):
                        r_pos = _skip_ws_and_comments(body, q, m)
                        if r_pos < m and body[r_pos] == ord("R") and (
                            r_pos + 1 >= m or body[r_pos + 1] in _PDF_WS_OR_DELIM
                        ):
                            is_indirect = True
                            p = r_pos + 1
                    if is_indirect:
                        declared_len = None
                    else:
                        sig = body[d_start:p].lstrip(b"0")
                        if len(sig) <= MAX_STARTXREF_DIGITS:
                            declared_len = int(sig) if sig else 0
                        else:
                            declared_len = None
            else:
                declared_len = None
                p = _skip_pdf_dict_value(body, p, m)
        elif norm_key == b"Type":
            if p < m and body[p] == 0x2F:
                tm = _NAME_BODY_END_RE.search(body, p + 1, m)
                t_end = tm.start() if tm is not None else m
                norm_t, _ = _decode_pdf_name_token(body[p + 1 : t_end])
                if norm_t == b"ObjStm":
                    is_objstm = True
                p = t_end
            else:
                p = _skip_pdf_dict_value(body, p, m)
        else:
            nxt = _skip_pdf_dict_value(body, p, m)
            p = nxt if nxt > p else p + 1

    return filters, unresolvable_filter, declared_len, is_objstm


def _find_next_structural_endstream(raw: bytes, search_from: int) -> int:
    """
    Return byte offset of the first `endstream` at or after `search_from` followed by a structural
    PDF boundary (`endobj`, `N G obj`, `xref`, `trailer`, `startxref`, `%%EOF`), or `-1` if none.
    """
    n = len(raw)
    search_p = search_from
    while search_p < n:
        cand = raw.find(b"endstream", search_p)
        if cand == -1:
            return -1
        after_es = cand + 9
        if after_es < n and raw[after_es] not in _PDF_WS_OR_DELIM:
            search_p = after_es
            continue
        win_end = min(n, after_es + 128)
        nxt = _skip_ws_and_comments(raw, after_es, win_end)
        if _AFTER_ENDSTREAM_STRUCT_RE.match(raw[nxt:win_end]) is not None:
            return cand
        search_p = after_es
    return -1


def _find_earliest_stage2_resync(buf: bytes, s_start: int, s_end: int) -> int | None:
    """Fast `bytes.find` pre-filtered lookup for the earliest `N G obj` / `endobj` / `stream` / `endstream`."""
    if s_end - s_start < 6:
        return None
    has_obj = buf.find(b"obj", s_start, s_end) != -1
    has_str = buf.find(b"stream", s_start, s_end) != -1
    if not (has_obj or has_str):
        return None
    earliest: int | None = None
    for kw in (b"obj", b"stream"):
        cur = s_start
        kw_len = len(kw)
        while cur < s_end:
            hit = buf.find(kw, cur, s_end)
            if hit == -1:
                break
            win_lo = max(s_start, hit - 64)
            win_hi = min(s_end, hit + kw_len + 12)
            m = _STAGE2_OBJ_RESYNC_RE.search(buf, win_lo, win_hi)
            if m is not None:
                kw_off = m.start("kw") if m.group("kw") is not None else m.start("stkw")
                if kw_off >= s_start and (earliest is None or kw_off < earliest):
                    earliest = kw_off
                    break
            cur = hit + kw_len
    return earliest


def _find_embedded_pdf_obj_offset(raw: bytes, s_start: int, s_end: int) -> int | None:
    """
    Detect smuggled PDF object/trailer syntax (`N G obj`, `endobj`, `trailer`, `startxref`) inside
    `raw[s_start:s_end]` using C-level `bytes.find` pre-filters + `_EMBEDDED_PDF_OBJ_RE`.
    """
    span_len = s_end - s_start
    if span_len < 6:
        return None
    has_obj = raw.find(b"obj", s_start, s_end) != -1
    has_tr = span_len >= 7 and raw.find(b"trailer", s_start, s_end) != -1
    has_sx = span_len >= 9 and raw.find(b"startxref", s_start, s_end) != -1
    if not (has_obj or has_tr or has_sx):
        return None

    earliest: int | None = None
    for kw in (b"obj", b"trailer", b"startxref"):
        cur = s_start
        kw_len = len(kw)
        while cur < s_end:
            hit = raw.find(kw, cur, s_end)
            if hit == -1:
                break
            win_lo = max(s_start, hit - 64)
            win_hi = min(s_end, hit + kw_len + 4)
            m = _EMBEDDED_PDF_OBJ_RE.search(raw, win_lo, win_hi)
            if m is not None:
                kw_off = m.start("kw")
                if earliest is None or kw_off < earliest:
                    earliest = kw_off
                break
            cur = hit + kw_len
    return earliest


def _record_raw_stream_span(
    raw: bytes,
    s_start: int,
    s_end: int,
    raw_stream_spans: List[tuple[int, int]],
    add_error: Callable[[int | None, str], None],
    pos: int,
) -> None:
    """
    Guard skipped binary stream spans against embedded PDF object smuggling (`R3-H2`).

    If smuggled `N G obj` / `endobj` / `trailer` / `startxref` syntax is detected inside
    `raw[s_start:s_end]`, logs an error and leaves the smuggled object region unskipped so Stage 2
    still inspects all embedded `/OpenAction`, `/JavaScript`, `/AcroForm`, and Info keys.
    """
    span_len = s_end - s_start
    if span_len >= 6 and (
        raw.find(b"obj", s_start, s_end) != -1
        or (span_len >= 7 and raw.find(b"trailer", s_start, s_end) != -1)
        or (span_len >= 9 and raw.find(b"startxref", s_start, s_end) != -1)
    ):
        emb_off = _find_embedded_pdf_obj_offset(raw, s_start, s_end)
        if emb_off is not None:
            add_error(pos, "Embedded PDF object/trailer syntax detected inside stream body")
            if emb_off > s_start:
                raw_stream_spans.append((s_start, emb_off))
            return
    raw_stream_spans.append((s_start, s_end))


class _StreamDictTracker:
    """
    Monotonic O(N) forward lexical tracker for enclosing `<< ... >>` stream dictionaries.

    `self.lex_pos` strictly advances forward across the file so every non-stream byte is tokenized
    at most once, eliminating repeated backward window scans on adversarial decoy-stream inputs.
    """

    __slots__ = (
        "raw",
        "n",
        "lex_pos",
        "open_stack",
        "last_closed_dict",
        "unclosed_budget",
        "in_indirect_obj",
        "on_lex_error",
    )

    def __init__(
        self,
        raw: bytes,
        on_lex_error: Callable[[int | None, str], None] | None = None,
        *,
        start_pos: int = 0,
    ) -> None:
        self.raw = raw
        self.n = len(raw)
        self.lex_pos = max(0, start_pos)
        self.open_stack: List[int] = []
        self.last_closed_dict: tuple[int, int] | None = None
        self.unclosed_budget = MAX_UNCLOSED_RECOVERY_BUDGET
        self.in_indirect_obj = False
        self.on_lex_error = on_lex_error

    def reset_at(self, next_cursor: int) -> None:
        if next_cursor > self.lex_pos:
            self.lex_pos = next_cursor
        self.open_stack.clear()
        self.last_closed_dict = None
        self.in_indirect_obj = False

    def advance_to_stream(self, stream_pos: int) -> tuple[bytes | None, bool]:
        """Advance `lex_pos` up to `stream_pos` and return `(dict_bytes, exceeded_1mib_cap)`."""
        if self.lex_pos > stream_pos:
            return None, False

        raw = self.raw
        n = self.n
        lp = self.lex_pos
        if not self.open_stack and (stream_pos - lp) <= 256:
            if lp < stream_pos and raw[lp] in (0x0A, 0x0D):
                lp += 2 if raw[lp : lp + 2] == b"\r\n" else 1
            if raw[lp : lp + 2] == b"<<":
                sm = _SIMPLE_DICT_RE.match(raw, lp, stream_pos)
                if sm is not None:
                    de = sm.end()
                    gap = stream_pos - de
                    if (
                        (
                            gap == 0
                            or (gap == 1 and raw[de] in _PDF_WS_BYTES)
                            or (gap == 2 and raw[de:stream_pos] == b"\r\n")
                        )
                        and raw.find(b"end", lp + 2, de - 2) == -1
                    ):
                        self.last_closed_dict = (lp, de)
                        self.lex_pos = stream_pos
                        return raw[lp:de], False
        while self.lex_pos < stream_pos:
            m = _TRACKER_LEX_RE.search(raw, self.lex_pos, stream_pos)
            if m is None:
                self.lex_pos = stream_pos
                break
            tok_start = m.start()
            tok_end = m.end()
            lead = raw[tok_start]

            if lead == 0x25:  # '%' comment (batched complete lines or single unterminated '%')
                if raw[tok_end - 1] in (0x0A, 0x0D):
                    self.lex_pos = tok_end
                else:
                    eol_m = _EOL_RE.search(raw, tok_start + 1)
                    self.lex_pos = eol_m.end() if eol_m is not None else n
                    if self.lex_pos > stream_pos:
                        return None, False

            elif lead == 0x28:  # '(' literal string (batched single-line `(...)` or nested/escaped `(`)
                if not self.open_stack:
                    self.last_closed_dict = None
                if tok_end > tok_start + 1:
                    self.lex_pos = tok_end
                    continue
                if not self.open_stack:
                    resync_hi = min(stream_pos, tok_start + 1 + MAX_STREAM_DICT_BYTES)
                    resync_off = _find_earliest_stage2_resync(raw, tok_start + 1, resync_hi)
                    if not self.in_indirect_obj:
                        dict_cand = raw.find(b"<<", tok_start + 1, resync_hi)
                        if dict_cand != -1 and (resync_off is None or dict_cand < resync_off):
                            resync_off = dict_cand
                    if resync_off is not None:
                        sub_end, sub_closed = _scan_pdf_literal_string(
                            raw,
                            tok_start,
                            max_scan=max(0, resync_off - tok_start - 1),
                        )
                        if not sub_closed:
                            if self.on_lex_error is not None:
                                self.on_lex_error(
                                    tok_start,
                                    "Unterminated top-level PDF literal string before stream/object boundary (resynchronized)",
                                )
                            self.lex_pos = resync_off
                            continue
                        self.lex_pos = sub_end
                        continue
                max_lit = MAX_STREAM_DICT_BYTES if self.open_stack else MAX_PDF_STRING_SCAN_BYTES
                end_lit, closed_lit = _scan_pdf_literal_string(raw, tok_start, max_scan=max_lit)
                if closed_lit:
                    self.lex_pos = end_lit
                    if self.lex_pos > stream_pos:
                        return None, False
                else:
                    self.open_stack.clear()
                    self.last_closed_dict = None
                    scanned = max(1, end_lit - tok_start)
                    if self.unclosed_budget > 0:
                        self.unclosed_budget -= scanned
                        reset_m = _TOP_RESET_RE.search(raw, tok_start + 1, min(end_lit, stream_pos))
                        if reset_m is not None:
                            self.lex_pos = reset_m.end()
                            continue
                    self.lex_pos = end_lit
                    if self.lex_pos > stream_pos:
                        return None, False

            elif lead == 0x3C:  # '<<' or '<'
                if tok_end - tok_start == 2 and raw[tok_start : tok_start + 2] == b"<<":
                    if not self.open_stack:
                        sm = _SIMPLE_DICT_RE.match(raw, tok_start, stream_pos)
                        if sm is not None and raw.find(b"end", tok_start + 2, sm.end() - 2) == -1:
                            self.last_closed_dict = (tok_start, sm.end())
                            self.lex_pos = sm.end()
                            continue
                        self.last_closed_dict = None
                    self.open_stack.append(tok_start)
                    self.lex_pos = tok_start + 2
                else:
                    if not self.open_stack:
                        self.last_closed_dict = None
                    nm = _NON_HEX_WS_RE.search(
                        raw,
                        tok_start + 1,
                        min(n, tok_start + MAX_STREAM_DICT_BYTES + 1),
                    )
                    if nm is not None and raw[nm.start()] == 0x3E:
                        self.lex_pos = nm.start() + 1
                    else:
                        self.lex_pos = tok_start + 1
                    if self.lex_pos > stream_pos:
                        return None, False

            elif lead == 0x3E:  # '>>'
                if self.open_stack:
                    d_open = self.open_stack.pop()
                    if not self.open_stack:
                        self.last_closed_dict = (d_open, tok_start + 2)
                else:
                    self.last_closed_dict = None
                self.lex_pos = tok_start + 2

            else:  # 'N G obj' / 'endobj' / 'endstream'
                if tok_start == 0 or (
                    raw[tok_start - 1] in _PDF_WS_OR_DELIM and raw[tok_start - 1] != 0x2F
                ):
                    self.open_stack.clear()
                    self.last_closed_dict = None
                    tok_bytes = raw[tok_start:tok_end]
                    if tok_bytes == b"endobj":
                        self.in_indirect_obj = False
                    elif tok_bytes != b"endstream" and tok_bytes.endswith(b"obj"):
                        self.in_indirect_obj = True
                self.lex_pos = tok_end

        if self.open_stack or self.last_closed_dict is None:
            return None, False

        d_open, d_close = self.last_closed_dict
        if d_close != stream_pos:
            gap = stream_pos - d_close
            if not (
                (gap == 1 and raw[d_close] in _PDF_WS_BYTES)
                or (gap == 2 and raw[d_close : stream_pos] == b"\r\n")
                or _skip_ws_and_comments(raw, d_close, stream_pos) == stream_pos
            ):
                self.last_closed_dict = None
                return None, False

        if (d_close - d_open) > MAX_STREAM_DICT_BYTES:
            self.last_closed_dict = None
            return None, True

        return raw[d_open:d_close], False


def _decode_pdf_bytes_text(data: bytes) -> str:
    """Decode raw PDF string bytes handling UTF-16BE, UTF-16LE, UTF-8 BOMs, or PDFDocEncoding/Latin-1."""
    if data.startswith(codecs.BOM_UTF16_BE):
        return data[2:].decode("utf-16-be", errors="replace").strip("\x00 \t\r\n")
    if data.startswith(codecs.BOM_UTF16_LE):
        return data[2:].decode("utf-16-le", errors="replace").strip("\x00 \t\r\n")
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace").strip("\x00 \t\r\n")
    return data.decode("latin-1", errors="replace").strip("\x00 \t\r\n")


def _decode_pdf_literal(raw_bytes: bytes) -> str:
    """Decode ISO 32000-1 §7.3.4.2 PDF literal string content (escapes, octal, line continuation, BOM)."""
    out = bytearray()
    i = 0
    n = len(raw_bytes)
    while i < n:
        ch = raw_bytes[i]
        if ch == 0x5C:
            if i + 1 >= n:
                break
            nxt = raw_bytes[i + 1]
            if nxt in _ESC_MAP:
                out.append(_ESC_MAP[nxt])
                i += 2
                continue
            if 0x30 <= nxt <= 0x37:
                oct_val = nxt - 0x30
                j = i + 2
                end_oct = min(i + 4, n)
                while j < end_oct and 0x30 <= raw_bytes[j] <= 0x37:
                    oct_val = (oct_val << 3) | (raw_bytes[j] - 0x30)
                    j += 1
                out.append(oct_val & 0xFF)
                i = j
                continue
            if nxt in (10, 13):
                i += 3 if (nxt == 13 and i + 2 < n and raw_bytes[i + 2] == 10) else 2
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return _decode_pdf_bytes_text(bytes(out))


def _read_pdf_string_after_key(buf: bytes, after_key: int) -> tuple[str | None, int]:
    """
    Read optional PDF whitespace/`%` comments after `/Key`, then decode `(...)` or `<...>`.

    Uses bounded `_EOL_RE` for inline comments so LF-only inputs never trigger unbounded scans.
    """
    n = len(buf)
    ws_limit = min(n, after_key + 256)
    p = _skip_ws_and_comments(buf, after_key, ws_limit)
    if p >= n:
        return None, n

    lead = buf[p]
    if lead == 0x28:  # '(' literal string
        next_pos, closed_ok = _scan_pdf_literal_string(buf, p)
        if closed_ok and next_pos <= n and next_pos >= p + 2:
            val = _decode_pdf_literal(buf[p + 1 : next_pos - 1])
            return val, next_pos
        return None, next_pos

    if lead == 0x3C and buf[p : p + 2] != b"<<":  # '<...>' hex string
        scan_limit = min(n, p + 1 + MAX_PDF_STRING_SCAN_BYTES)
        end_hex = buf.find(b">", p + 1, scan_limit)
        if end_hex == -1:
            return None, scan_limit
        hex_slice = buf[p + 1 : end_hex]
        if _NON_HEX_WS_RE.search(hex_slice) is None:
            compact = hex_slice.translate(None, _PDF_WS_STRIP)
            if len(compact) % 2 == 1:
                compact += b"0"
            if compact:
                try:
                    return _decode_pdf_bytes_text(bytes.fromhex(compact.decode("ascii"))), end_hex + 1
                except ValueError:
                    return None, end_hex + 1
        return None, end_hex + 1

    return None, p


def _scan_pdf_lexical_tokens(
    buf: bytes,
    *,
    skip_spans: List[tuple[int, int]] | None,
    info_out: Dict[str, List[str]],
    info_seen: Dict[str, set[str]],
    risk_counts: Dict[str, int],
    on_info_cap: Callable[[int], None] | None = None,
    on_lex_error: Callable[[int | None, str], None] | None = None,
    start_offset: int = 0,
) -> None:
    """
    Single-pass C-accelerated O(N) PDF lexical scanner outside comments, strings, and binary streams.

    Consumes consecutive `%...EOL` comment runs in C via `_LEX_TRIGGER_RE`, jumps across `(...)`
    via `_LIT_SPECIAL_RE` with hard resynchronization at `N G obj` / `endobj` / `stream` boundaries
    (`R4-H1`), and skips `<hex>` runs via `_NON_HEX_WS_RE` with zero quadratic paths.
    """
    n = len(buf)
    init_pos = max(0, start_offset)
    pos = init_pos
    spans = skip_spans or []
    span_idx = 0
    num_spans = len(spans)
    dict_depth = 0

    while pos < n:
        while span_idx < num_spans and pos >= spans[span_idx][1]:
            span_idx += 1
        if span_idx < num_spans and pos >= spans[span_idx][0]:
            pos = spans[span_idx][1]
            span_idx += 1
            dict_depth = 0
            continue

        seg_end = spans[span_idx][0] if span_idx < num_spans else n
        if pos == init_pos or (span_idx > 0 and pos == spans[span_idx - 1][1]):
            if _FAST_INTERESTING_RE.search(buf, pos, seg_end) is None:
                if span_idx < num_spans:
                    pos = spans[span_idx][1]
                    span_idx += 1
                    dict_depth = 0
                    continue
                break

        m = _LEX_TRIGGER_RE.search(buf, pos, seg_end)
        if m is None:
            if span_idx < num_spans:
                pos = spans[span_idx][1]
                span_idx += 1
                dict_depth = 0
                continue
            break
        idx = m.start()

        lead = buf[idx]
        if lead == 0x3C and m.end() - idx == 2 and buf[idx : idx + 2] == b"<<":
            dict_depth += 1
            pos = m.end()
            continue
        if lead == 0x3E and m.end() - idx == 2 and buf[idx : idx + 2] == b">>":
            if dict_depth > 0:
                dict_depth -= 1
            pos = m.end()
            continue
        if 0x30 <= lead <= 0x39:  # 'N G obj'
            if idx == 0 or (buf[idx - 1] in _PDF_WS_OR_DELIM and buf[idx - 1] != 0x2F):
                dict_depth = 0
            pos = m.end()
            continue
        if lead == ord("e"):  # 'endobj' or 'endstream'
            if idx == 0 or (buf[idx - 1] in _PDF_WS_OR_DELIM and buf[idx - 1] != 0x2F):
                dict_depth = 0
            pos = m.end()
            continue

        if lead == 0x25 or (lead == 0x28 and m.end() - idx >= 2):  # batched '%' or single-line flat `(...)`
            pos = m.end()
            continue

        if lead == 0x28:  # multi-line, nested, escaped, or unclosed '(' literal string
            win_hi = min(seg_end, idx + 1 + MAX_STREAM_DICT_BYTES)
            if dict_depth == 0:
                resync_off = _find_earliest_stage2_resync(buf, idx + 1, win_hi)
                if resync_off is not None:
                    sub_end, sub_closed = _scan_pdf_literal_string(
                        buf,
                        idx,
                        max_scan=max(0, resync_off - idx - 1),
                    )
                    if not sub_closed:
                        if on_lex_error is not None:
                            on_lex_error(
                                idx,
                                "Unterminated top-level literal string before object boundary (lexer resynchronized)",
                            )
                        pos = resync_off
                        continue
                    pos = sub_end
                    continue
                end_lit, closed_ok = _scan_pdf_literal_string(
                    buf,
                    idx,
                    max_scan=max(0, win_hi - idx - 1),
                )
                if not closed_ok and on_lex_error is not None:
                    on_lex_error(idx, "Unterminated top-level PDF literal string")
                pos = end_lit
                continue

            end_lit, closed_ok = _scan_pdf_literal_string(
                buf,
                idx,
                max_scan=max(0, win_hi - idx - 1),
            )
            if not closed_ok:
                resync_off = _find_earliest_stage2_resync(buf, idx + 1, end_lit)
                dict_depth = 0
                if on_lex_error is not None:
                    on_lex_error(
                        idx,
                        "Unterminated PDF literal string resynchronized at object boundary",
                    )
                pos = resync_off if resync_off is not None else end_lit
                continue
            pos = end_lit
            continue

        if lead == 0x3C:  # single '<' hex string candidate
            if idx + 1 < n and buf[idx + 1] in _HEX_OR_WS_BYTES:
                scan_limit = min(n, idx + 1 + MAX_PDF_STRING_SCAN_BYTES)
                nm = _NON_HEX_WS_RE.search(buf, idx + 1, scan_limit)
                if nm is None:
                    pos = scan_limit
                elif buf[nm.start()] == 0x3E:  # '>'
                    pos = nm.start() + 1
                else:
                    pos = nm.start()
                continue
            pos = idx + 1
            continue

        # lead == 0x2F ('/'): PDF Name token
        end_m = _NAME_BODY_END_RE.search(buf, idx + 1)
        name_end = end_m.start() if end_m is not None else n
        raw_body = buf[idx + 1 : name_end]
        if not raw_body:
            pos = name_end if name_end > idx else idx + 1
            continue

        if b"#" in raw_body:
            norm_body, had_hex_esc = _decode_pdf_name_token(raw_body)
            if had_hex_esc and norm_body in _SENSITIVE_PDF_NAMES:
                risk_counts["obfuscated_name_tokens"] = risk_counts.get("obfuscated_name_tokens", 0) + 1
        else:
            norm_body = raw_body

        risk_bucket = _RISK_NAME_MAP.get(norm_body)
        if risk_bucket is not None:
            risk_counts[risk_bucket] = risk_counts.get(risk_bucket, 0) + 1

        info_key = _INFO_KEY_BYTES_MAP.get(norm_body)
        if info_key is not None:
            val, next_pos = _read_pdf_string_after_key(buf, name_end)
            if val:
                clipped = val[:240]
                if clipped:
                    seen_k = info_seen.setdefault(info_key, set())
                    if clipped not in seen_k:
                        bucket = info_out.setdefault(info_key, [])
                        if len(bucket) < MAX_INFO_VALUES_PER_KEY:
                            seen_k.add(clipped)
                            bucket.append(clipped)
                        elif on_info_cap is not None:
                            on_info_cap(idx)
            pos = next_pos if next_pos > name_end else name_end
            continue

        pos = name_end


def _extract_pdf_string_value(raw: bytes, key: str) -> List[str]:
    """Extract literal `(val)` or hex `<hex>` PDF string values for `/Key` (honoring `#xx` & comments)."""
    info_out: Dict[str, List[str]] = {}
    info_seen: Dict[str, set[str]] = {}
    risk_dummy: Dict[str, int] = {}
    _scan_pdf_lexical_tokens(
        raw,
        skip_spans=None,
        info_out=info_out,
        info_seen=info_seen,
        risk_counts=risk_dummy,
    )
    return info_out.get(key, [])


def _is_xml_ncname_char(ch: str) -> bool:
    return ch.isalnum() or ch in ("_", "-", ".")


def _extract_xmp_field(txt: str, name: str) -> str | None:
    """Extract `<ns:Name>val</ns:Name>` or `ns:Name="val"` in O(N) without backtracking regexes."""
    token = f":{name}"
    tok_len = len(token)
    n = len(txt)
    cursor = 0

    while cursor < n:
        idx = txt.find(token, cursor)
        if idx == -1:
            return None
        after = idx + tok_len
        ns_start = idx
        while ns_start > 0 and (idx - ns_start) < 64 and _is_xml_ncname_char(txt[ns_start - 1]):
            ns_start -= 1

        if ns_start < idx and ns_start > 0:
            prev_ch = txt[ns_start - 1]
            if prev_ch == "<" and after < n and (txt[after] == ">" or txt[after] in " \t\r\n/"):
                gt = txt.find(">", after, min(n, after + 512))
                if gt != -1 and txt[gt - 1] != "/":
                    lt = txt.find("<", gt + 1, min(n, gt + 1 + 1024))
                    if lt != -1 and txt[lt : lt + 2] == "</":
                        close_gt = txt.find(">", lt + 2, min(n, lt + 2 + 128))
                        if close_gt != -1:
                            val = txt[gt + 1 : lt].strip()
                            if val:
                                return val[:240]
            elif prev_ch in " \t\r\n" and after < n:
                eq_pos = after
                while eq_pos < min(n, after + 32) and txt[eq_pos] in " \t\r\n":
                    eq_pos += 1
                if eq_pos < n and txt[eq_pos] == "=":
                    q_pos = eq_pos + 1
                    while q_pos < min(n, eq_pos + 32) and txt[q_pos] in " \t\r\n":
                        q_pos += 1
                    if q_pos < n and txt[q_pos] in ('"', "'"):
                        quote_ch = txt[q_pos]
                        end_q = txt.find(quote_ch, q_pos + 1, min(n, q_pos + 1 + 1024))
                        if end_q != -1:
                            val = txt[q_pos + 1 : end_q].strip()
                            if val:
                                return val[:240]
        cursor = after
    return None


def _parse_xmp_packet(xml_bytes: bytes, source_offset: int, from_compressed_stream: bool) -> Dict[str, Any]:
    txt = xml_bytes.decode("utf-8", errors="replace")
    return {
        "source_offset": source_offset,
        "from_compressed_stream": from_compressed_stream,
        "creator_tool": _extract_xmp_field(txt, "CreatorTool"),
        "producer": _extract_xmp_field(txt, "Producer"),
        "create_date": _extract_xmp_field(txt, "CreateDate"),
        "modify_date": _extract_xmp_field(txt, "ModifyDate"),
        "document_id": _extract_xmp_field(txt, "DocumentID"),
        "instance_id": _extract_xmp_field(txt, "InstanceID"),
    }


def _scan_xmp_packets(
    buf: bytes,
    *,
    from_compressed_stream: bool,
    fixed_source_offset: int | None = None,
    max_packets: int = MAX_XMP_PACKETS,
) -> tuple[List[Dict[str, Any]], bool]:
    """
    Single-pass O(N) cursor scanner for `<?xpacket ... ?> ... <?xpacket end=... ?>` packets.

    Caps each packet at `MAX_XMP_PACKET_BYTES` (1 MiB) and halts immediately once `max_packets`
    is reached (returning `(packets, hit_cap_bool)`) to prevent object-graph amplification bombs.
    """
    packets: List[Dict[str, Any]] = []
    n = len(buf)
    cursor = 0
    open_pos: int | None = None

    while cursor < n:
        pos = buf.find(b"<?xpacket", cursor)
        if pos == -1:
            break
        after = pos + 9
        if after >= n or (buf[after] not in _PDF_WS_BYTES and buf[after : after + 2] != b"?>"):
            cursor = after
            continue
        pi_end = buf.find(b"?>", after, min(n, pos + 256))
        if pi_end == -1:
            cursor = after
            continue
        pi_body = buf[after:pi_end].lstrip(b" \t\r\n")
        is_end_pi = pi_body.startswith(b"end") and (
            len(pi_body) == 3 or pi_body[3] in b" \t\r\n="
        )
        if is_end_pi:
            packet_end = pi_end + 2
            if open_pos is not None and (packet_end - open_pos) <= MAX_XMP_PACKET_BYTES:
                if len(packets) >= max_packets:
                    return packets, True
                src_off = fixed_source_offset if fixed_source_offset is not None else open_pos
                packets.append(
                    _parse_xmp_packet(
                        buf[open_pos:packet_end],
                        src_off,
                        from_compressed_stream=from_compressed_stream,
                    )
                )
            open_pos = None
        else:
            open_pos = pos
        cursor = pi_end + 2

    return packets, False


def _build_non_stream_windows(n: int, skip_spans: List[tuple[int, int]] | None) -> List[tuple[int, int]]:
    """Build sorted, disjoint `[lo, hi)` byte intervals outside `skip_spans`."""
    if not skip_spans:
        return [(0, n)] if n > 0 else []
    windows: List[tuple[int, int]] = []
    cur = 0
    for s_lo, s_hi in sorted(skip_spans):
        lo = max(cur, min(n, s_lo))
        hi = max(lo, min(n, s_hi))
        if cur < lo:
            windows.append((cur, lo))
        cur = max(cur, hi)
    if cur < n:
        windows.append((cur, n))
    return windows


def _has_real_startxref_eof(raw: bytes, after_kw: int, limit: int) -> bool:
    """Bounded O(1) check (`<= 256` bytes, zero regex backtracking) for `startxref <ws> <offset> <ws> %%EOF`."""
    bound = min(len(raw), limit, after_kw + 256)
    p = _skip_ws_and_comments(raw, after_kw, bound)
    d_start = p
    while p < bound and 0x30 <= raw[p] <= 0x39:
        p += 1
    if p == d_start or (p - d_start) > MAX_STARTXREF_DIGITS:
        return False
    p = _skip_ws_and_comments(raw, p, bound)
    if p + 5 > len(raw) or raw[p : p + 5] != b"%%EOF":
        return False
    return p + 5 >= len(raw) or raw[p + 5] in _PDF_WS_BYTES


def _find_next_lexical_obj_boundary(
    raw: bytes,
    search_from: int,
    non_stream_wins: List[tuple[int, int]],
) -> tuple[int, bytes]:
    """
    Find the next genuine lexical `endobj` or `N G obj` boundary after `search_from`,
    skipping `raw_stream_spans`, `%...EOL` comments, `(...)` strings, `<hex>` strings, and `/endobj` names.
    """
    n = len(raw)
    for w_lo, w_hi in non_stream_wins:
        if w_hi <= search_from:
            continue
        q = max(w_lo, search_from)
        while q < w_hi:
            bm = _OBJ_BOUND_LEX_RE.search(raw, q, w_hi)
            if bm is None:
                break
            b_idx = bm.start()
            b_tok = bm.group(0)
            if b_tok[0] == 0x25 or (b_tok[0] == 0x28 and len(b_tok) >= 2):
                q = bm.end()
                continue
            if b_tok == b"(":
                p_depth = 1
                sq = b_idx + 1
                while sq < w_hi and p_depth > 0:
                    sm = _STR_PDF_LEX_RE.search(raw, sq, w_hi)
                    if sm is None:
                        sq = w_hi
                        break
                    st_tok = sm.group(0)
                    if st_tok == b"(":
                        p_depth += 1
                        sq = sm.start() + 1
                    elif st_tok == b")":
                        p_depth -= 1
                        sq = sm.start() + 1
                    else:
                        sq = sm.end()
                q = sq
                continue
            if b_tok == b"<<":
                q = b_idx + 2
                continue
            if b_tok == b"<":
                nm = _NON_HEX_WS_RE.search(raw, b_idx + 1, w_hi)
                if nm is None:
                    q = w_hi
                elif raw[nm.start()] == 0x3E:
                    q = nm.start() + 1
                else:
                    q = nm.start()
                continue
            if b_idx == 0 or (raw[b_idx - 1] in _PDF_WS_OR_DELIM and raw[b_idx - 1] != 0x2F):
                return (b_idx, b"endobj" if b_tok == b"endobj" else b"obj")
            q = bm.end()
    return (n + 1, b"")


def _scan_structural_eof_offsets(
    raw: bytes,
    raw_stream_spans: List[tuple[int, int]],
    note_marker_cap: Callable[[int], None] | None = None,
    add_error: Callable[[int | None, str], None] | None = None,
    *,
    header_offset: int = -1,
    header_end: int = -1,
) -> tuple[List[int], int, int, List[tuple[int, int]], List[tuple[int, int]]]:
    """
    Unified single-pass O(N) lexical scanner for structural PDF trailer `%%EOF` markers,
    top-level trailer windows (`not in_obj and dict_depth == 0 and array_depth == 0`), and
    plain non-stream/non-string/non-comment PDF code windows.

    Prevents bare `%%EOF`, `startxref`, or `xref` tokens inside indirect `obj..endobj` bodies,
    `<<...>>` dictionaries, or `[...]` arrays from polluting structural revision counts while
    still preserving `code_windows` for `/Type /XRef` stream dictionary detection.
    """
    eof_offsets: List[int] = []
    code_windows: List[tuple[int, int]] = []
    top_trailer_windows: List[tuple[int, int]] = []
    total_eof_count = 0
    last_eof_offset = -1
    n = len(raw)
    scan_start = header_offset if header_offset > 0 else 0
    in_obj = False
    last_obj_offset = scan_start
    last_open_delim_offset = scan_start
    dict_depth = 0
    array_depth = 0

    non_stream_wins = _build_non_stream_windows(n, raw_stream_spans)
    cached_bound_pos = -1
    cached_bound_kind = b""

    def _has_closing_endobj_from(probe_offset: int) -> bool:
        nonlocal cached_bound_pos, cached_bound_kind
        if probe_offset > cached_bound_pos:
            cached_bound_pos, cached_bound_kind = _find_next_lexical_obj_boundary(
                raw, probe_offset, non_stream_wins
            )
        return cached_bound_kind == b"endobj"

    for win_lo, win_hi in non_stream_wins:
        if win_hi <= scan_start:
            continue
        if win_lo < scan_start:
            win_lo = scan_start
        pos = win_lo
        code_start = win_lo
        top_start: int | None = (
            win_lo if (not in_obj and dict_depth == 0 and array_depth == 0) else None
        )
        paren_depth = 0
        open_paren_offset = win_lo
        while pos < win_hi:
            if paren_depth > 0:
                m = _STR_PDF_LEX_RE.search(raw, pos, win_hi)
                if m is None:
                    break
                idx = m.start()
                tok = m.group(0)
                if tok == b"(":
                    paren_depth += 1
                    pos = idx + 1
                elif tok == b")":
                    paren_depth -= 1
                    pos = idx + 1
                    if paren_depth == 0:
                        code_start = pos
                        top_start = (
                            pos if (not in_obj and dict_depth == 0 and array_depth == 0) else None
                        )
                else:
                    pos = m.end()
                continue

            m = _TOP_PDF_LEX_RE.search(raw, pos, win_hi)
            if m is None:
                break
            idx = m.start()
            tok = m.group(0)

            if tok == b"(":
                if code_start < idx:
                    code_windows.append((code_start, idx))
                if top_start is not None and top_start < idx:
                    top_trailer_windows.append((top_start, idx))
                top_start = None
                paren_depth = 1
                open_paren_offset = idx
                pos = idx + 1
                continue
            if tok == b"<<":
                if top_start is not None and top_start < idx:
                    top_trailer_windows.append((top_start, idx))
                top_start = None
                if dict_depth == 0 and array_depth == 0:
                    last_open_delim_offset = idx
                dict_depth += 1
                pos = idx + 2
                continue
            if tok == b">>":
                if dict_depth > 0:
                    dict_depth -= 1
                pos = idx + 2
                if not in_obj and dict_depth == 0 and array_depth == 0 and top_start is None:
                    top_start = pos
                continue
            if tok == b"[":
                if top_start is not None and top_start < idx:
                    top_trailer_windows.append((top_start, idx))
                top_start = None
                if dict_depth == 0 and array_depth == 0:
                    last_open_delim_offset = idx
                if not in_obj and dict_depth == 0 and add_error is not None:
                    add_error(
                        idx,
                        "Unexpected top-level PDF '[' array delimiter outside indirect object or trailer dictionary",
                    )
                array_depth += 1
                pos = idx + 1
                continue
            if tok == b"]":
                if array_depth > 0:
                    array_depth -= 1
                pos = idx + 1
                if not in_obj and dict_depth == 0 and array_depth == 0 and top_start is None:
                    top_start = pos
                continue
            if tok == b"endobj":
                if idx == 0 or (raw[idx - 1] in _PDF_WS_OR_DELIM and raw[idx - 1] != 0x2F):
                    if (dict_depth > 0 or array_depth > 0) and add_error is not None:
                        add_error(
                            idx,
                            "Unclosed PDF dictionary or array before 'endobj'",
                        )
                    in_obj = False
                    dict_depth = 0
                    array_depth = 0
                    pos = m.end()
                    if top_start is None:
                        top_start = pos
                else:
                    pos = m.end()
                continue
            if tok in (b"xref", b"trailer", b"startxref"):
                is_delim_ok = idx == 0 or (raw[idx - 1] in _PDF_WS_OR_DELIM and raw[idx - 1] != 0x2F)
                if is_delim_ok:
                    if not in_obj and dict_depth == 0 and array_depth == 0:
                        is_real_trailer_hdr = True
                    elif (
                        (
                            tok == b"xref"
                            and _REAL_XREF_SUBSECT_RE.match(raw, m.end(), min(win_hi, m.end() + 256))
                            is not None
                        )
                        or (tok == b"startxref" and _has_real_startxref_eof(raw, m.end(), win_hi))
                    ) and (not in_obj or not _has_closing_endobj_from(m.end())):
                        is_real_trailer_hdr = True
                    else:
                        is_real_trailer_hdr = False

                    if is_real_trailer_hdr:
                        if (in_obj or dict_depth > 0 or array_depth > 0) and add_error is not None:
                            add_error(
                                idx,
                                "Unclosed PDF object, dictionary, or array before trailer/xref section",
                            )
                        in_obj = False
                        dict_depth = 0
                        array_depth = 0
                        if top_start is None:
                            top_start = idx
                pos = m.end()
                continue
            if 0x30 <= tok[0] <= 0x39:  # 'N G obj'
                if idx == 0 or (raw[idx - 1] in _PDF_WS_OR_DELIM and raw[idx - 1] != 0x2F):
                    if in_obj and add_error is not None:
                        add_error(
                            idx,
                            "Indirect PDF object missing 'endobj' before next object header",
                        )
                    if top_start is not None and top_start < idx:
                        top_trailer_windows.append((top_start, idx))
                    top_start = None
                    in_obj = True
                    last_obj_offset = idx
                    dict_depth = 0
                    array_depth = 0
                pos = m.end()
                continue
            if tok == b"<":
                if code_start < idx:
                    code_windows.append((code_start, idx))
                if top_start is not None and top_start < idx:
                    top_trailer_windows.append((top_start, idx))
                top_start = None
                nm = _NON_HEX_WS_RE.search(raw, idx + 1, win_hi)
                if nm is None:
                    if add_error is not None:
                        add_error(
                            idx,
                            "Unterminated PDF hexadecimal string '<' encountered during structural trailer scan",
                        )
                    pos = win_hi
                    code_start = win_hi
                elif raw[nm.start()] == 0x3E:
                    pos = nm.start() + 1
                    code_start = pos
                    if not in_obj and dict_depth == 0 and array_depth == 0:
                        top_start = pos
                else:
                    if add_error is not None:
                        add_error(
                            idx,
                            "Malformed non-hexadecimal character inside PDF '<...>' string",
                        )
                    pos = nm.start()
                    code_start = pos
                    if not in_obj and dict_depth == 0 and array_depth == 0:
                        top_start = pos
                continue
            if tok in (b")", b">"):
                pos = m.end()
                continue

            # tok == b"%": flush preceding plain code, then distinguish top-level `%%EOF` vs `%...EOL` comment
            if code_start < idx:
                code_windows.append((code_start, idx))
            if top_start is not None and top_start < idx:
                top_trailer_windows.append((top_start, idx))
            top_start = None

            is_eof_token = (
                raw[idx : idx + 5] == b"%%EOF"
                and (idx == 0 or raw[idx - 1] in _PDF_WS_BYTES or raw[idx - 1] in b")>]}")
                and (idx + 5 >= n or raw[idx + 5] in _PDF_WS_BYTES)
            )
            if is_eof_token and dict_depth == 0 and array_depth == 0 and in_obj:
                if not _has_closing_endobj_from(idx + 5):
                    if add_error is not None:
                        add_error(
                            idx,
                            "Indirect PDF object missing 'endobj' before %%EOF marker",
                        )
                    in_obj = False

            is_top_level = not in_obj and dict_depth == 0 and array_depth == 0
            if is_top_level and is_eof_token:
                total_eof_count += 1
                last_eof_offset = idx
                if len(eof_offsets) < MAX_CONTAINER_MARKERS:
                    eof_offsets.append(idx)
                elif note_marker_cap is not None:
                    note_marker_cap(idx)
                pos = min(win_hi, idx + 5)
                code_start = pos
                top_start = pos
                continue

            eol_m = _EOL_RE.search(raw, idx + 1, win_hi)
            if eol_m is not None:
                pos = eol_m.end()
            elif idx == header_offset and header_end > idx:
                pos = min(win_hi, header_end)
            else:
                pos = win_hi
            code_start = pos
            if is_top_level:
                top_start = pos

        if paren_depth == 0:
            if code_start < win_hi:
                code_windows.append((code_start, win_hi))
            if top_start is not None and top_start < win_hi:
                top_trailer_windows.append((top_start, win_hi))
        elif paren_depth > 0 and add_error is not None:
            add_error(
                open_paren_offset,
                "Unterminated PDF literal string '(' encountered during structural trailer scan",
            )

    if in_obj and add_error is not None:
        add_error(
            last_obj_offset,
            "Unterminated indirect PDF object (missing 'endobj' at EOF)",
        )
    elif (dict_depth > 0 or array_depth > 0) and add_error is not None:
        add_error(
            last_open_delim_offset,
            "Unterminated PDF dictionary or array delimiter at EOF",
        )

    return eof_offsets, total_eof_count, last_eof_offset, code_windows, top_trailer_windows


def _scan_startxref_offsets(
    raw: bytes,
    add_error: Callable[[int | None, str], None],
    note_marker_cap: Callable[[int], None],
    skip_spans: List[tuple[int, int]] | None = None,
    *,
    windows: List[tuple[int, int]] | None = None,
) -> List[Dict[str, Any]]:
    """
    Linear O(N) scanner for `startxref` pointers across structural code windows with <=18-digit bounds.

    Never invokes unbounded `int()` on >4300-digit inputs (`sys.get_int_max_str_digits()`).
    """
    out: List[Dict[str, Any]] = []
    n = len(raw)
    scan_windows = windows if windows is not None else _build_non_stream_windows(n, skip_spans)
    min_next_pos = 0

    for win_lo, win_hi in scan_windows:
        cursor = max(win_lo, min_next_pos)
        while cursor < win_hi:
            pos = raw.find(b"startxref", cursor, win_hi)
            if pos == -1:
                break
            after = pos + 9
            if pos > 0 and raw[pos - 1] not in _PDF_WS_BYTES and raw[pos - 1] not in b")>]}":
                cursor = after
                continue

            p = after
            ws_cap = min(n, after + 4096)
            while p < ws_cap:
                if raw[p] in _PDF_WS_BYTES:
                    p += 1
                elif raw[p] == 0x25 and raw[p : p + 5] != b"%%EOF":
                    eol_m = _EOL_RE.search(raw, p + 1, ws_cap)
                    if eol_m is None:
                        p = ws_cap
                        break
                    p = eol_m.end()
                else:
                    break
            if p == after or p >= n:
                cursor = min(win_hi, after)
                continue

            sign = 1
            if raw[p] in (0x2B, 0x2D):
                if raw[p] == 0x2D:
                    sign = -1
                p += 1

            d_start = p
            while p < n and 0x30 <= raw[p] <= 0x39:
                p += 1
            if p == d_start:
                cursor = min(win_hi, max(after, p))
                continue

            min_next_pos = p
            cursor = min(win_hi, p)
            sig_digits = raw[d_start:p].lstrip(b"0")

            if len(sig_digits) > MAX_STARTXREF_DIGITS:
                if len(out) < MAX_CONTAINER_MARKERS:
                    out.append({"marker_offset": pos, "declared_xref_offset": None})
                else:
                    note_marker_cap(pos)
                add_error(pos, "startxref offset exceeds bounded 64-bit integer range")
                continue

            decl = sign * (int(sig_digits) if sig_digits else 0)
            if len(out) < MAX_CONTAINER_MARKERS:
                out.append({"marker_offset": pos, "declared_xref_offset": decl})
            else:
                note_marker_cap(pos)

            if decl < 0:
                add_error(pos, "Invalid negative startxref offset (< 0)")
            elif decl >= n:
                add_error(pos, "startxref offset points at or past end of PDF container")

    return out


def inspect_pdf_container(
    raw: bytes,
    label: str = "input.pdf",
    *,
    source_label: str | None = None,
) -> Dict[str, Any]:
    """Deterministically inspect a PDF binary container for incremental revisions and metadata provenance."""
    effective_label = source_label if source_label is not None else label
    head_window = raw[:1024]
    hdr_match = _PDF_HEADER_RE.search(head_window)
    if hdr_match is None:
        return {
            "artifact": effective_label,
            "container_format": "UNSUPPORTED_OR_NOT_A_PDF",
            "valid_container": False,
            "epistemic_tier": "OBSERVED",
            "file_size_bytes": len(raw),
            "trailing_bytes_after_final_eof": None,
            "container_errors": [
                {"byte_offset": 0, "reason": "Missing ISO 32000-1 %PDF-x.y header within first 1024 bytes"}
            ],
        }

    header_offset = hdr_match.start()
    pdf_version = hdr_match.group(1).decode("ascii", errors="replace")
    container_errors: List[Dict[str, Any]] = []
    errors_capped = False
    markers_capped = False
    info_cap_logged = False

    def add_error(byte_offset: int | None, reason: str) -> None:
        nonlocal errors_capped
        if len(container_errors) < MAX_CONTAINER_ERRORS - 1:
            container_errors.append({"byte_offset": byte_offset, "reason": reason})
        elif not errors_capped:
            errors_capped = True
            container_errors.append(
                {
                    "byte_offset": byte_offset,
                    "reason": "Container error count exceeded 128-entry safety cap; additional errors suppressed",
                }
            )

    def note_marker_cap(byte_offset: int) -> None:
        nonlocal markers_capped
        if not markers_capped:
            markers_capped = True
            add_error(
                byte_offset,
                "Structural PDF marker count exceeded 2048-entry cap; offset list truncated",
            )

    def note_info_cap(byte_offset: int) -> None:
        nonlocal info_cap_logged
        if not info_cap_logged:
            info_cap_logged = True
            add_error(
                byte_offset,
                f"Info value cap reached ({MAX_INFO_VALUES_PER_KEY} distinct values per key); additional values omitted",
            )

    n = len(raw)

    xmp_packets, xmp_capped = _scan_xmp_packets(
        raw,
        from_compressed_stream=False,
        max_packets=MAX_XMP_PACKETS,
    )
    if xmp_capped:
        add_error(
            0,
            f"XMP packet count exceeded {MAX_XMP_PACKETS}-packet safety cap; additional XMP packets skipped",
        )

    def _on_dec_info_cap(byte_off: int) -> None:
        note_info_cap(byte_off)

    def inspect_decoded_stream_payload(payload_bytes: bytes, stream_offset: int, from_compressed: bool) -> None:
        nonlocal xmp_capped
        if from_compressed and not xmp_capped and b"<?xpacket" in payload_bytes:
            rem_xmp = MAX_XMP_PACKETS - len(xmp_packets)
            if rem_xmp > 0:
                new_pkts, hit_cap = _scan_xmp_packets(
                    payload_bytes,
                    from_compressed_stream=True,
                    fixed_source_offset=stream_offset,
                    max_packets=rem_xmp,
                )
                xmp_packets.extend(new_pkts)
                if hit_cap:
                    xmp_capped = True
                    add_error(
                        stream_offset,
                        f"XMP packet count exceeded {MAX_XMP_PACKETS}-packet safety cap; additional XMP packets skipped",
                    )
            else:
                _probe_pkts, hit_cap = _scan_xmp_packets(
                    payload_bytes,
                    from_compressed_stream=True,
                    fixed_source_offset=stream_offset,
                    max_packets=0,
                )
                if hit_cap:
                    xmp_capped = True
                    add_error(
                        stream_offset,
                        f"XMP packet count exceeded {MAX_XMP_PACKETS}-packet safety cap; additional XMP packets skipped",
                    )

        if b"/" in payload_bytes:
            _scan_pdf_lexical_tokens(
                payload_bytes,
                skip_spans=None,
                info_out=dec_info_out,
                info_seen=dec_info_seen,
                risk_counts=dec_risk_counts,
                on_info_cap=_on_dec_info_cap,
            )

    # Stage 1: Single-pass O(N) monotonic stream discovery & ordered filter pipeline decoding
    raw_mv = memoryview(raw)
    raw_stream_spans: List[tuple[int, int]] = []
    dec_info_out: Dict[str, List[str]] = {}
    dec_info_seen: Dict[str, set[str]] = {}
    dec_risk_counts: Dict[str, int] = {}
    dict_header_cache: Dict[bytes, tuple[List[bytes], bool, int | None, bool]] = {}
    tracker = _StreamDictTracker(raw, on_lex_error=add_error, start_pos=header_offset)

    cursor = header_offset
    cached_end_pos = -2
    cached_struct_es_pos = -2
    total_decompressed_bytes = 0
    decompression_budget_exhausted = False

    def _refresh_cached_end_pos(min_offset: int) -> int:
        nonlocal cached_end_pos
        if cached_end_pos != -1 and cached_end_pos < min_offset:
            search_from = max(min_offset, (cached_end_pos + 9) if cached_end_pos >= 0 else min_offset)
            cached_end_pos = -1
            while search_from < n:
                cand_end = raw.find(b"endstream", search_from)
                if cand_end == -1:
                    break
                cand_after = cand_end + 9
                if cand_after >= n or raw[cand_after] in _PDF_WS_OR_DELIM:
                    cached_end_pos = cand_end
                    break
                search_from = cand_after
        return cached_end_pos

    while cursor < n:
        pos = raw.find(b"stream", cursor)
        if pos == -1:
            break
        after = pos + 6
        # Reject `/stream` Name tokens (0x2F) and non-delimiter prefixes (`upstream`, `endstream`)
        if pos > 0 and (raw[pos - 1] == 0x2F or raw[pos - 1] not in _PDF_WS_OR_DELIM):
            cursor = after
            continue
        if after >= n:
            break

        # Check EOL immediately after `stream` BEFORE advancing tracker so `b" streamX" * 40000` is O(1)/hit
        if raw[after : after + 2] == b"\r\n":
            body_start = after + 2
            is_bare_cr = False
        elif raw[after] == 0x0A:
            body_start = after + 1
            is_bare_cr = False
        elif raw[after] == 0x0D:
            body_start = after + 1
            is_bare_cr = True
        else:
            cursor = after
            continue

        dict_bytes, exceeded_dict_cap = tracker.advance_to_stream(pos)
        if exceeded_dict_cap:
            add_error(pos, "Stream dictionary exceeded 1 MiB safety limit")
            dec_risk_counts["undecoded_filter_streams"] = (
                dec_risk_counts.get("undecoded_filter_streams", 0) + 1
            )
            tracker.reset_at(body_start)
            cursor = body_start
            continue
        if dict_bytes is None:
            if tracker.lex_pos <= pos and _refresh_cached_end_pos(body_start) != -1:
                add_error(pos, "PDF stream keyword without resolvable enclosing dictionary")
                dec_risk_counts["undecoded_filter_streams"] = (
                    dec_risk_counts.get("undecoded_filter_streams", 0) + 1
                )
                tracker.reset_at(body_start)
            cursor = max(body_start, tracker.lex_pos)
            continue

        if is_bare_cr:
            add_error(
                pos,
                "Non-conformant bare CR after stream keyword (ISO 32000-1 requires CRLF or LF)",
            )
            tracker.reset_at(body_start)
            cursor = body_start
            continue

        if len(dict_bytes) <= 256 and dict_bytes in dict_header_cache:
            filters, unresolvable_filter, declared_len, is_objstm = dict_header_cache[dict_bytes]
        else:
            filters, unresolvable_filter, declared_len, is_objstm = _parse_stream_dict_header(dict_bytes)
            if len(dict_bytes) <= 256 and len(dict_header_cache) < 256:
                dict_header_cache[dict_bytes] = (filters, unresolvable_filter, declared_len, is_objstm)
        body_end = -1
        after_endstream = -1
        used_declared_len = False

        if declared_len is not None and 0 <= declared_len <= (n - body_start):
            cand_decl_end = body_start + declared_len
            ws_p = cand_decl_end
            ws_cap = min(n, ws_p + 64)
            while ws_p < ws_cap and raw[ws_p] in _PDF_WS_BYTES:
                ws_p += 1
            if raw[ws_p : ws_p + 9] == b"endstream" and (
                ws_p + 9 >= n or raw[ws_p + 9] in _PDF_WS_OR_DELIM
            ):
                if cached_struct_es_pos != -1 and cached_struct_es_pos < body_start:
                    start_es = max(
                        body_start,
                        (cached_struct_es_pos + 9) if cached_struct_es_pos >= 0 else body_start,
                    )
                    cached_struct_es_pos = _find_next_structural_endstream(raw, start_es)
                if 0 <= cached_struct_es_pos < cand_decl_end:
                    add_error(
                        pos,
                        "Declared stream /Length overruns an earlier endstream/endobj boundary",
                    )
                else:
                    body_end = cand_decl_end
                    after_endstream = ws_p + 9
                    used_declared_len = True

        if not used_declared_len:
            if _refresh_cached_end_pos(body_start) == -1:
                add_error(pos, "Unclosed PDF stream object (missing endstream marker)")
                break
            body_end = cached_end_pos
            after_endstream = cached_end_pos + 9

        # 1. Unfiltered stream (0 filters): scan raw body directly so unfiltered streams never hide JS/Info
        if not filters and not unresolvable_filter:
            _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
            inspect_decoded_stream_payload(raw[body_start:body_end], pos, from_compressed=False)
            tracker.reset_at(after_endstream)
            cursor = after_endstream
            continue

        # 2. Unsupported or unresolvable filter pipeline
        if (
            unresolvable_filter
            or len(filters) > MAX_FILTER_CHAIN_DEPTH
            or any(f not in _SUPPORTED_DECODE_FILTERS for f in filters)
        ):
            _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
            if (
                unresolvable_filter
                or len(filters) > MAX_FILTER_CHAIN_DEPTH
                or is_objstm
                or any(f not in _PURE_IMAGE_FILTERS for f in filters)
            ):
                dec_risk_counts["undecoded_filter_streams"] = (
                    dec_risk_counts.get("undecoded_filter_streams", 0) + 1
                )
            tracker.reset_at(after_endstream)
            cursor = after_endstream
            continue

        # 3. Supported filter pipeline (/FlateDecode, /ASCIIHexDecode, /ASCII85Decode)
        if decompression_budget_exhausted:
            _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
            tracker.reset_at(after_endstream)
            cursor = after_endstream
            continue

        cur_data: bytes | memoryview = raw_mv[body_start:body_end]
        stage0_consumed = body_end - body_start
        pipeline_status = "ok"
        first_stage_unpacked = 0
        budget_halted = False

        if len(filters) == 1 and filters[0] in (b"FlateDecode", b"Fl"):
            remaining_budget = MAX_TOTAL_DECOMPRESSED_BYTES - total_decompressed_bytes
            if remaining_budget <= 0:
                decompression_budget_exhausted = True
                add_error(
                    pos,
                    "Cumulative stream decompression exceeded 32 MiB safety budget; remaining streams skipped",
                )
                _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
                tracker.reset_at(after_endstream)
                cursor = after_endstream
                continue
            step_cap = min(MAX_PDF_STREAM_BYTES, remaining_budget)
            pipeline_status, first_stage_unpacked, stage0_consumed, out_bytes = _decompress_flate_stream(
                cur_data,
                max_len=step_cap,
            )
            total_decompressed_bytes += first_stage_unpacked
            if pipeline_status == "ok":
                cur_data = out_bytes
        else:
            for stage_idx, fname in enumerate(filters):
                remaining_budget = MAX_TOTAL_DECOMPRESSED_BYTES - total_decompressed_bytes
                if remaining_budget <= 0:
                    decompression_budget_exhausted = True
                    add_error(
                        pos,
                        "Cumulative stream decompression exceeded 32 MiB safety budget; remaining streams skipped",
                    )
                    _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
                    budget_halted = True
                    break

                step_cap = min(MAX_PDF_STREAM_BYTES, remaining_budget)
                if fname in (b"FlateDecode", b"Fl"):
                    st, unpacked_len, consumed_len, out_bytes = _decompress_flate_stream(
                        cur_data,
                        max_len=step_cap,
                    )
                elif fname in (b"ASCIIHexDecode", b"AHx"):
                    if stage_idx == 0:
                        st, unpacked_len, consumed_len, out_bytes = _decode_ascii_hex_stream(
                            cur_data,
                            max_len=step_cap,
                            raw_buf=raw,
                            raw_start=body_start,
                            raw_end=body_end,
                        )
                    else:
                        st, unpacked_len, consumed_len, out_bytes = _decode_ascii_hex_stream(
                            cur_data,
                            max_len=step_cap,
                        )
                else:
                    if stage_idx == 0:
                        st, unpacked_len, consumed_len, out_bytes = _decode_ascii85_stream(
                            cur_data,
                            max_len=step_cap,
                            raw_buf=raw,
                            raw_start=body_start,
                            raw_end=body_end,
                        )
                    else:
                        st, unpacked_len, consumed_len, out_bytes = _decode_ascii85_stream(
                            cur_data,
                            max_len=step_cap,
                        )

                total_decompressed_bytes += unpacked_len
                if stage_idx == 0:
                    first_stage_unpacked = unpacked_len
                    stage0_consumed = consumed_len

                if st != "ok":
                    pipeline_status = st
                    break
                cur_data = out_bytes

        if budget_halted:
            tracker.reset_at(after_endstream)
            cursor = after_endstream
            continue

        if pipeline_status == "limit":
            _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
            if total_decompressed_bytes >= MAX_TOTAL_DECOMPRESSED_BYTES:
                decompression_budget_exhausted = True
                add_error(
                    pos,
                    "Cumulative stream decompression exceeded 32 MiB safety budget; remaining streams skipped",
                )
                tracker.reset_at(after_endstream)
                cursor = after_endstream
                continue
            add_error(
                pos,
                "Single PDF stream exceeded 16 MiB decompression safety limit; stream skipped",
            )
            tracker.reset_at(after_endstream)
            cursor = after_endstream
            continue

        if pipeline_status == "corrupt":
            add_error(pos, "Corrupted or truncated compressed PDF stream")
            if (
                first_stage_unpacked > 0
                or used_declared_len
                or total_decompressed_bytes >= MAX_TOTAL_DECOMPRESSED_BYTES
            ):
                _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
                if total_decompressed_bytes >= MAX_TOTAL_DECOMPRESSED_BYTES:
                    decompression_budget_exhausted = True
                    add_error(
                        pos,
                        "Cumulative stream decompression exceeded 32 MiB safety budget; remaining streams skipped",
                    )
                tracker.reset_at(after_endstream)
                cursor = after_endstream
            else:
                if raw.find(b"stream", body_start, body_end) != -1:
                    tracker.reset_at(body_start)
                    cursor = body_start
                else:
                    _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
                    tracker.reset_at(after_endstream)
                    cursor = after_endstream
            continue

        # Zero-copy C regex check for non-whitespace trailing bytes after stage-0 stream EOF (`R3-H3`)
        has_trailing = _NON_PDF_WS_RE.search(raw, body_start + stage0_consumed, body_end) is not None
        if not has_trailing:
            _record_raw_stream_span(raw, body_start, body_end, raw_stream_spans, add_error, pos)
            tracker.reset_at(after_endstream)
            cursor = after_endstream
        else:
            add_error(pos, "Unexpected trailing bytes after stream EOF")
            stream_actual_end = body_start + max(1, stage0_consumed)
            _record_raw_stream_span(raw, body_start, stream_actual_end, raw_stream_spans, add_error, pos)
            tracker.reset_at(stream_actual_end)
            cursor = stream_actual_end

        dec_bytes = cur_data if isinstance(cur_data, bytes) else bytes(cur_data)
        if b"/" in dec_bytes or (not xmp_capped and b"<?xpacket" in dec_bytes):
            inspect_decoded_stream_payload(dec_bytes, pos, from_compressed=True)

    # Stage 2: Unified structural trailer/xref marker scan (skipping streams, strings, hex & comments)
    (
        eof_offsets,
        total_eof_count,
        last_eof_offset,
        structural_code_windows,
        top_trailer_windows,
    ) = _scan_structural_eof_offsets(
        raw,
        raw_stream_spans,
        note_marker_cap=note_marker_cap,
        add_error=add_error,
        header_offset=header_offset,
        header_end=hdr_match.end(),
    )
    if total_eof_count == 0:
        add_error(n, "Missing terminal %%EOF marker")

    startxref_offsets = _scan_startxref_offsets(
        raw,
        add_error,
        note_marker_cap,
        windows=top_trailer_windows,
    )
    if len(startxref_offsets) > total_eof_count and not markers_capped:
        add_error(
            startxref_offsets[-1]["marker_offset"],
            f"Structural trailer mismatch: observed {len(startxref_offsets)} startxref markers vs {total_eof_count} %%EOF markers",
        )

    xref_offsets: List[int] = []
    xref_cap_hit = False
    for win_lo, win_hi in top_trailer_windows:
        xref_cur = win_lo
        while xref_cur < win_hi:
            xpos = raw.find(b"xref", xref_cur, win_hi)
            if xpos == -1:
                break
            if (xpos == 0 or raw[xpos - 1] in _PDF_WS_BYTES or raw[xpos - 1] in b")>]}") and (
                xpos + 4 < n and raw[xpos + 4] in _PDF_WS_BYTES
            ):
                if len(xref_offsets) < MAX_CONTAINER_MARKERS:
                    xref_offsets.append(xpos)
                else:
                    note_marker_cap(xpos)
                    xref_cap_hit = True
                    break
            xref_cur = xpos + 4
        if xref_cap_hit:
            break

    xref_stream_offsets: List[int] = []
    xref_stm_cap_hit = False
    for win_lo, win_hi in structural_code_windows:
        for m in _XREF_STREAM_RE.finditer(raw, win_lo, win_hi):
            if len(xref_stream_offsets) < MAX_CONTAINER_MARKERS:
                xref_stream_offsets.append(m.start())
            else:
                note_marker_cap(m.start())
                xref_stm_cap_hit = True
                break
        if xref_stm_cap_hit:
            break

    trailing_bytes = 0
    if last_eof_offset != -1:
        last_eof_end = last_eof_offset + 5
        rest = raw[last_eof_end:].lstrip(b"\r\n\x00 ")
        trailing_bytes = len(rest)

    info_metadata: Dict[str, List[str]] = {}
    info_seen: Dict[str, set[str]] = {}
    risk_counts: Dict[str, int] = {}

    _scan_pdf_lexical_tokens(
        raw,
        skip_spans=raw_stream_spans,
        info_out=info_metadata,
        info_seen=info_seen,
        risk_counts=risk_counts,
        on_info_cap=note_info_cap,
        on_lex_error=add_error,
        start_offset=header_offset,
    )

    for k, vals in dec_info_out.items():
        seen_k = info_seen.setdefault(k, set())
        bucket = info_metadata.setdefault(k, [])
        for v in vals:
            if v not in seen_k:
                if len(bucket) < MAX_INFO_VALUES_PER_KEY:
                    seen_k.add(v)
                    bucket.append(v)
                else:
                    note_info_cap(0)
                    break

    for rk, cnt in dec_risk_counts.items():
        risk_counts[rk] = risk_counts.get(rk, 0) + cnt

    risk_markers: Dict[str, int] = {rk: cnt for rk, cnt in risk_counts.items() if cnt > 0}
    return {
        "artifact": effective_label,
        "container_format": "PDF",
        "valid_container": bool(total_eof_count > 0 and not container_errors),
        "epistemic_tier": "DERIVED",
        "pdf_version": pdf_version,
        "header_offset": header_offset,
        "file_size_bytes": len(raw),
        "eof_offsets": eof_offsets,
        "startxref_offsets": startxref_offsets,
        "xref_offsets": xref_offsets,
        "xref_stream_offsets": xref_stream_offsets,
        "incremental_revision_count": total_eof_count,
        "has_multiple_revisions": total_eof_count > 1,
        "trailing_bytes_after_final_eof": trailing_bytes,
        "info_metadata": info_metadata,
        "xmp_metadata": xmp_packets,
        "risk_markers": risk_markers,
        "container_errors": container_errors,
        "alternative_explanations": [
            "Multiple %%EOF / xref sections legitimately arise from electronic signatures, PDF form saves, annotation edits, incremental saves, or web linearization.",
            "Producer/Creator or XMP tool mismatches are an investigation triage lead and require bank-portal corroboration rather than standalone proof of falsification.",
        ],
    }


def apply_pdf_redaction(
    pdf_report: Dict[str, Any],
    redact: bool = True,
    salt: bytes | None = None,
) -> Dict[str, Any]:
    """
    Return a deep-copied PDF report suppressing filenames, byte-size side channels, dates, and raw metadata.

    Never mutates `pdf_report` or any nested dicts/lists in-place. When `salt is None`, defaults
    to `DEFAULT_EPHEMERAL_SALT` from `starshield.ioc_validators` so keyed HMAC tokens align across
    calls within a process run and respect active HMAC digest agility.

    Offset/Size Redaction Invariant (`redact=True`):
    Suppresses `file_size_bytes`, `header_offset`, `trailing_bytes_after_final_eof`, `eof_offsets`,
    `startxref_offsets`, `xref_offsets`, `xref_stream_offsets`, `xmp_metadata[].source_offset`,
    and `container_errors[].byte_offset` (`None`) while preserving `incremental_revision_count`
    and `has_multiple_revisions`, preventing exact file-size reconstruction from `eof_offsets[-1]`.
    """
    out = copy.deepcopy(pdf_report)
    if not redact:
        return out

    run_salt = DEFAULT_EPHEMERAL_SALT if salt is None else salt
    out["artifact"] = "[REDACTED_PDF_LABEL]"
    out["file_size_bytes"] = None
    out["trailing_bytes_after_final_eof"] = None

    for offset_key in (
        "header_offset",
        "eof_offsets",
        "startxref_offsets",
        "xref_offsets",
        "xref_stream_offsets",
    ):
        if offset_key in out:
            out[offset_key] = None

    info = out.get("info_metadata")
    if isinstance(info, dict):
        red_info: Dict[str, List[str]] = {}
        for k, vals in info.items():
            if not isinstance(vals, list):
                continue
            if k in ("CreationDate", "ModDate"):
                red_info[k] = ["[REDACTED_PDF_TIMESTAMP]" for _ in vals]
            elif k in ("Producer", "Creator"):
                red_info[k] = [mask_identifier(str(v), salt=run_salt) for v in vals]
            else:
                red_info[k] = ["[REDACTED_TEXT_METADATA]" for _ in vals]
        out["info_metadata"] = red_info

    xmp_list = out.get("xmp_metadata")
    if isinstance(xmp_list, list):
        for xmp in xmp_list:
            if not isinstance(xmp, dict):
                continue
            if "source_offset" in xmp:
                xmp["source_offset"] = None
            for dt_k in ("create_date", "modify_date"):
                if xmp.get(dt_k):
                    xmp[dt_k] = "[REDACTED_PDF_TIMESTAMP]"
            for id_k in ("creator_tool", "producer", "document_id", "instance_id"):
                if xmp.get(id_k):
                    xmp[id_k] = mask_identifier(str(xmp[id_k]), salt=run_salt)

    cerrs = out.get("container_errors")
    if isinstance(cerrs, list):
        for cerr in cerrs:
            if isinstance(cerr, dict) and "byte_offset" in cerr:
                cerr["byte_offset"] = None

    return out


def build_synthetic_incremental_pdf(
    producer_rev1: str = "ReportLab PDF Library 4.0",
    producer_rev2: str = "Synthetic PDF Incremental Editor 1.2",
) -> bytes:
    """Build a valid multi-revision clean-room PDF with two %%EOF and two xref sections."""
    chunks: List[bytes] = [b"%PDF-1.4\n"]
    offsets: Dict[int, int] = {}

    def add_obj(obj_num: int, body: bytes) -> None:
        offsets[obj_num] = sum(len(c) for c in chunks)
        chunks.append(f"{obj_num} 0 obj\n".encode("ascii") + body + b"\nendobj\n")

    add_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    add_obj(
        4,
        (
            f"<< /Producer ({producer_rev1}) /Creator (Meridian ERP 1.0) "
            f"/CreationDate (D:20260318100000Z) >>"
        ).encode("latin-1"),
    )

    xref1_offset = sum(len(c) for c in chunks)
    xref1 = ["xref\n0 5\n0000000000 65535 f \n"]
    for i in range(1, 5):
        xref1.append(f"{offsets[i]:010d} 00000 n \n")
    chunks.append("".join(xref1).encode("ascii"))
    chunks.append(
        f"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R >>\nstartxref\n{xref1_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )

    rev2_info_offset = sum(len(c) for c in chunks)
    chunks.append(
        (
            f"4 0 obj\n<< /Producer ({producer_rev2}) /Creator (Meridian PDF Utility) "
            f"/CreationDate (D:20260318100000Z) /ModDate (D:20260318143000Z) >>\nendobj\n"
        ).encode("latin-1")
    )
    xref2_offset = sum(len(c) for c in chunks)
    chunks.append(
        (
            f"xref\n4 1\n{rev2_info_offset:010d} 00000 n \n"
            f"trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R /Prev {xref1_offset} >>\n"
            f"startxref\n{xref2_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return b"".join(chunks)
