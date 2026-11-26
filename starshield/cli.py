#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
StarShield Forensics CLI (`starshield`)
Author: Ziqi Xiao (@Ziqi)
License: MIT

Deterministic, strictly offline browser cache, container structure, and identifier
syntax triage toolkit for endpoint and evidentiary pre-screening.

Every analytical claim is tagged with an explicit epistemic tier:
  - OBSERVED : Directly present in raw input bytes/fields
  - DERIVED  : Deterministically computed from raw input (CRC32C, Luhn, Mod-97, deltas)
  - INFERRED : Triage lead requiring external corroboration (never standalone proof)
  - UNKNOWN  : Outside the evidentiary boundary of local client artifacts
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import html
import importlib.resources
import json
import math
import os
import re
import secrets
import stat
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from starshield import __version__
from starshield.image_containers import (
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (
    DEFAULT_EPHEMERAL_SALT,
    SUPPORTED_HMAC_DIGESTS,
    VALIDATION_SCOPE_NOTE,
    empty_ioc_dict,
    extract_validated_iocs,
    get_active_hmac_callable,
    get_active_hmac_digest,
    luhn_valid,
    mask_identifier,
    merge_ioc_dicts,
    set_active_hmac_digest,
)
from starshield.leveldb_log import (
    VALID_SCHEMA_MODES,
    SafeDiagnosticError,
    _collect_ioc_scalars,
    build_writebatch,
    classify_carved_json_object,
    dumps_strict_json,
    encode_logical_record_across_blocks,
    inspect_chromium_storage_path,
    normalize_carved_record_fields,
    parse_leveldb_wal,
    read_bounded_bytes,
    sanitize_json_value,
    sanitize_utf8_str,
)
from starshield.leveldb_sstable import (
    build_leveldb_sstable,
    parse_leveldb_sstable,
    parse_leveldb_store,
)
from starshield.pdf_containers import (
    apply_pdf_redaction,
    inspect_pdf_container,
)
from starshield.pseudonymizer import (
    SessionPseudonymizer,
    detokenize_text,
    extract_currency_amounts,
    load_vault_strict,
    shred_vault_file,
)

MAX_DEFAULT_MB = 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_bounded_json_int(num_str: str) -> int:
    if len(num_str.lstrip("+-")) > 64:
        raise SafeDiagnosticError("JSON integer exceeds bounded 64-digit safety limit")
    return int(num_str)


def redact_timestamp(ts: Any) -> Any:
    """Suppress exact dates and times in default masked mode to prevent timeline linkage."""
    if ts is None or ts == "":
        return None
    epoch = parse_strict_utc_ts(ts)
    if epoch is None:
        return "[REDACTED_UNPARSED_TIMESTAMP]"
    return "[REDACTED_UTC_TIMESTAMP]"


def redact_msg_id(msg_id: str, salt: bytes) -> str:
    """Keyed per-run HMAC message token with configurable digest agility."""
    if not msg_id:
        return ""
    digest = hmac.new(salt, sanitize_utf8_str(msg_id).encode("utf-8"), get_active_hmac_callable()).hexdigest()[:12]
    return f"msg_hmac_{digest}"


def build_acquisition_manifest(
    raw: bytes,
    source_label: str,
    redact: bool = True,
    operator: str = "unspecified",
) -> Dict[str, Any]:
    now_utc = datetime.now(timezone.utc)
    return {
        "source_label": "[REDACTED_SOURCE_LABEL]" if redact else source_label,
        "input_byte_length": None if redact else len(raw),
        "input_sha256": (
            "[OMITTED_IN_MASKED_MODE]"
            if redact
            else sha256_bytes(raw)
        ),
        "processed_utc": now_utc.strftime("%Y-%m") if redact else now_utc.isoformat(),
        "tool_version": f"starshield-forensics/{__version__}",
        "operator": operator,
        "redaction_notice": (
            "Default masked mode applies ephemeral per-run HMAC-SHA256 keyed pseudonymization "
            "(not formal legal anonymization under GDPR/UK GDPR) and suppresses raw file hashes, "
            "exact byte lengths, exact UTC dates, filenames, image free-text chunks, and plaintext "
            "bodies by default."
        ),
        "provenance_caveat": (
            "Cryptographic hashes attest post-acquisition byte integrity only; upstream device "
            "authenticity and completeness require an independent acquisition log."
        ),
    }


def format_masked_error(exc: BaseException) -> str:
    """
    Map runtime exceptions to fixed, zero-PII strings in masked mode (`redact=True`).

    Never emits raw `str(exc)` from OS/stdlib/JSON exceptions so nested filenames, subdirectory
    paths, raw byte counts, and malformed payload snippets can never leak.
    """
    if isinstance(exc, SafeDiagnosticError):
        return exc.safe_message
    if isinstance(exc, ValueError) and str(exc) == (
        "Refusing to shred file: target does not carry a valid starshield-token-vault/v1 header"
    ):
        return str(exc)
    if isinstance(exc, RecursionError):
        return "Input exceeded maximum parser nesting depth (path and payload suppressed in masked mode)"
    if isinstance(exc, MemoryError):
        return "Input exceeded available memory bounds (path and payload suppressed in masked mode)"
    if isinstance(exc, UnicodeDecodeError):
        return "Input is not valid UTF-8 text (raw byte context suppressed in masked mode)"
    if isinstance(exc, json.JSONDecodeError):
        return "Malformed JSON input (line/column and snippet suppressed in masked mode)"
    if isinstance(exc, OSError):
        return "Unable to access or read regular input file (filename and OS path suppressed in masked mode)"
    return "Invalid input value or schema violation (details suppressed in masked mode)"


def strip_markup(raw: str) -> str:
    if not raw:
        return ""
    cleaned = sanitize_utf8_str(str(raw))
    cleaned = re.sub(r"<br\s*/?>", "\n", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"<[^<>]{0,4096}>", " ", cleaned)
    cleaned = html.unescape(cleaned)
    return re.sub(r"[ \t]+", " ", cleaned).strip()


def parse_strict_utc_ts(ts: Any) -> float | None:
    """Parse epoch ms/s or explicit timezone-aware ISO-8601. Rejects naive local timestamps."""
    try:
        if ts is None or ts == "" or isinstance(ts, bool):
            return None
        if isinstance(ts, int):
            if not (-10**16 < ts < 10**16):
                return None
            val = float(ts)
            return val / 1000.0 if abs(val) > 1e11 else val
        if isinstance(ts, float):
            if math.isnan(ts) or math.isinf(ts) or not (-1e16 < ts < 1e16):
                return None
            return ts / 1000.0 if abs(ts) > 1e11 else ts
        s = str(ts).strip()
        if not s or len(s) > 128:
            return None
        if len(s) <= 64 and re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", s):
            val = float(s)
            if math.isnan(val) or math.isinf(val) or not (-1e16 < val < 1e16):
                return None
            return val / 1000.0 if abs(val) > 1e11 else val
        normalized = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc).timestamp()
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def apply_wal_record_redaction(
    wal_parsed: Dict[str, Any],
    redact: bool = True,
    salt: bytes | None = None,
    pseudonymizer: SessionPseudonymizer | None = None,
) -> Dict[str, Any]:
    out = copy.deepcopy(wal_parsed)
    run_salt = DEFAULT_EPHEMERAL_SALT if salt is None else salt
    if redact:
        if "file_size_bytes" in out:
            out["file_size_bytes"] = None
        if "target_label" in out:
            out["target_label"] = "[REDACTED_TARGET_PATH]"
        if "manifest_comparator" in out and out["manifest_comparator"] is not None:
            comp_parts = [p.strip() for p in str(out["manifest_comparator"]).split(",") if p.strip()]
            if not comp_parts or any(p not in {"leveldb.BytewiseComparator", "idb_cmp1"} for p in comp_parts):
                out["manifest_comparator"] = "[REDACTED_CUSTOM_COMPARATOR]"
        if "corrupted_blocks_or_frames" in out and isinstance(out["corrupted_blocks_or_frames"], list):
            safe_corr_list: List[Dict[str, Any]] = []
            for c_blk in out["corrupted_blocks_or_frames"]:
                if isinstance(c_blk, dict):
                    projected: Dict[str, Any] = {}
                    for sk in ("byte_offset", "block_index", "record_type", "offset", "length"):
                        if sk in c_blk and isinstance(c_blk[sk], int) and not isinstance(c_blk[sk], bool):
                            projected[sk] = c_blk[sk]
                    if "reason" in c_blk:
                        projected["reason"] = "[REDACTED_CORRUPTION_REASON]" if (
                            "@" in str(c_blk["reason"]) or "://" in str(c_blk["reason"]) or "/" in str(c_blk["reason"])
                        ) else str(c_blk["reason"])[:240]
                    if "source_file" in c_blk:
                        projected["source_file"] = "[REDACTED_SOURCE_FILE]"
                    safe_corr_list.append(projected)
                else:
                    safe_corr_list.append({"reason": "[REDACTED_CORRUPTION_ENTRY]"})
            out["corrupted_blocks_or_frames"] = safe_corr_list
    for rec in out.get("recovered_records", []):
        raw_txt = str(rec.get("cached_content") or "")
        if redact and pseudonymizer is not None:
            rec["extracted_iocs"] = pseudonymizer.pseudonymize_iocs_from_text(raw_txt)
        else:
            rec["extracted_iocs"] = extract_validated_iocs(raw_txt, redact=redact, salt=run_salt)
        if redact:
            if "source_file" in rec:
                rec["source_file"] = "[REDACTED_SOURCE_FILE]"
            rec["key_sha256"] = "[OMITTED_IN_MASKED_MODE]"
            rec["value_sha256"] = "[OMITTED_IN_MASKED_MODE]"
            rec["message_id"] = redact_msg_id(str(rec.get("message_id") or ""), salt=run_salt)
            if pseudonymizer is not None:
                rec["sender_mri"] = (
                    pseudonymizer.assign("ENTITY", str(rec["sender_mri"]))
                    if rec.get("sender_mri")
                    else ""
                )
                if "storage_origin" in rec:
                    rec["storage_origin"] = (
                        pseudonymizer.assign("ORIGIN", str(rec["storage_origin"]))
                        if rec.get("storage_origin")
                        else ""
                    )
                rec["extracted_currency_amounts"] = extract_currency_amounts(raw_txt)
                rec["cached_content"] = (
                    "[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]"
                )
            else:
                rec["sender_mri"] = mask_identifier(str(rec.get("sender_mri") or ""), salt=run_salt)
                if "storage_origin" in rec:
                    rec["storage_origin"] = mask_identifier(str(rec.get("storage_origin") or ""), salt=run_salt)
                rec["cached_content"] = "[REDACTED_CONTENT]"
            rec["composetime"] = redact_timestamp(rec.get("composetime"))
            rec["deletetime"] = redact_timestamp(rec.get("deletetime"))
            rec["edittime"] = redact_timestamp(rec.get("edittime"))
    out["ioc_validation_scope_note"] = VALIDATION_SCOPE_NOTE
    return out


_STANDARD_PNG_CHUNKS = frozenset(
    {
        "IHDR", "PLTE", "IDAT", "IEND", "iCCP", "sRGB", "gAMA", "cHRM",
        "pHYs", "tEXt", "zTXt", "iTXt", "tIME", "bKGD", "tRNS", "sBIT",
        "hIST", "sPLT", "eXIf",
    }
)


def apply_image_redaction(
    img_report: Dict[str, Any],
    redact: bool = True,
    salt: bytes | None = None,
) -> Dict[str, Any]:
    """Return a deep-copied image report suppressing text previews, custom chunk tags, and ICC identifiers."""
    out = copy.deepcopy(img_report)
    if not redact:
        return out
    run_salt = DEFAULT_EPHEMERAL_SALT if salt is None else salt
    out["artifact"] = "[REDACTED_IMAGE_LABEL]"
    for ch in out.get("chunks_summary", []):
        if isinstance(ch, dict):
            if "chunk" in ch and ch.get("chunk") not in _STANDARD_PNG_CHUNKS:
                ch["chunk"] = "[CUSTOM_PNG_CHUNK]"
            if "type" in ch and ch.get("type") not in _STANDARD_PNG_CHUNKS:
                ch["type"] = "[CUSTOM_PNG_CHUNK]"
    for cerr in out.get("crc_errors", []):
        if isinstance(cerr, dict):
            if "chunk" in cerr and cerr.get("chunk") not in _STANDARD_PNG_CHUNKS:
                cerr["chunk"] = "[CUSTOM_PNG_CHUNK]"
            if "chunk_type" in cerr and cerr.get("chunk_type") not in _STANDARD_PNG_CHUNKS:
                cerr["chunk_type"] = "[CUSTOM_PNG_CHUNK]"
    for prof in out.get("icc_profiles", []):
        if not isinstance(prof, dict):
            continue
        if not prof.get("valid_icc_header") and "reason" in prof:
            prof["reason"] = "Invalid or non-ISO-15076-1 ICC profile header (raw signature bytes suppressed in masked mode)"
        if prof.get("png_iccp_name"):
            prof["png_iccp_name"] = mask_identifier(str(prof["png_iccp_name"]), salt=run_salt)
        if prof.get("profile_creator"):
            prof["profile_creator"] = mask_identifier(str(prof["profile_creator"]), salt=run_salt)
        if prof.get("description_hint"):
            prof["description_hint"] = mask_identifier(str(prof["description_hint"]), salt=run_salt)
    for tag in out.get("software_text_chunks", []):
        if isinstance(tag, dict):
            tag["preview"] = "[REDACTED_TEXT_METADATA]"
    return out


def triage_exported_chatsvc_json(
    payload: Dict[str, Any] | List[Any],
    redact: bool = True,
    salt: bytes | None = None,
    schema_mode: str = "auto",
    pseudonymizer: SessionPseudonymizer | None = None,
) -> Dict[str, Any]:
    if schema_mode not in VALID_SCHEMA_MODES:
        raise SafeDiagnosticError("Unsupported schema_mode requested")

    messages: List[Any] = []
    if isinstance(payload, list):
        if not payload or not all(isinstance(x, dict) for x in payload):
            raise SafeDiagnosticError(
                "Expected non-empty JSON array of message objects or JSON object containing 'messages', 'records', or 'conversations'"
            )
        messages = payload
    elif isinstance(payload, dict):
        matched_container = False
        if "messages" in payload:
            matched_container = True
            raw_msgs = payload.get("messages")
            if not isinstance(raw_msgs, list):
                raise SafeDiagnosticError("Expected 'messages' to be a JSON list")
            messages.extend(raw_msgs)
        if "records" in payload:
            matched_container = True
            raw_recs = payload.get("records")
            if not isinstance(raw_recs, list):
                raise SafeDiagnosticError("Expected 'records' to be a JSON list")
            messages.extend(raw_recs)
        if "conversations" in payload:
            matched_container = True
            convs = payload.get("conversations")
            if not isinstance(convs, list):
                raise SafeDiagnosticError("Expected 'conversations' to be a JSON list")
            for conv in convs:
                if not isinstance(conv, dict):
                    continue
                conv_msgs = conv.get("MessageList")
                if conv_msgs is None:
                    conv_msgs = conv.get("messages")
                if isinstance(conv_msgs, list):
                    messages.extend(conv_msgs)
        if not matched_container:
            messages = []
    else:
        raise SafeDiagnosticError(
            "Expected JSON array or object containing 'messages', 'records', or 'conversations'"
        )

    run_salt = DEFAULT_EPHEMERAL_SALT if salt is None else salt
    retracted: List[Dict[str, Any]] = []
    edited: List[Dict[str, Any]] = []
    corpus_iocs = empty_ioc_dict()
    corpus_seen: Dict[str, set[Any]] = {}
    any_scalar_truncated = False

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        schema_tag = classify_carved_json_object(msg, schema_mode=schema_mode)
        if schema_mode == "chatsvc" and schema_tag != "chatsvc":
            continue
        norm = normalize_carved_record_fields(msg, schema_tag or "generic_json")
        body = strip_markup(norm["cached_content"])
        raw_scalars, msg_trunc = _collect_ioc_scalars(msg, cap=4096, max_chars=262_144)
        if msg_trunc:
            any_scalar_truncated = True
        extra_scalars = [strip_markup(s) for s in raw_scalars]
        full_msg_scan = body + ("\n" + "\n".join(s for s in extra_scalars if s and s not in body) if extra_scalars else "")
        # Extract IOCs strictly PER MESSAGE across both body and structured fields without cross-message pairing!
        if redact and pseudonymizer is not None:
            msg_iocs = pseudonymizer.pseudonymize_iocs_from_text(full_msg_scan)
        else:
            msg_iocs = extract_validated_iocs(full_msg_scan, redact=redact, salt=run_salt)
        merge_ioc_dicts(corpus_iocs, msg_iocs, seen_cache=corpus_seen)

        delete_ts = norm["deletetime"]
        edit_ts = norm["edittime"]
        raw_id = norm["message_id"]
        rendered_id = redact_msg_id(raw_id, salt=run_salt) if redact else raw_id
        sender = norm["sender_mri"] or "unknown"
        if redact and pseudonymizer is not None:
            rendered_sender = pseudonymizer.assign("ENTITY", sender)
            rendered_body = (
                "[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]"
            )
            msg_amounts = extract_currency_amounts(body)
        elif redact:
            rendered_sender = mask_identifier(sender, salt=run_salt)
            rendered_body = "[REDACTED_CONTENT]"
            msg_amounts = None
        else:
            rendered_sender = sender
            rendered_body = body
            msg_amounts = extract_currency_amounts(body)
        comp_ts = norm["composetime"]

        if delete_ts:
            rec_entry: Dict[str, Any] = {
                "epistemic_tier": "OBSERVED",
                "schema_detected": schema_tag or "generic_json",
                "id": rendered_id,
                "sender_mri": rendered_sender,
                "compose_time": redact_timestamp(comp_ts) if redact else comp_ts,
                "delete_time": redact_timestamp(delete_ts) if redact else delete_ts,
                "cached_plaintext": rendered_body,
                "extracted_iocs": msg_iocs,
            }
            if msg_amounts is not None:
                rec_entry["extracted_currency_amounts"] = msg_amounts
            retracted.append(rec_entry)
        if edit_ts:
            edited.append(
                {
                    "epistemic_tier": "OBSERVED",
                    "schema_detected": schema_tag or "generic_json",
                    "id": rendered_id,
                    "sender_mri": rendered_sender,
                    "compose_time": redact_timestamp(comp_ts) if redact else comp_ts,
                    "edit_time": redact_timestamp(edit_ts) if redact else edit_ts,
                    "limitation": "Exported JSON retains post-edit content only; pre-edit versions require uncompacted LevelDB sequence history.",
                }
            )

    triage_out: Dict[str, Any] = {
        "input_mode": "exported_message_json",
        "schema_mode": schema_mode,
        "messages_present_in_input": len(messages),
        "soft_deleted_messages_in_input": len(retracted),
        "edited_messages_in_input": len(edited),
        "structured_field_scan_truncated": any_scalar_truncated,
        "completeness_caveat": (
            "Counts reflect records present in the supplied export only; already compacted "
            "or garbage-collected LevelDB records cannot be enumerated from client cache alone."
        ),
        "soft_deleted_records": retracted,
        "edited_records": edited,
        "corpus_validated_iocs": corpus_iocs,
        "ioc_validation_scope_note": VALIDATION_SCOPE_NOTE,
    }
    return triage_out


def corroborate_timestamps(
    payload: Dict[str, Any],
    redact: bool = True,
    salt: bytes | None = None,
) -> Dict[str, Any]:
    """Verify timezone-aware UTC event ordering and clock-skew bounds across generic event pairs."""
    if not isinstance(payload, dict):
        raise SafeDiagnosticError("Expected top-level JSON object for timestamp corroboration")
    run_salt = salt if salt is not None else secrets.token_bytes(32)
    event_pairs = payload.get("timestamp_pairs")
    if event_pairs is None:
        event_pairs = []
    elif not isinstance(event_pairs, list):
        raise SafeDiagnosticError("Expected 'timestamp_pairs' to be a JSON list")

    routing_tags = payload.get("session_metadata")
    if routing_tags is None:
        routing_tags = []
    elif not isinstance(routing_tags, list):
        raise SafeDiagnosticError("Expected 'session_metadata' to be a JSON list")

    matrix: List[Dict[str, Any]] = []
    seen_regions: Dict[str, int] = {}
    for ev in routing_tags:
        if not isinstance(ev, dict):
            continue
        tag = str(ev.get("edge_pop_tag", "")).strip()
        if tag:
            rendered_tag = mask_identifier(tag, salt=run_salt) if redact else tag
            seen_regions[rendered_tag] = seen_regions.get(rendered_tag, 0) + 1

    for r_tag, count in sorted(seen_regions.items(), key=lambda x: -x[1]):
        matrix.append(
            {
                "observation": f"Infrastructure edge tag {r_tag} observed across {count} session record(s).",
                "provenance": "session_metadata[].edge_pop_tag",
                "epistemic_tier": "OBSERVED",
                "alternative_explanations": [
                    "Edge PoP tags reflect CDN or media-relay latency routing, NOT confirmed physical endpoint geolocation.",
                    "Repeated events within a single persistent session are correlated rather than statistically independent.",
                ],
            }
        )

    intervals: List[Dict[str, Any]] = []
    for idx, pair in enumerate(event_pairs):
        if not isinstance(pair, dict):
            continue
        raw_label = str(pair.get("label", f"pair_{idx + 1}"))
        label = f"pair_{idx + 1}" if redact else raw_label
        t_start = parse_strict_utc_ts(pair.get("start_utc"))
        t_end = parse_strict_utc_ts(pair.get("end_utc"))
        if t_start is None or t_end is None:
            intervals.append(
                {
                    "label": label,
                    "raw_label": None if redact else raw_label,
                    "status": "INVALID_OR_TIMEZONE_NAIVE_TIMESTAMP",
                    "epistemic_tier": "UNKNOWN",
                }
            )
            continue
        delta = round(t_end - t_start, 3)
        if delta < 0:
            intervals.append(
                {
                    "label": label,
                    "raw_label": None if redact else raw_label,
                    "delta_seconds": None if redact else delta,
                    "status": "REJECTED_NEGATIVE_DELTA_CLOCK_SKEW_OR_BAD_INPUT",
                    "epistemic_tier": "UNKNOWN",
                }
            )
        else:
            intervals.append(
                {
                    "label": label,
                    "raw_label": None if redact else raw_label,
                    "delta_seconds": "[REDACTED_INTERVAL]" if redact else delta,
                    "status": "DERIVED_NON_NEGATIVE_INTERVAL",
                    "epistemic_tier": "DERIVED",
                    "caveat": "Cross-system timestamp intervals depend on NTP clock synchronization across endpoints.",
                }
            )

    return {
        "corroboration_matrix": matrix,
        "timestamp_interval_observations": intervals,
    }


def summarize_corpus_linguistics(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Compute strictly descriptive utterance length & punctuation statistics (ZERO clinical/legal diagnosis)."""
    if not isinstance(payload, dict):
        raise SafeDiagnosticError("Expected top-level JSON object for corpus linguistics summary")
    messages = payload.get("messages")
    if messages is None:
        messages = []
    elif not isinstance(messages, list):
        raise SafeDiagnosticError("Expected 'messages' to be a JSON list")
    subject_id = payload.get("subject_sender_id", "user:subject_01")

    utterances = [
        strip_markup(m.get("content") or m.get("text") or m.get("body") or "")
        for m in messages
        if isinstance(m, dict)
        and (m.get("from") == subject_id or m.get("user") == subject_id or m.get("sender") == subject_id)
        and strip_markup(m.get("content") or m.get("text") or m.get("body") or "")
    ]

    n = len(utterances)
    lengths = [len(u) for u in utterances]
    in_3_to_12 = [u for u in utterances if 3 <= len(u) <= 12]
    no_mid_punct = [
        u for u in utterances if not re.search(r"[,.;:!?，。；：！？]", u[:-1] if len(u) > 1 else u)
    ]

    return {
        "epistemic_tier": "DERIVED",
        "sample_size": n,
        "minimum_recommended_sample_met": n >= 30,
        "median_char_length": round(statistics.median(lengths), 2) if lengths else None,
        "utterance_ratio_3_to_12_chars": round(len(in_3_to_12) / n, 4) if n else None,
        "zero_mid_punctuation_ratio": round(len(no_mid_punct) / n, 4) if n else None,
        "methodological_limitation": (
            "Descriptive text statistics only. Short, unpunctuated replies are routine in "
            "workplace and mobile messaging and never establish psychological state or legal vulnerability."
        ),
    }


def build_synthetic_leveldb_wal_bytes() -> bytes:
    """
    Create a clean-room, specification-only LevelDB `.log` test vector emulating Chromium
    IndexedDB binary prefixes (`\\xff\\x15` Blink header) + cross-32KiB `FIRST/MIDDLE/LAST` blocks.
    Uses standard RFC/ISO textbook test values from a fictional 2025 UK supplier-invoice scenario.
    """
    blink_prefix = b"\xff\x15\xfe\x00\x22"
    msg1 = blink_prefix + json.dumps(
        {
            "id": "msg_spec_0001",
            "from": "user:impersonated_supplier_01",
            "composetime": "2025-03-18T10:00:00Z",
            "content": (
                "Updated UK Faster Payments supplier account for Invoice INV-2025-0100 (GBP 18,400.00): "
                "Sort Code 00-00-00 Account 00000000."
            ),
            "properties": {
                "deletetime": "1742292600000",
                "nested_meta": {"schema_hint": "chromium_idb_spec_vector"},
            },
        }
    ).encode("utf-8")

    # Standard ISO/IEC 7812 Luhn test vector prefix (620000000000000x -> 6200000000000005)
    prefix = "620000000000000"
    valid_test_card = next(prefix + d for d in "0123456789" if luhn_valid(prefix + d))
    # Pad second WriteBatch (>66 KiB) so it spans 3 physical 32KiB blocks via FIRST + MIDDLE + LAST
    padding_blob = "X" * 68000
    msg2 = blink_prefix + json.dumps(
        {
            "id": "msg_spec_0002",
            "from": "user:impersonated_supplier_01",
            "composetime": "2025-03-18T14:30:00Z",
            "content": (
                f"Secondary reserve IBAN GB82WEST12345698765432 (SWIFT NWBKGB2LXXX), "
                f"Norway test IBAN NO9386011117947, and Luhn test card {valid_test_card}."
            ),
            "properties": {"deletetime": "1742308800000", "blob_pad": padding_blob},
        }
    ).encode("utf-8")

    wb1 = build_writebatch(1001, [(1, b"\x00\x01\x02\x01idb:msg:spec_0001", msg1)])
    wb2 = build_writebatch(1002, [(1, b"\x00\x01\x02\x01idb:msg:spec_0002", msg2)])

    part1 = encode_logical_record_across_blocks(wb1, initial_block_used=0)
    part2 = encode_logical_record_across_blocks(wb2, initial_block_used=len(part1))
    return part1 + part2


def build_synthetic_leveldb_sstable_bytes() -> bytes:
    """Build a spec-compliant Snappy-compressed `.ldb` SSTable with an active record and a tombstoned record."""
    rec_active = json.dumps(
        {
            "id": "sst_spec_0101",
            "from": "8:live:vendor_ops_01",
            "composetime": "2025-03-19T09:00:00Z",
            "content": "Confirmed settlement reference RF18539007547034 for EUR 12,500.00 to IBAN DE89370400440532013000.",
        }
    ).encode("utf-8")
    rec_historical = json.dumps(
        {
            "id": "sst_spec_0100",
            "from": "8:live:vendor_ops_01",
            "composetime": "2025-03-19T08:15:00Z",
            "content": "Superseded beneficiary draft IBAN GB82WEST12345698765432 prior to tombstone deletion.",
        }
    ).encode("utf-8")
    return build_leveldb_sstable(
        [
            (b"idb:conv:0101", 2010, 1, rec_active),
            (b"idb:conv:0100", 2005, 0, b""),
            (b"idb:conv:0100", 2001, 1, rec_historical),
        ],
        compress=True,
    )


def build_demo_report(redact: bool = True, salt: bytes | None = None) -> Dict[str, Any]:
    run_salt = salt if salt is not None else secrets.token_bytes(32)
    try:
        sample_json_bytes = (
            importlib.resources.files("starshield.data")
            .joinpath("synthetic_case_benchmark.json")
            .read_bytes()
        )
    except Exception:
        repo_sample = Path(__file__).resolve().parent.parent / "samples" / "synthetic_case_benchmark.json"
        sample_json_bytes = repo_sample.read_bytes()
    payload = json.loads(sample_json_bytes.decode("utf-8"))

    wal_bytes = build_synthetic_leveldb_wal_bytes()
    wal_parsed = apply_wal_record_redaction(parse_leveldb_wal(wal_bytes), redact=redact, salt=run_salt)
    sst_bytes = build_synthetic_leveldb_sstable_bytes()
    sst_parsed = apply_wal_record_redaction(parse_leveldb_sstable(sst_bytes), redact=redact, salt=run_salt)

    valid_png = build_valid_png_with_iccp(
        "Display P3",
        "APPL",
        software_text="Software\x00QuickShot Raster Editor 4.2",
    )
    valid_jpeg = build_valid_jpeg_with_icc_and_8bim("Display P3", "APPL", split_icc_chunks=2)

    return {
        "toolkit": f"starshield-forensics v{__version__} (Deterministic Chromium Cache & Container Provenance Toolkit)",
        "author": "Ziqi Xiao (@Ziqi)",
        "dataset_notice": "100% CLEAN-ROOM SPECIFICATION TEST VECTORS (2025 UK SUPPLIER INVOICE SCENARIO — TLP:CLEAR)",
        "acquisition_manifest": build_acquisition_manifest(
            sample_json_bytes,
            "synthetic_case_benchmark.json",
            redact=redact,
        ),
        "engine_1_raw_leveldb_wal_carver": wal_parsed,
        "engine_1b_snappy_sstable_carver": sst_parsed,
        "engine_2_exported_json_triage": triage_exported_chatsvc_json(payload, redact=redact, salt=run_salt),
        "engine_3_timestamp_and_session_corroboration": corroborate_timestamps(payload, redact=redact, salt=run_salt),
        "engine_4a_structural_png_metadata": apply_image_redaction(
            inspect_image_container(valid_png, "spec_valid_iccp_sample.png"),
            redact=redact,
            salt=run_salt,
        ),
        "engine_4b_structural_jpeg_metadata": apply_image_redaction(
            inspect_image_container(valid_jpeg, "spec_valid_app2_8bim_sample.jpg"),
            redact=redact,
            salt=run_salt,
        ),
        "engine_5_descriptive_linguistics": summarize_corpus_linguistics(payload),
    }


def _guard_vault_not_same_file(vault_file: Path | None, input_file: Path | None) -> None:
    """Reject `--vault-file` if it is a symlink/hardlink, aliases an input inode, or sits inside a target directory."""
    if vault_file is None:
        return
    st_v: os.stat_result | None = None
    try:
        st_v = os.lstat(vault_file)
    except FileNotFoundError:
        st_v = None
    except OSError as exc:
        raise SafeDiagnosticError("Unable to verify token vault target path safety") from exc

    if st_v is not None:
        if stat.S_ISLNK(st_v.st_mode):
            raise SafeDiagnosticError("Refusing to write token vault through a symbolic link")
        if st_v.st_nlink > 1:
            raise SafeDiagnosticError("Refusing to write token vault to a multi-hardlink target")

    if input_file is None:
        return
    in_target = Path(os.path.expanduser(str(input_file)))
    try:
        st_i_lstat = os.lstat(in_target)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SafeDiagnosticError("Unable to verify input artifact path for token vault safety") from exc

    st_i_stat: os.stat_result | None = None
    try:
        st_i_stat = os.stat(in_target)
    except FileNotFoundError:
        st_i_stat = None
    except OSError as exc:
        raise SafeDiagnosticError("Unable to resolve input artifact target for token vault safety") from exc

    if st_v is not None and (
        os.path.samestat(st_v, st_i_lstat)
        or (st_i_stat is not None and os.path.samestat(st_v, st_i_stat))
    ):
        raise SafeDiagnosticError(
            "Refusing to overwrite existing file: vault path aliases input artifact (not a valid starshield-token-vault/v1 file)"
        )

    dir_targets = [s for s in (st_i_lstat, st_i_stat) if s is not None and stat.S_ISDIR(s.st_mode)]
    if not dir_targets:
        clean_in_name = in_target.name.rstrip(" .")
        is_numbered_ldb_file = bool(re.match(r"^[0-9]+\.(?:log|ldb|sst)$", clean_in_name, re.IGNORECASE))
        in_parent = in_target.parent
        parent_has_ldb_markers = False
        if not is_numbered_ldb_file and in_parent.is_dir():
            try:
                for entry in os.scandir(in_parent):
                    en = entry.name.rstrip(" .")
                    if en.upper() in ("CURRENT", "LOCK") or en.upper().startswith("MANIFEST-"):
                        parent_has_ldb_markers = True
                        break
                    if en.lower().endswith((".ldb", ".sst")):
                        parent_has_ldb_markers = True
                        break
            except OSError:
                parent_has_ldb_markers = False
        if is_numbered_ldb_file or parent_has_ldb_markers:
            try:
                dir_targets.append(os.stat(in_parent))
            except OSError:
                pass

    if dir_targets:
        raw_v = Path(os.path.expanduser(str(vault_file)))
        anc = raw_v if raw_v.is_absolute() else (Path(os.getcwd()) / raw_v)
        deepest_existing: Path | None = None
        probe = anc.parent
        while True:
            try:
                os.stat(probe)
                deepest_existing = probe
                break
            except FileNotFoundError:
                if probe == probe.parent:
                    break
                probe = probe.parent
            except OSError as exc:
                raise SafeDiagnosticError("Unable to verify token vault ancestor directory safety") from exc

        anc_candidates: List[Path] = []
        if deepest_existing is not None:
            for start_p in (deepest_existing, Path(os.path.realpath(deepest_existing))):
                cur = start_p
                while True:
                    anc_candidates.append(cur)
                    if cur == cur.parent:
                        break
                    cur = cur.parent

        for cand in anc_candidates:
            try:
                st_anc = os.stat(cand)
            except OSError as exc:
                raise SafeDiagnosticError("Unable to stat token vault ancestor directory") from exc
            for dt_st in dir_targets:
                if os.path.samestat(st_anc, dt_st):
                    raise SafeDiagnosticError(
                        "Refusing to create or write token vault inside the target evidence directory"
                    )


def run_demo(redact: bool = True, salt: bytes | None = None) -> int:
    report = build_demo_report(redact=redact, salt=salt)
    print(dumps_strict_json(report, indent=2))
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="starshield",
        description=f"StarShield Forensics v{__version__} — Deterministic Chromium Cache & Container Triage CLI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"starshield-forensics {__version__}",
    )
    parser.add_argument(
        "--unredacted",
        action="store_true",
        help="Include unmasked identifiers, raw SHA-256, exact timestamps, and plaintext bodies (offline lab use only)",
    )
    parser.add_argument(
        "--max-mb",
        type=int,
        default=MAX_DEFAULT_MB,
        help=f"Maximum input file size in MiB (default: {MAX_DEFAULT_MB})",
    )
    parser.add_argument(
        "--hmac-digest",
        choices=tuple(SUPPORTED_HMAC_DIGESTS.keys()),
        default="sha256",
        help="HMAC digest algorithm for keyed pseudonymization agility (default: sha256)",
    )
    parser.add_argument(
        "--hmac-key-file",
        type=Path,
        default=None,
        help="Optional external secret key file (>=16 bytes) for cross-run pseudonymization without hardcoded keys",
    )
    parser.add_argument(
        "--pseudonymize",
        action="store_true",
        help="Emit structural skeleton with session-tagged placeholders (<IBAN_GB_9F3AC41D_01>, <ENTITY_9F3AC41D_01>) while withholding raw prose",
    )
    parser.add_argument(
        "--vault-file",
        type=Path,
        default=None,
        help="Persist local 0600 reverse token vault JSON (prefer /dev/shm) for offline `starshield detokenize` (implies --pseudonymize)",
    )
    parser.add_argument(
        "--vault-overwrite",
        action="store_true",
        help="Explicitly allow replacing an existing starshield-token-vault/v1 file created by a prior session",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Run deterministic triage pipeline on clean-room specification test vectors")

    p_pre = sub.add_parser(
        "precheck",
        help="Zero-PII local GO/PARTIAL/NO-GO feasibility check on a Chromium storage folder or .log/.ldb file",
    )
    p_pre.add_argument("target_path", type=Path, help="Read-only Chromium IndexedDB/LevelDB folder or .log/.ldb file")
    p_pre.add_argument(
        "--schema",
        choices=VALID_SCHEMA_MODES,
        default="auto",
        help="JSON record schema filter (default: auto — supports Teams/Skype, Slack, WhatsApp Web & B2B portals)",
    )

    p_wal = sub.add_parser("parse-leveldb-log", help="Parse Chromium IndexedDB LevelDB .log file with byte offsets & CRC32C")
    p_wal.add_argument("log_file", type=Path, help="Read-only copy of LevelDB .log write-ahead log")
    p_wal.add_argument(
        "--schema",
        choices=VALID_SCHEMA_MODES,
        default="auto",
        help="JSON record schema filter (default: auto — supports Teams/Skype, Slack, WhatsApp Web & B2B portals)",
    )

    p_store = sub.add_parser(
        "parse-leveldb-store",
        help="Parse Chromium/Electron LevelDB folder or Snappy .ldb SSTable with MANIFEST live-vs-tombstone reconciliation",
    )
    p_store.add_argument("target_path", type=Path, help="Read-only LevelDB directory or standalone .ldb/.sst/.log file")
    p_store.add_argument(
        "--schema",
        choices=VALID_SCHEMA_MODES,
        default="auto",
        help="Record schema filter (default: auto; use generic-json to include LocalStorage KV string slices)",
    )

    p_rec = sub.add_parser("triage-json", help="Triage exported message JSON for soft-deleted records & validated IOCs")
    p_rec.add_argument("json_file", type=Path, help="Path to exported message JSON")
    p_rec.add_argument(
        "--schema",
        choices=VALID_SCHEMA_MODES,
        default="auto",
        help="JSON record schema filter (default: auto)",
    )

    p_sig = sub.add_parser("corroborate-timestamps", help="Verify timezone-aware UTC intervals and session metadata")
    p_sig.add_argument("json_file", type=Path, help="Path to timestamp/session JSON")

    p_img = sub.add_parser("inspect-image", help="Parse RFC 2083 PNG / ISO 10918 JPEG ICC & APP13 container metadata")
    p_img.add_argument("image_file", type=Path, help="Path to PNG or JPEG image")

    p_pdf = sub.add_parser(
        "inspect-pdf",
        help="Inspect PDF container structure, incremental save revisions (%%EOF/xref), XMP metadata & action cues",
    )
    p_pdf.add_argument("pdf_file", type=Path, help="Path to local PDF document")

    p_dur = sub.add_parser("summarize-linguistics", help="Compute descriptive utterance length & punctuation statistics")
    p_dur.add_argument("json_file", type=Path, help="Path to chat transcript JSON")

    p_detok = sub.add_parser(
        "detokenize",
        help="Locally restore <IBAN_GB_9F3AC41D_01>/<TRC20_9F3AC41D_01>/<ENTITY_9F3AC41D_01> placeholders using a 0600 token vault file",
    )
    p_detok.add_argument("--vault", required=True, type=Path, help="Path to local starshield-token-vault/v1 JSON file")
    p_detok.add_argument("--input", type=Path, default=None, help="Optional input text/markdown/JSON file to detokenize")
    p_detok.add_argument("--text", type=str, default=None, help="Optional inline string to detokenize")

    p_shred = sub.add_parser(
        "shred-vault",
        help=(
            "Best-effort logical overwrite (random + zero passes + fsync) and unlink of a local 0600 token vault file "
            "(does not guarantee physical block erasure on SSD/NVMe or APFS/Btrfs/ZFS CoW; prefer /dev/shm)"
        ),
    )
    p_shred.add_argument(
        "--vault",
        required=True,
        type=Path,
        help="Path to local starshield-token-vault/v1 file for best-effort logical overwrite + unlink",
    )

    sub.add_parser(
        "mcp",
        help="Run deterministic read-only Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio",
    )

    args = parser.parse_args(argv)
    redact = not args.unredacted
    use_pseudo = bool(args.pseudonymize or args.vault_file is not None)
    prev_digest = get_active_hmac_digest()
    set_active_hmac_digest(args.hmac_digest)

    try:
        if args.unredacted and (args.pseudonymize or args.vault_file is not None or args.vault_overwrite):
            raise SafeDiagnosticError("--unredacted cannot be combined with --pseudonymize or --vault-file")
        if (args.pseudonymize or args.vault_file is not None or args.vault_overwrite) and args.command not in (
            "parse-leveldb-log",
            "parse-leveldb-store",
            "triage-json",
            "mcp",
        ):
            raise SafeDiagnosticError(
                f"--pseudonymize / --vault-file is only supported by tokenizing subcommands "
                f"(parse-leveldb-log, parse-leveldb-store, triage-json, mcp), not '{args.command}'"
            )
        if args.unredacted and args.command != "mcp":
            sys.stderr.write(
                "[starshield] WARNING: --unredacted lab mode active; privacy airlock disabled.\n"
            )
        if args.hmac_key_file is not None:
            _guard_vault_not_same_file(args.vault_file, args.hmac_key_file)
            raw_key = read_bounded_bytes(args.hmac_key_file, max_mb=1, redact=redact).strip()
            if len(raw_key) < 16:
                raise SafeDiagnosticError("External --hmac-key-file must contain at least 16 secret bytes")
            run_salt = raw_key
        else:
            run_salt = secrets.token_bytes(32)
        pseudo = SessionPseudonymizer() if (redact and use_pseudo) else None
        if args.command == "demo":
            return run_demo(redact=redact, salt=run_salt)

        if args.command == "precheck":
            _guard_vault_not_same_file(args.vault_file, args.target_path)
            pre_report = inspect_chromium_storage_path(
                args.target_path,
                max_mb=args.max_mb,
                schema_mode=args.schema,
                redact=redact,
            )
            print(dumps_strict_json({"precheck_manifest": pre_report}, indent=2))
            return 0

        if args.command == "parse-leveldb-log":
            _guard_vault_not_same_file(args.vault_file, args.log_file)
            raw = read_bounded_bytes(args.log_file, args.max_mb, redact=redact)
            parsed = apply_wal_record_redaction(
                parse_leveldb_wal(raw, schema_mode=args.schema),
                redact=redact,
                salt=run_salt,
                pseudonymizer=pseudo,
            )
            if pseudo is not None and args.vault_file is not None:
                pseudo.save_vault_atomic(args.vault_file, allow_overwrite=args.vault_overwrite)
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.log_file.name, redact=redact),
                "leveldb_wal_analysis": parsed,
            }
            if pseudo is not None:
                out["pseudonym_session_id"] = pseudo.session_id
                out["pseudonym_session_tag"] = pseudo.session_tag
                out["pseudonym_token_counts"] = pseudo.token_counts()
                if pseudo.cap_exceeded_categories():
                    out["pseudonym_cap_exceeded_categories"] = pseudo.cap_exceeded_categories()
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "parse-leveldb-store":
            _guard_vault_not_same_file(args.vault_file, args.target_path)
            raw_store = parse_leveldb_store(
                args.target_path,
                max_mb=args.max_mb,
                schema_mode=args.schema,
                redact=redact,
            )
            redacted_store = apply_wal_record_redaction(
                raw_store,
                redact=redact,
                salt=run_salt,
                pseudonymizer=pseudo,
            )
            if pseudo is not None and args.vault_file is not None:
                pseudo.save_vault_atomic(args.vault_file, allow_overwrite=args.vault_overwrite)
            out = {
                "leveldb_store_analysis": redacted_store,
            }
            if pseudo is not None:
                out["pseudonym_session_id"] = pseudo.session_id
                out["pseudonym_session_tag"] = pseudo.session_tag
                out["pseudonym_token_counts"] = pseudo.token_counts()
                if pseudo.cap_exceeded_categories():
                    out["pseudonym_cap_exceeded_categories"] = pseudo.cap_exceeded_categories()
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "triage-json":
            _guard_vault_not_same_file(args.vault_file, args.json_file)
            raw = read_bounded_bytes(args.json_file, args.max_mb, redact=redact)
            data = sanitize_json_value(json.loads(raw.decode("utf-8"), parse_int=_parse_bounded_json_int))
            triaged = triage_exported_chatsvc_json(
                data,
                redact=redact,
                salt=run_salt,
                schema_mode=args.schema,
                pseudonymizer=pseudo,
            )
            if pseudo is not None and args.vault_file is not None:
                pseudo.save_vault_atomic(args.vault_file, allow_overwrite=args.vault_overwrite)
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.json_file.name, redact=redact),
                "triage_result": triaged,
            }
            if pseudo is not None:
                out["pseudonym_session_id"] = pseudo.session_id
                out["pseudonym_session_tag"] = pseudo.session_tag
                out["pseudonym_token_counts"] = pseudo.token_counts()
                if pseudo.cap_exceeded_categories():
                    out["pseudonym_cap_exceeded_categories"] = pseudo.cap_exceeded_categories()
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "corroborate-timestamps":
            _guard_vault_not_same_file(args.vault_file, args.json_file)
            raw = read_bounded_bytes(args.json_file, args.max_mb, redact=redact)
            data = sanitize_json_value(json.loads(raw.decode("utf-8"), parse_int=_parse_bounded_json_int))
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.json_file.name, redact=redact),
                "corroboration": corroborate_timestamps(data, redact=redact, salt=run_salt),
            }
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "inspect-image":
            _guard_vault_not_same_file(args.vault_file, args.image_file)
            raw = read_bounded_bytes(args.image_file, args.max_mb, redact=redact)
            label = "[REDACTED_IMAGE_LABEL]" if redact else args.image_file.name
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.image_file.name, redact=redact),
                "image_container_analysis": apply_image_redaction(
                    inspect_image_container(raw, label),
                    redact=redact,
                    salt=run_salt,
                ),
            }
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "inspect-pdf":
            _guard_vault_not_same_file(args.vault_file, args.pdf_file)
            raw = read_bounded_bytes(args.pdf_file, args.max_mb, redact=redact)
            label = "[REDACTED_PDF_LABEL]" if redact else args.pdf_file.name
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.pdf_file.name, redact=redact),
                "pdf_container_analysis": apply_pdf_redaction(
                    inspect_pdf_container(raw, label),
                    redact=redact,
                    salt=run_salt,
                ),
            }
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "summarize-linguistics":
            _guard_vault_not_same_file(args.vault_file, args.json_file)
            raw = read_bounded_bytes(args.json_file, args.max_mb, redact=redact)
            data = sanitize_json_value(json.loads(raw.decode("utf-8"), parse_int=_parse_bounded_json_int))
            out = {
                "acquisition_manifest": build_acquisition_manifest(raw, args.json_file.name, redact=redact),
                "descriptive_linguistics": summarize_corpus_linguistics(data),
            }
            print(dumps_strict_json(out, indent=2))
            return 0

        if args.command == "detokenize":
            _guard_vault_not_same_file(args.vault, args.input)
            if args.vault_file is not None:
                _guard_vault_not_same_file(args.vault_file, args.input)
            mapping, vault_tag = load_vault_strict(args.vault)
            if args.text is not None:
                src_text = sanitize_utf8_str(args.text)
            elif args.input is not None:
                src_text = sanitize_utf8_str(read_bounded_bytes(args.input, args.max_mb, redact=redact).decode("utf-8"))
            else:
                limit_b = int(args.max_mb) * 1024 * 1024
                raw_in = sys.stdin.buffer.read(limit_b + 1)
                if len(raw_in) > limit_b:
                    raise SafeDiagnosticError(f"Stdin exceeds --max-mb={int(args.max_mb)} safety limit")
                src_text = sanitize_utf8_str(raw_in.decode("utf-8"))
            restored, count, unmatched = detokenize_text(
                src_text,
                mapping,
                expected_session_tag=vault_tag,
            )
            detok_out: Dict[str, Any] = {
                "detokenized_text": restored,
                "placeholders_restored": count,
                "vault_session_tag": vault_tag,
                "unmatched_or_foreign_tokens": unmatched,
                "tool_version": f"starshield-forensics/{__version__}",
            }
            if unmatched:
                detok_out["cross_session_warning"] = (
                    f"Left {len(unmatched)} placeholder(s) unexpanded because their session tag "
                    f"did not match vault session_tag '{vault_tag}' or was absent from vault."
                )
            print(dumps_strict_json(detok_out, indent=2))
            return 0

        if args.command == "shred-vault":
            shred_report = shred_vault_file(args.vault)
            shred_report["tool_version"] = f"starshield-forensics/{__version__}"
            print(dumps_strict_json(shred_report, indent=2))
            return 0

        if args.command == "mcp":
            from starshield.mcp_server import run_mcp_stdio_server

            return run_mcp_stdio_server(
                redact=redact,
                max_mb=args.max_mb,
                salt=run_salt,
                vault_file=args.vault_file,
                allow_vault_overwrite=args.vault_overwrite,
            )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        UnicodeDecodeError,
        RecursionError,
        MemoryError,
    ) as exc:
        if redact:
            safe_msg = format_masked_error(exc)
            sys.stderr.write(dumps_strict_json({"error": safe_msg, "masked_mode": True}, indent=None) + "\n")
        else:
            if isinstance(exc, RecursionError):
                lab_msg = "Input exceeded maximum parser nesting depth"
            elif isinstance(exc, MemoryError):
                lab_msg = "Input exceeded available memory bounds"
            else:
                lab_msg = str(exc)
            sys.stderr.write(dumps_strict_json({"error": lab_msg, "masked_mode": False}, indent=None) + "\n")
        return 2
    except Exception as exc:
        if redact:
            safe_msg = format_masked_error(exc)
            sys.stderr.write(dumps_strict_json({"error": safe_msg, "masked_mode": True}, indent=None) + "\n")
        else:
            sys.stderr.write(dumps_strict_json({"error": str(exc), "masked_mode": False}, indent=None) + "\n")
        return 2
    finally:
        set_active_hmac_digest(prev_digest)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
