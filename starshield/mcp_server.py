# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Deterministic, strictly offline Model Context Protocol (MCP) stdio server for `starshield-forensics`.

Exposes eight read-only deterministic tools over JSON-RPC 2.0 (`stdio`):
  1. `starshield_demo`                    — Clean-room synthetic showcase across all engines (keyed HMAC mode)
  2. `starshield_precheck_leveldb`        — Zero-PII GO/PARTIAL/NO_GO_COMPACTED_OR_UNSUPPORTED LevelDB check
  3. `starshield_parse_leveldb_log`       — Structural `.log` WAL carver (`<IBAN_GB_9F3A_01>`, zero raw prose)
  4. `starshield_parse_leveldb_store`     — Structural `.ldb`/`.log`/`MANIFEST` live-vs-tombstone reconciler
  5. `starshield_triage_json`             — Structural exported JSON triage (`<ENTITY_9F3A_01>`, zero raw prose)
  6. `starshield_inspect_image_tamper`    — PNG/JPEG ICC & 8BIM container structure observation (not tamper proof)
  7. `starshield_validate_financial_iocs` — Offline Luhn, IBAN, SWIFT, ABA, RF, LEI, TRON & EIP-55 syntax check
  8. `starshield_inspect_pdf_tamper`      — ISO 32000 PDF container structure & incremental revision observation

Privacy-by-Default Structural Airlock:
  `starshield mcp` is NOT a natural-language prompt-injection detector or sanitizer. Instead, default
  masked mode withholds raw free-form chat/document prose and emits only deterministic structural
  skeletons (byte offsets, sequence numbers, soft-delete flags, visible numeric currency amounts, and
  session-tagged `<IBAN_GB_9F3A_01>` / `<TRC20_9F3A_01>` / `<ENTITY_9F3A_01>` placeholders whose IBAN/BIC
  tokens preserve 2-letter ISO country codes). Note: `starshield_demo` uses keyed HMAC masking
  (`[REDACTED_HMAC:...]`) while scrubbing CLI `--unredacted` flag hints from prose placeholders.
  Reverse `detokenize` and `shred-vault` are local CLI commands and are NEVER exposed over MCP.
"""

from __future__ import annotations

import json
import math
import secrets
import sys
from pathlib import Path
from typing import Any, BinaryIO, Dict, Tuple

from starshield import __version__
from starshield.cli import (
    MAX_DEFAULT_MB,
    SafeDiagnosticError,
    _parse_bounded_json_int,
    apply_image_redaction,
    apply_wal_record_redaction,
    build_acquisition_manifest,
    build_demo_report,
    format_masked_error,
    read_bounded_bytes,
    triage_exported_chatsvc_json,
)
from starshield.image_containers import inspect_image_container
from starshield.ioc_validators import VALIDATION_SCOPE_NOTE, extract_validated_iocs
from starshield.leveldb_log import (
    VALID_SCHEMA_MODES,
    dumps_strict_json,
    inspect_chromium_storage_path,
    parse_leveldb_wal,
    sanitize_json_value,
    sanitize_utf8_str,
)
from starshield.leveldb_sstable import parse_leveldb_store
from starshield.pdf_containers import apply_pdf_redaction, inspect_pdf_container
from starshield.pseudonymizer import SessionPseudonymizer, extract_currency_amounts

MAX_RPC_FRAME_BYTES = 4 * 1024 * 1024
SUPPORTED_MCP_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_MCP_VERSION = "2024-11-05"

_READ_ONLY_ANNOTATIONS: Dict[str, Any] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

MCP_TOOLS: list[Dict[str, Any]] = [
    {
        "name": "starshield_demo",
        "title": "Run StarShield Clean-Room Synthetic Demo",
        "description": (
            "Execute StarShield's 5 deterministic offline triage engines on embedded 100% synthetic "
            "specification vectors (LevelDB 32KiB CRC32C WAL carving, PNG/JPEG ICC & 8BIM container "
            "inspection, Luhn/IBAN Mod-97/SWIFT validation, and UTC timestamp corroboration)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_precheck_leveldb",
        "title": "Precheck Chromium / Electron Local LevelDB Storage",
        "description": (
            "Perform a read-only millisecond diagnostic and GO/PARTIAL/NO_GO_COMPACTED_OR_UNSUPPORTED "
            "feasibility check on a local Chromium browser (Chrome/Edge/Brave Local Storage & existing "
            "LevelDB-backed IndexedDB, WhatsApp Web, browser extensions) or Electron desktop app "
            "(Microsoft Teams, Slack Local Storage) directory or .log/.ldb file without leaking raw "
            "content. Distinguishes compacted .ldb SSTables and non-LevelDB SQLite stores (such as newly "
            "created Chrome 156+ IndexedDB stores, while existing LevelDB stores remain in LevelDB)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Local path to a Chromium/Electron IndexedDB/LevelDB folder or .log/.ldb file.",
                },
                "schema_mode": {
                    "type": "string",
                    "enum": list(VALID_SCHEMA_MODES),
                    "default": "auto",
                    "description": "JSON record schema filter (default: auto).",
                },
            },
            "required": ["target_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_parse_leveldb_log",
        "title": "Parse LevelDB .log WAL Structural Skeleton",
        "description": (
            "Carve uncompacted Chromium/Electron LevelDB .log write-ahead log records with 32 KiB "
            "Castagnoli CRC32C (polynomial 0x82F63B78, mask delta 0xA282EAD8) verification. Default masked "
            "mode withholds raw free-form prose and returns deterministic structural skeletons (offsets, "
            "soft-delete flags, visible numeric currency amounts, and session-fingerprinted "
            "<IBAN_GB_XXXX_01> / <ENTITY_XXXX_01> placeholders whose IBAN/BIC tokens expose 2-letter ISO "
            "country codes)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_path": {
                    "type": "string",
                    "description": "Local path to a read-only LevelDB .log write-ahead log copy.",
                },
                "schema_mode": {
                    "type": "string",
                    "enum": list(VALID_SCHEMA_MODES),
                    "default": "auto",
                    "description": "JSON record schema filter (default: auto).",
                },
            },
            "required": ["log_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_parse_leveldb_store",
        "title": "Parse LevelDB Store (.ldb SSTable + MANIFEST + .log) Structural Skeleton",
        "description": (
            "Carve compacted Snappy/uncompressed LevelDB .ldb SSTables, MANIFEST VersionEdits, and .log "
            "write-ahead logs offline, reconciling LIVE_ACTIVE, UI_SOFT_DELETED, and "
            "TOMBSTONED_HISTORICAL_RECOVERED records with per-block Castagnoli CRC32C verification. Default "
            "masked mode withholds raw free-form prose and returns structural skeletons with visible numeric "
            "currency amounts and session-fingerprinted <IBAN_GB_XXXX_01> / <ENTITY_XXXX_01> placeholders."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Local path to a read-only LevelDB directory or standalone .ldb/.sst/.log file.",
                },
                "schema_mode": {
                    "type": "string",
                    "enum": list(VALID_SCHEMA_MODES),
                    "default": "auto",
                    "description": "Record schema filter (default: auto; generic-json includes LocalStorage KV text).",
                },
            },
            "required": ["target_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_triage_json",
        "title": "Triage Exported Messaging JSON Structural Skeleton",
        "description": (
            "Enumerate soft-deleted and edited records in exported messaging JSON artifacts. Default "
            "masked mode withholds raw chat prose and emits deterministic structural skeletons with "
            "visible numeric currency amounts and session-fingerprinted <IBAN_GB_XXXX_01> / "
            "<TRC20_XXXX_01> / <ENTITY_XXXX_01> tokens (IBAN/BIC tokens expose 2-letter ISO country codes)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "json_path": {
                    "type": "string",
                    "description": "Local path to an exported messaging or portal JSON file.",
                },
                "schema_mode": {
                    "type": "string",
                    "enum": list(VALID_SCHEMA_MODES),
                    "default": "auto",
                    "description": "JSON record schema filter (default: auto).",
                },
            },
            "required": ["json_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_inspect_image_tamper",
        "title": "Inspect PNG/JPEG Container Structure",
        "description": (
            "CONTAINER STRUCTURE OBSERVATION ONLY (NOT TAMPER OR FORGERY DETECTION): Deterministically "
            "verify RFC 2083 PNG chunk CRC32 integrity (IHDR/IDAT/IEND/iCCP) and ISO 10918 JPEG APP2 "
            "ICC_PROFILE / APP13 Photoshop 8BIM resource blocks alongside benign OS-save caveats."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Local path to a PNG or JPEG image file.",
                },
            },
            "required": ["image_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_validate_financial_iocs",
        "title": "Validate Identifier Checksums Offline",
        "description": (
            "Scan text offline to extract and mathematically verify ISO/IEC 7812 Luhn card numbers, "
            "89-country ISO 13616 IBAN Mod-97 accounts, 250-territory ISO 9362 SWIFT/BIC codes, UK Sort "
            "Code + Account pairs, US ABA Routing numbers, ISO 11649 RF Creditor References, ISO 17442 "
            "LEIs, TRON TRC-20 Base58Check, and Ethereum EIP-55 addresses. "
            f"{VALIDATION_SCOPE_NOTE}"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text snippet to check offline for mathematical identifier syntax.",
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_inspect_pdf_tamper",
        "title": "Inspect PDF Container Structure & Incremental Save Revisions",
        "description": (
            "CONTAINER STRUCTURE OBSERVATION ONLY (NOT TAMPER OR FORGERY DETECTION): Deterministically "
            "inspect ISO 32000 PDF container structure offline for multi-revision %%EOF / xref / startxref "
            "incremental save history, Info/XMP producer metadata, and embedded action cues (/JavaScript, "
            "/Launch, /EmbeddedFiles) alongside benign e-signature, form-fill, and linearization caveats."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pdf_path": {
                    "type": "string",
                    "description": "Local path to a PDF document file.",
                },
            },
            "required": ["pdf_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
]

_KNOWN_TOOL_NAMES = frozenset(tool["name"] for tool in MCP_TOOLS)
_TOOL_ALLOWED_ARGS: Dict[str, frozenset[str]] = {
    tool["name"]: frozenset(tool["inputSchema"].get("properties", {}).keys())
    for tool in MCP_TOOLS
}


def _dispatch_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    redact: bool,
    max_mb: int,
    session_salt: bytes,
    session_pseudonymizer: SessionPseudonymizer | None = None,
) -> Dict[str, Any]:
    try:
        allowed_keys = _TOOL_ALLOWED_ARGS.get(tool_name, frozenset())
        unexpected_keys = set(arguments.keys()) - allowed_keys
        if unexpected_keys:
            if tool_name == "starshield_demo":
                raise SafeDiagnosticError("starshield_demo accepts no arguments")
            raise SafeDiagnosticError(
                "Unexpected tool argument(s) rejected by strict inputSchema (additionalProperties=false)"
            )

        active_pseudo = session_pseudonymizer if redact else None

        if tool_name == "starshield_demo":
            payload = build_demo_report(redact=redact, salt=session_salt)
            if redact:
                payload = json.loads(
                    json.dumps(payload, ensure_ascii=False).replace(
                        '"[REDACTED_CONTENT]"',
                        '"[WITHHELD_IN_STRUCTURAL_MCP_MODE — free-form prose withheld by default]"',
                    )
                )
        elif tool_name == "starshield_precheck_leveldb":
            raw_target = arguments.get("target_path")
            if not isinstance(raw_target, str) or not raw_target.strip():
                raise SafeDiagnosticError("'target_path' must be a non-empty string")
            schema_mode = arguments.get("schema_mode", "auto")
            if not isinstance(schema_mode, str) or schema_mode not in VALID_SCHEMA_MODES:
                raise SafeDiagnosticError(f"'schema_mode' must be one of {VALID_SCHEMA_MODES}")
            target_path = Path(raw_target)
            pre_report = inspect_chromium_storage_path(
                target_path,
                max_mb=max_mb,
                schema_mode=schema_mode,
                redact=redact,
            )
            payload = {
                "masked_mode": redact,
                "precheck_manifest": pre_report,
            }
        elif tool_name == "starshield_parse_leveldb_log":
            raw_log = arguments.get("log_path")
            if not isinstance(raw_log, str) or not raw_log.strip():
                raise SafeDiagnosticError("'log_path' must be a non-empty string")
            schema_mode = arguments.get("schema_mode", "auto")
            if not isinstance(schema_mode, str) or schema_mode not in VALID_SCHEMA_MODES:
                raise SafeDiagnosticError(f"'schema_mode' must be one of {VALID_SCHEMA_MODES}")
            log_path = Path(raw_log)
            raw_bytes = read_bounded_bytes(log_path, max_mb=max_mb, redact=redact)
            parsed_wal = apply_wal_record_redaction(
                parse_leveldb_wal(raw_bytes, schema_mode=schema_mode),
                redact=redact,
                salt=session_salt,
                pseudonymizer=active_pseudo,
            )
            payload = {
                "masked_mode": redact,
                "acquisition_manifest": build_acquisition_manifest(raw_bytes, log_path.name, redact=redact),
                "leveldb_wal_analysis": parsed_wal,
            }
            if active_pseudo is not None:
                payload["pseudonym_session_id"] = active_pseudo.session_id
                payload["pseudonym_session_tag"] = active_pseudo.session_tag
                payload["pseudonym_token_counts"] = active_pseudo.token_counts()
                if active_pseudo.cap_exceeded_categories():
                    payload["pseudonym_cap_exceeded_categories"] = active_pseudo.cap_exceeded_categories()
        elif tool_name == "starshield_parse_leveldb_store":
            raw_target = arguments.get("target_path")
            if not isinstance(raw_target, str) or not raw_target.strip():
                raise SafeDiagnosticError("'target_path' must be a non-empty string")
            schema_mode = arguments.get("schema_mode", "auto")
            if not isinstance(schema_mode, str) or schema_mode not in VALID_SCHEMA_MODES:
                raise SafeDiagnosticError(f"'schema_mode' must be one of {VALID_SCHEMA_MODES}")
            target_path = Path(raw_target)
            raw_store = parse_leveldb_store(
                target_path,
                max_mb=max_mb,
                schema_mode=schema_mode,
                redact=redact,
            )
            redacted_store = apply_wal_record_redaction(
                raw_store,
                redact=redact,
                salt=session_salt,
                pseudonymizer=active_pseudo,
            )
            payload = {
                "masked_mode": redact,
                "leveldb_store_analysis": redacted_store,
            }
            if active_pseudo is not None:
                payload["pseudonym_session_id"] = active_pseudo.session_id
                payload["pseudonym_session_tag"] = active_pseudo.session_tag
                payload["pseudonym_token_counts"] = active_pseudo.token_counts()
                if active_pseudo.cap_exceeded_categories():
                    payload["pseudonym_cap_exceeded_categories"] = active_pseudo.cap_exceeded_categories()
        elif tool_name == "starshield_triage_json":
            raw_json_p = arguments.get("json_path")
            if not isinstance(raw_json_p, str) or not raw_json_p.strip():
                raise SafeDiagnosticError("'json_path' must be a non-empty string")
            schema_mode = arguments.get("schema_mode", "auto")
            if not isinstance(schema_mode, str) or schema_mode not in VALID_SCHEMA_MODES:
                raise SafeDiagnosticError(f"'schema_mode' must be one of {VALID_SCHEMA_MODES}")
            json_path = Path(raw_json_p)
            raw_bytes = read_bounded_bytes(json_path, max_mb=max_mb, redact=redact)
            parsed_json = sanitize_json_value(
                json.loads(raw_bytes.decode("utf-8"), parse_int=_parse_bounded_json_int)
            )
            triaged = triage_exported_chatsvc_json(
                parsed_json,
                redact=redact,
                salt=session_salt,
                schema_mode=schema_mode,
                pseudonymizer=active_pseudo,
            )
            payload = {
                "masked_mode": redact,
                "acquisition_manifest": build_acquisition_manifest(raw_bytes, json_path.name, redact=redact),
                "triage_result": triaged,
            }
            if active_pseudo is not None:
                payload["pseudonym_session_id"] = active_pseudo.session_id
                payload["pseudonym_session_tag"] = active_pseudo.session_tag
                payload["pseudonym_token_counts"] = active_pseudo.token_counts()
                if active_pseudo.cap_exceeded_categories():
                    payload["pseudonym_cap_exceeded_categories"] = active_pseudo.cap_exceeded_categories()
        elif tool_name == "starshield_inspect_image_tamper":
            raw_img = arguments.get("image_path")
            if not isinstance(raw_img, str) or not raw_img.strip():
                raise SafeDiagnosticError("'image_path' must be a non-empty string")
            img_path = Path(raw_img)
            raw_bytes = read_bounded_bytes(img_path, max_mb=max_mb, redact=redact)
            label = "[REDACTED_IMAGE_LABEL]" if redact else img_path.name
            payload = {
                "masked_mode": redact,
                "acquisition_manifest": build_acquisition_manifest(raw_bytes, img_path.name, redact=redact),
                "image_container_analysis": apply_image_redaction(
                    inspect_image_container(raw_bytes, label),
                    redact=redact,
                    salt=session_salt,
                ),
            }
        elif tool_name == "starshield_validate_financial_iocs":
            raw_text = arguments.get("text")
            if not isinstance(raw_text, str):
                raise SafeDiagnosticError("'text' must be a UTF-8 string")
            raw_text = sanitize_utf8_str(raw_text)
            encoded_len = len(raw_text.encode("utf-8"))
            if encoded_len > int(max_mb) * 1024 * 1024:
                raise SafeDiagnosticError(f"Input text exceeds --max-mb={int(max_mb)} safety limit")
            payload = {
                "epistemic_tier": "DERIVED",
                "masked_mode": redact,
                "tool_version": f"starshield-forensics/{__version__}",
                "validation_scope_note": VALIDATION_SCOPE_NOTE,
                "validated_iocs": extract_validated_iocs(raw_text, redact=redact, salt=session_salt),
            }
            if active_pseudo is not None:
                payload["order_preserving_iocs"] = active_pseudo.pseudonymize_iocs_from_text(raw_text)
                payload["extracted_currency_amounts"] = extract_currency_amounts(raw_text)
                payload["airlock_visibility_note"] = (
                    "validated_iocs uses keyed HMAC tokens; order_preserving_iocs preserves 2-letter ISO "
                    "country codes on IBAN/BIC tokens (<IBAN_CC_...>), and extracted_currency_amounts "
                    "retains numeric amounts unmasked."
                )
                payload["pseudonym_session_tag"] = active_pseudo.session_tag
                payload["pseudonym_session_id"] = active_pseudo.session_id
                if active_pseudo.cap_exceeded_categories():
                    payload["pseudonym_cap_exceeded_categories"] = active_pseudo.cap_exceeded_categories()
        elif tool_name == "starshield_inspect_pdf_tamper":
            raw_pdf = arguments.get("pdf_path")
            if not isinstance(raw_pdf, str) or not raw_pdf.strip():
                raise SafeDiagnosticError("'pdf_path' must be a non-empty string")
            pdf_path = Path(raw_pdf)
            raw_bytes = read_bounded_bytes(pdf_path, max_mb=max_mb, redact=redact)
            label = "[REDACTED_PDF_LABEL]" if redact else pdf_path.name
            payload = {
                "masked_mode": redact,
                "acquisition_manifest": build_acquisition_manifest(raw_bytes, pdf_path.name, redact=redact),
                "pdf_container_analysis": apply_pdf_redaction(
                    inspect_pdf_container(raw_bytes, label),
                    redact=redact,
                    salt=session_salt,
                ),
            }
        else:  # pragma: no cover
            raise SafeDiagnosticError("Unsupported tool name")

        return {
            "content": [
                {
                    "type": "text",
                    "text": dumps_strict_json(payload, indent=2),
                }
            ],
            "isError": False,
        }
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
            err_msg = format_masked_error(exc)
        else:
            if isinstance(exc, RecursionError):
                err_msg = "Input exceeded maximum parser nesting depth"
            elif isinstance(exc, MemoryError):
                err_msg = "Input exceeded available memory bounds"
            else:
                err_msg = str(exc)
        return {
            "content": [
                {
                    "type": "text",
                    "text": dumps_strict_json({"error": err_msg, "masked_mode": redact}, indent=None),
                }
            ],
            "isError": True,
        }
    except Exception as exc:
        err_msg = format_masked_error(exc) if redact else str(exc)
        return {
            "content": [
                {
                    "type": "text",
                    "text": dumps_strict_json({"error": err_msg, "masked_mode": redact}, indent=None),
                }
            ],
            "isError": True,
        }


def handle_mcp_message(
    msg: Any,
    *,
    redact: bool = True,
    max_mb: int = MAX_DEFAULT_MB,
    session_salt: bytes | None = None,
    session_pseudonymizer: SessionPseudonymizer | None = None,
) -> Dict[str, Any] | None:
    """Process a single parsed JSON-RPC 2.0 message and return a response dict (or None for notifications)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        raw_id = msg.get("id") if isinstance(msg, dict) else None
        req_id = (
            raw_id
            if (
                raw_id is None
                or (
                    isinstance(raw_id, (str, int, float))
                    and not isinstance(raw_id, bool)
                    and not (isinstance(raw_id, float) and (math.isnan(raw_id) or math.isinf(raw_id)))
                )
            )
            else None
        )
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request object"},
        }

    method = msg.get("method")
    has_id = "id" in msg
    req_id = msg.get("id")
    if has_id:
        if isinstance(req_id, float) and (math.isnan(req_id) or math.isinf(req_id)):
            req_id = None
        elif req_id is not None and (not isinstance(req_id, (str, int, float)) or isinstance(req_id, bool)):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 'id' member (must be string, number, or null)"},
            }
    if not isinstance(method, str) or not method:
        return {
            "jsonrpc": "2.0",
            "id": req_id if has_id else None,
            "error": {"code": -32600, "message": "Missing or non-string 'method' field"},
        }

    # JSON-RPC 2.0 notifications have no 'id' member and must never emit a response
    if not has_id:
        return None

    params = msg.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": "'params' must be a JSON object when provided"},
        }

    active_salt = session_salt if session_salt is not None else secrets.token_bytes(32)
    active_pseudo = (
        (session_pseudonymizer if session_pseudonymizer is not None else SessionPseudonymizer())
        if redact
        else None
    )

    if method == "initialize":
        requested_ver = params.get("protocolVersion")
        negotiated_ver = requested_ver if requested_ver in SUPPORTED_MCP_VERSIONS else DEFAULT_MCP_VERSION
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated_ver,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "starshield-forensics",
                    "version": __version__,
                },
                "instructions": (
                    "Deterministic, strictly offline, read-only digital forensics & container provenance "
                    "server. Default masked mode withholds free-form chat/document prose and emits only "
                    "structural skeletons + session-tagged <CATEGORY_XXXX_NN> placeholders so raw PII, "
                    "filenames, and file hashes never enter LLM context."
                ),
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

    if method == "resources/templates/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": []}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        tool_name = params.get("name")
        raw_args = params.get("arguments", {})
        if not isinstance(tool_name, str) or tool_name not in _KNOWN_TOOL_NAMES:
            tool_err_msg = (
                "Unknown StarShield MCP tool (caller-supplied tool name suppressed in masked mode)"
                if redact
                else f"Unknown StarShield MCP tool: {tool_name!r}"
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": tool_err_msg},
            }
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": "Tool 'arguments' must be a JSON object"},
            }
        tool_res = _dispatch_tool_call(
            tool_name,
            raw_args,
            redact=redact,
            max_mb=max_mb,
            session_salt=active_salt,
            session_pseudonymizer=active_pseudo,
        )
        return {"jsonrpc": "2.0", "id": req_id, "result": tool_res}

    method_err_msg = (
        "Method not found (caller-supplied method suppressed in masked mode)"
        if redact
        else f"Method not found: {method}"
    )
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": method_err_msg},
    }


def _write_rpc_frame(outstream: BinaryIO, payload: Dict[str, Any], framing: str) -> None:
    try:
        body = dumps_strict_json(payload, indent=None, separators=(",", ":")).encode("utf-8")
    except (RecursionError, MemoryError, ValueError, TypeError):
        body = b'{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal MCP serialization error"}}'
    if framing == "content-length":
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        outstream.write(header + body)
    else:
        outstream.write(body + b"\n")
    outstream.flush()


def _read_next_rpc_frame(instream: BinaryIO) -> Tuple[bytes | None, str, Dict[str, Any] | None]:
    """
    Read one JSON-RPC message supporting both newline-delimited MCP stdio and Content-Length headers.
    Returns (raw_json_bytes, framing_mode, prebuilt_error_response).
    """
    while True:
        first_line = instream.readline(MAX_RPC_FRAME_BYTES + 1)
        if not first_line:
            return None, "line", None
        if len(first_line) > MAX_RPC_FRAME_BYTES:
            return (
                b"",
                "line",
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "JSON-RPC frame exceeds 4 MiB safety limit"},
                },
            )
        stripped = first_line.strip()
        if not stripped:
            continue

        if stripped.lower().startswith(b"content-length:"):
            try:
                content_len = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                return (
                    b"",
                    "content-length",
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Malformed Content-Length header"},
                    },
                )
            if content_len < 0 or content_len > MAX_RPC_FRAME_BYTES:
                return (
                    b"",
                    "content-length",
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Content-Length outside bounded range"},
                    },
                )
            # Consume remaining HTTP-style headers with strict line/byte budget until blank line
            hdr_lines = 0
            hdr_bytes = 0
            while True:
                hdr_line = instream.readline(4097)
                if not hdr_line:
                    return (
                        b"",
                        "content-length",
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32700, "message": "Truncated HTTP-style MCP header block"},
                        },
                    )
                if hdr_line in (b"\r\n", b"\n"):
                    break
                hdr_lines += 1
                hdr_bytes += len(hdr_line)
                if len(hdr_line) > 4096 or hdr_lines > 32 or hdr_bytes > 16384:
                    return (
                        b"",
                        "content-length",
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {"code": -32600, "message": "MCP header block exceeds 16 KiB / 32-header safety limit"},
                        },
                    )
            body = instream.read(content_len)
            if len(body) != content_len:
                return (
                    b"",
                    "content-length",
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Truncated Content-Length JSON-RPC body"},
                    },
                )
            return body, "content-length", None

        return stripped, "line", None


def run_mcp_stdio_server(
    *,
    redact: bool = True,
    max_mb: int = MAX_DEFAULT_MB,
    salt: bytes | None = None,
    vault_file: Path | None = None,
    instream: BinaryIO | None = None,
    outstream: BinaryIO | None = None,
) -> int:
    """Run the deterministic StarShield MCP server over stdio until EOF."""
    if max_mb < 1:
        raise SafeDiagnosticError("--max-mb safety limit must be >= 1 MiB")
    reader = instream if instream is not None else sys.stdin.buffer
    writer = outstream if outstream is not None else sys.stdout.buffer
    session_salt = salt if salt is not None else secrets.token_bytes(32)
    session_pseudo = SessionPseudonymizer() if redact else None
    last_saved_total = 0

    while True:
        raw_bytes, framing, frame_err = _read_next_rpc_frame(reader)
        if raw_bytes is None and frame_err is None:
            return 0
        if frame_err is not None:
            _write_rpc_frame(writer, frame_err, framing)
            return 0

        try:
            parsed = json.loads((raw_bytes or b"").decode("utf-8"), parse_int=_parse_bounded_json_int)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError):
            _write_rpc_frame(
                writer,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error: invalid or over-nested UTF-8 JSON"},
                },
                framing,
            )
            continue

        try:
            response = handle_mcp_message(
                parsed,
                redact=redact,
                max_mb=max_mb,
                session_salt=session_salt,
                session_pseudonymizer=session_pseudo,
            )
        except Exception:
            raw_id = parsed.get("id") if isinstance(parsed, dict) else None
            req_id = (
                raw_id
                if (
                    raw_id is None
                    or (
                        isinstance(raw_id, (str, int, float))
                        and not isinstance(raw_id, bool)
                        and not (isinstance(raw_id, float) and (math.isnan(raw_id) or math.isinf(raw_id)))
                    )
                )
                else None
            )
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32603,
                    "message": "Internal MCP dispatch error (details suppressed in masked mode)",
                },
            }

        vault_persist_warning: str | None = None
        if (
            vault_file is not None
            and redact
            and session_pseudo is not None
            and isinstance(parsed, dict)
            and parsed.get("method") == "tools/call"
            and sum(session_pseudo.token_counts().values()) > last_saved_total
        ):
            try:
                session_pseudo.save_vault_atomic(vault_file)
                last_saved_total = sum(session_pseudo.token_counts().values())
            except (OSError, ValueError, RecursionError, MemoryError):
                vault_persist_warning = (
                    "Unable to persist local token vault; check --vault-file parent directory and permissions"
                )

        if response is not None:
            if vault_persist_warning is not None and isinstance(response.get("result"), dict):
                response["result"]["vault_persist_warning"] = vault_persist_warning
            _write_rpc_frame(writer, response, framing)
