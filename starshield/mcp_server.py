# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Deterministic, strictly offline Model Context Protocol (MCP) stdio server for `starshield-forensics`.

Exposes four read-only deterministic tools over JSON-RPC 2.0 (`stdio`):
  1. `starshield_demo`                    — Clean-room synthetic showcase across all 5 engines
  2. `starshield_precheck_leveldb`        — Zero-PII GO/PARTIAL/NO_GO Chromium & Electron LevelDB check
  3. `starshield_inspect_image_tamper`    — PNG/JPEG ICC & Photoshop 8BIM container provenance check
  4. `starshield_validate_financial_iocs` — Offline Luhn, 89-country IBAN Mod-97, SWIFT/BIC & UK Sort Code validator

Privacy-by-Default Architecture:
  Unless `--unredacted` is explicitly passed at server startup inside an isolated offline lab,
  every tool response enforces ephemeral per-session HMAC-SHA256 pseudonymization so raw PII,
  filenames, local OS paths, and raw file hashes never enter cloud LLM context windows.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from typing import Any, BinaryIO, Dict, Tuple

from starshield import __version__
from starshield.cli import (
    MAX_DEFAULT_MB,
    apply_image_redaction,
    build_acquisition_manifest,
    build_demo_report,
    read_bounded_bytes,
)
from starshield.image_containers import inspect_image_container
from starshield.ioc_validators import extract_validated_iocs
from starshield.leveldb_log import VALID_SCHEMA_MODES, inspect_chromium_storage_path

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
            "Perform a read-only millisecond diagnostic and GO/PARTIAL/NO_GO feasibility check on a "
            "local Chromium browser or Electron desktop app (VS Code, Slack, Microsoft Teams, Discord, "
            "WhatsApp Desktop) IndexedDB/LevelDB directory or .log/.ldb file without leaking raw content."
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
        "name": "starshield_inspect_image_tamper",
        "title": "Inspect PNG/JPEG Screenshot & Receipt Container Provenance",
        "description": (
            "Deterministically verify RFC 2083 PNG chunk CRC32 integrity (IHDR/IDAT/IEND/iCCP) and "
            "ISO 10918 JPEG APP2 ICC_PROFILE / APP13 Photoshop 8BIM resource blocks for FinTech "
            "reimbursement, e-commerce receipt, and disputed screenshot pre-screening."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Local path to a PNG or JPEG screenshot, receipt, or attachment.",
                },
            },
            "required": ["image_path"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "starshield_validate_financial_iocs",
        "title": "Validate Payment & Banking Checksums Offline",
        "description": (
            "Scan text offline in <1ms to extract and mathematically verify ISO/IEC 7812 Luhn card "
            "numbers, 89-country ISO 13616 IBAN Mod-97 accounts, 250-territory ISO 9362 SWIFT/BIC "
            "codes, and intra-message UK Faster Payments Sort Code + 8-digit Account pairs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text snippet, invoice instruction, or chat note to validate offline.",
                },
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "annotations": _READ_ONLY_ANNOTATIONS,
    },
]

_KNOWN_TOOL_NAMES = frozenset(tool["name"] for tool in MCP_TOOLS)


def _scrub_error_message(raw_msg: str, redact: bool, candidate_paths: Tuple[Path, ...]) -> str:
    if not redact:
        return raw_msg
    safe_msg = raw_msg
    for cand in candidate_paths:
        full_str = str(cand)
        if full_str:
            safe_msg = safe_msg.replace(full_str, "[REDACTED_PATH]")
        if cand.name:
            safe_msg = safe_msg.replace(cand.name, "[REDACTED_FILENAME]")
    return safe_msg


def _dispatch_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    redact: bool,
    max_mb: int,
    session_salt: bytes,
) -> Dict[str, Any]:
    candidate_paths: list[Path] = []
    try:
        if tool_name == "starshield_demo":
            if arguments:
                raise ValueError("starshield_demo accepts no arguments")
            payload = build_demo_report(redact=redact, salt=session_salt)
        elif tool_name == "starshield_precheck_leveldb":
            raw_target = arguments.get("target_path")
            if not isinstance(raw_target, str) or not raw_target.strip():
                raise ValueError("'target_path' must be a non-empty string")
            schema_mode = arguments.get("schema_mode", "auto")
            if not isinstance(schema_mode, str) or schema_mode not in VALID_SCHEMA_MODES:
                raise ValueError(f"'schema_mode' must be one of {VALID_SCHEMA_MODES}")
            target_path = Path(raw_target)
            candidate_paths.append(target_path)
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
        elif tool_name == "starshield_inspect_image_tamper":
            raw_img = arguments.get("image_path")
            if not isinstance(raw_img, str) or not raw_img.strip():
                raise ValueError("'image_path' must be a non-empty string")
            img_path = Path(raw_img)
            candidate_paths.append(img_path)
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
                raise ValueError("'text' must be a UTF-8 string")
            encoded_len = len(raw_text.encode("utf-8"))
            if encoded_len > max_mb * 1024 * 1024:
                raise ValueError(f"Input text exceeds --max-mb={max_mb} safety limit")
            payload = {
                "epistemic_tier": "DERIVED",
                "masked_mode": redact,
                "tool_version": f"starshield-forensics/{__version__}",
                "validated_iocs": extract_validated_iocs(raw_text, redact=redact, salt=session_salt),
            }
        else:  # pragma: no cover
            raise ValueError("Unsupported tool name")

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payload, indent=2, ensure_ascii=False),
                }
            ],
            "isError": False,
        }
    except (OSError, ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
        if redact and isinstance(exc, UnicodeDecodeError):
            err_msg = "Input is not valid UTF-8 text (raw byte context suppressed in masked mode)"
        else:
            err_msg = _scrub_error_message(str(exc), redact=redact, candidate_paths=tuple(candidate_paths))
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"error": err_msg, "masked_mode": redact}, ensure_ascii=False),
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
) -> Dict[str, Any] | None:
    """Process a single parsed JSON-RPC 2.0 message and return a response dict (or None for notifications)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        req_id = msg.get("id") if isinstance(msg, dict) else None
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32600, "message": "Invalid JSON-RPC 2.0 request object"},
        }

    method = msg.get("method")
    has_id = "id" in msg
    req_id = msg.get("id")
    if not isinstance(method, str) or not method:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
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
                    "server. Default masked mode applies ephemeral HMAC-SHA256 pseudonymization so raw PII, "
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
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Unknown StarShield MCP tool: {tool_name!r}"},
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
        )
        return {"jsonrpc": "2.0", "id": req_id, "result": tool_res}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def _write_rpc_frame(outstream: BinaryIO, payload: Dict[str, Any], framing: str) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
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
            # Consume remaining HTTP-style headers until blank line
            while True:
                hdr_line = instream.readline(4096)
                if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                    break
            body = instream.read(content_len)
            return body, "content-length", None

        return stripped, "line", None


def run_mcp_stdio_server(
    *,
    redact: bool = True,
    max_mb: int = MAX_DEFAULT_MB,
    salt: bytes | None = None,
    instream: BinaryIO | None = None,
    outstream: BinaryIO | None = None,
) -> int:
    """Run the deterministic StarShield MCP server over stdio until EOF."""
    if max_mb < 1:
        raise ValueError("--max-mb safety limit must be >= 1 MiB")
    reader = instream if instream is not None else sys.stdin.buffer
    writer = outstream if outstream is not None else sys.stdout.buffer
    session_salt = salt if salt is not None else secrets.token_bytes(32)

    while True:
        raw_bytes, framing, frame_err = _read_next_rpc_frame(reader)
        if raw_bytes is None and frame_err is None:
            return 0
        if frame_err is not None:
            _write_rpc_frame(writer, frame_err, framing)
            return 0

        try:
            parsed = json.loads((raw_bytes or b"").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _write_rpc_frame(
                writer,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error: invalid UTF-8 JSON"},
                },
                framing,
            )
            continue

        response = handle_mcp_message(
            parsed,
            redact=redact,
            max_mb=max_mb,
            session_salt=session_salt,
        )
        if response is not None:
            _write_rpc_frame(writer, response, framing)
