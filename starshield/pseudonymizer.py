# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Session-Fingerprinted Order-Preserving Pseudonymizer & Local Vault Manager (`pseudonymizer.py`).

Architectural Security Invariants:
  1. Structural Airlock (NOT a natural-language regex filter):
     `starshield mcp` is NOT a prompt-injection detector or sanitizer. Instead, in default masked
     mode, free-form chat/document prose is strictly withheld (`[WITHHELD_IN_STRUCTURAL_MCP_MODE]`),
     and only deterministic structural skeletons (byte offsets, sequence numbers, soft-delete flags,
     session-tagged `<ENTITY_9F3A_01>` handles, mathematically validated `<IBAN_GB_9F3A_01>` /
     `<TRC20_9F3A_01>` tokens, and numeric currency amounts) enter the LLM context window.
  2. Cross-Case Anti-Collision Session Fingerprints (`<CATEGORY_[CC_]<TAG4>_NN>`):
     Every placeholder embeds a 4-hex-character uppercase `session_tag` (e.g., `<IBAN_GB_9F3A_01>`,
     `<TRC20_9F3A_01>`) plus 2-letter ISO country codes on IBAN/BIC tokens. During offline
     `starshield detokenize`, tokens bearing a foreign `session_tag` are left unexpanded and
     explicitly flagged to prevent cross-case evidentiary contamination.
  3. One-Way MCP Airlock & `0600` Jump-Box Hygiene:
     Reverse lookup stays in RAM by default and is written to disk ONLY when `--vault-file` is
     explicitly supplied (`os.open` with `O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW`, `0600`).
     Because Python's standard library provides no native AEAD cipher, persisted vaults are
     OS-permission-protected plaintext JSON; operators should store them on `tmpfs` (`/dev/shm`)
     and run `starshield shred-vault --vault <path>` immediately upon case completion. Neither
     `detokenize` nor `shred-vault` is ever registered as an MCP tool.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from starshield import __version__
from starshield.ioc_validators import extract_validated_iocs
from starshield.leveldb_log import SafeDiagnosticError, dumps_strict_json, sanitize_utf8_str

MAX_VAULT_BYTES = 4 * 1024 * 1024
MAX_TOKENS_PER_CATEGORY = 10000
MAX_EXTRACTED_AMOUNTS = 64


def _parse_bounded_vault_int(num_str: str) -> int:
    if len(num_str.lstrip("+-")) > 64:
        raise ValueError("Vault integer exceeds bounded 64-digit safety limit")
    return int(num_str)

_SESSION_TAG_RE = re.compile(r"^[0-9A-F]{4}$")
_TOKEN_PLACEHOLDER_RE = re.compile(r"<([A-Z0-9_]+)_([0-9A-F]{4})_([0-9]{2,5}|OVR_[0-9A-F]{12})>")

_CURRENCY_AMOUNT_NUM_PAT = (
    r"(?:"
    r"[0-9]{1,3}(?:\.[0-9]{3})+(?:,[0-9]{2})?"
    r"|[0-9]{1,3}(?:['\u2019][0-9]{3})+(?:\.[0-9]{1,4}|,[0-9]{2})?"
    r"|[0-9]{1,3}(?:[ \u00a0\u202f\u2009\u2007][0-9]{3})+(?:,[0-9]{2}|\.[0-9]{2})"
    r"|[0-9]{1,3}(?:[\u00a0\u202f\u2009\u2007][0-9]{3})+(?![\u00a0\u202f\u2009\u2007][0-9]|[.,][0-9])"
    r"|[0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]{1,4})?"
    r"|[0-9]+(?:\.[0-9]{1,4}|,[0-9]{2})"
    r"|[0-9]+(?![ \u00a0\u202f\u2009\u2007][0-9]{3}(?:[ \u00a0\u202f\u2009\u2007][0-9]{3})*(?:[.,][0-9]|[ \u00a0\u202f\u2009\u2007][0-9]{1,2}(?![0-9])))"
    r")"
    r"(?![0-9A-Za-z]|[.,'\u2019][0-9])"
)
_CURRENCY_AMOUNT_RE = re.compile(
    r"(?:"
    r"(?<![A-Za-z0-9])(?:USD|EUR|GBP|HKD|CNY|RMB|SGD|AUD|CAD|CHF|JPY|USDT|USDC)\s*"
    + _CURRENCY_AMOUNT_NUM_PAT
    + r"|(?<![A-Za-z0-9])(?:HK\$|US\$|S\$|\$)\s*"
    + _CURRENCY_AMOUNT_NUM_PAT
    + r"|[£€¥]\s*"
    + _CURRENCY_AMOUNT_NUM_PAT
    + r")"
)


def extract_currency_amounts(text: str) -> List[str]:
    """Extract bounded, deterministic currency+amount tokens without leaking free-form prose."""
    if not text:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for m in _CURRENCY_AMOUNT_RE.finditer(text):
        norm = " ".join(m.group(0).split())
        if norm not in seen:
            seen.add(norm)
            out.append(norm)
            if len(out) >= MAX_EXTRACTED_AMOUNTS:
                break
    return out


class SessionPseudonymizer:
    """Deterministic per-session order-preserving placeholder mapper (`<CATEGORY_[CC_]<TAG4>_NN>`)."""

    def __init__(
        self,
        session_tag: str | None = None,
        session_id: str | None = None,
    ) -> None:
        if session_tag is not None:
            clean_tag = session_tag.strip().upper()
            if not _SESSION_TAG_RE.fullmatch(clean_tag):
                raise ValueError("session_tag must be exactly 4 uppercase hexadecimal characters")
            self.session_tag = clean_tag
        else:
            self.session_tag = secrets.token_hex(2).upper()

        self.session_id = session_id or f"ss_{self.session_tag.lower()}_{secrets.token_hex(6)}"
        self._cat_counters: Dict[str, int] = {}
        self._raw_to_token: Dict[Tuple[str, str], str] = {}
        self._token_to_raw: Dict[str, str] = {}
        self._overflow_salt = secrets.token_bytes(32)
        self._cap_exceeded_categories: set[str] = set()

    def assign(self, category: str, raw_value: str) -> str:
        """Assign `<CATEGORY_[CC_]<TAG4>_NN>`, falling back to `<..._OVR_HMAC12>` past 10,000 entries."""
        if not raw_value:
            return ""
        clean_raw = sanitize_utf8_str(raw_value)
        norm_cat = re.sub(r"[^A-Z0-9_]", "", category.upper()) or "ITEM"
        key = (norm_cat, clean_raw)
        existing = self._raw_to_token.get(key)
        if existing is not None:
            return existing

        compact = clean_raw.strip().upper()
        if norm_cat == "IBAN" and len(compact) >= 2 and compact[:2].isalpha() and compact[:2].isascii():
            prefix = f"IBAN_{compact[:2]}"
        elif norm_cat == "BIC" and len(compact) >= 6 and compact[4:6].isalpha() and compact[4:6].isascii():
            prefix = f"BIC_{compact[4:6]}"
        else:
            prefix = norm_cat

        cur_count = self._cat_counters.get(norm_cat, 0)
        if cur_count >= MAX_TOKENS_PER_CATEGORY:
            self._cap_exceeded_categories.add(norm_cat)
            hmac_hex = hmac.new(
                self._overflow_salt,
                f"{norm_cat}:{clean_raw}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()[:12].upper()
            return f"<{prefix}_{self.session_tag}_OVR_{hmac_hex}>"

        next_idx = cur_count + 1
        self._cat_counters[norm_cat] = next_idx
        token = f"<{prefix}_{self.session_tag}_{next_idx:02d}>"
        self._raw_to_token[key] = token
        self._token_to_raw[token] = clean_raw
        return token

    def token_counts(self) -> Dict[str, int]:
        return dict(self._cat_counters)

    def cap_exceeded_categories(self) -> List[str]:
        return sorted(self._cap_exceeded_categories)

    def pseudonymize_iocs_from_text(self, text: str) -> Dict[str, Any]:
        """Extract mathematically validated IOCs from `text` and replace values with session tokens."""
        raw_iocs = extract_validated_iocs(text, redact=False)
        return self.pseudonymize_ioc_dict(raw_iocs)

    def pseudonymize_ioc_dict(self, raw_iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Map an unredacted IOC dictionary to `<CATEGORY_[CC_]<TAG4>_NN>` placeholders."""
        out = copy.deepcopy(raw_iocs)
        bucket_cats = (
            ("luhn_validated_cards", "CARD"),
            ("unvalidated_card_candidates", "CARD"),
            ("mod97_validated_ibans", "IBAN"),
            ("unpaired_uk_sort_codes", "UK_SORT"),
            ("validated_swift_bics", "BIC"),
            ("aba_validated_routing_numbers", "ABA"),
            ("iso11649_creditor_references", "RF"),
            ("validated_leis", "LEI"),
            ("base58check_tron_addresses", "TRC20"),
            ("eip55_eth_addresses", "ETH"),
        )
        for bucket, cat in bucket_cats:
            items = out.get(bucket)
            if isinstance(items, list):
                out[bucket] = [self.assign(cat, str(v)) for v in items]

        uk_pairs = out.get("context_paired_uk_accounts")
        if isinstance(uk_pairs, list):
            new_pairs: List[Dict[str, Any]] = []
            for pair in uk_pairs:
                if isinstance(pair, dict):
                    p_copy = dict(pair)
                    if p_copy.get("sort_code"):
                        p_copy["sort_code"] = self.assign("UK_SORT", str(p_copy["sort_code"]))
                    if p_copy.get("account_number"):
                        p_copy["account_number"] = self.assign("UK_ACC", str(p_copy["account_number"]))
                    new_pairs.append(p_copy)
            out["context_paired_uk_accounts"] = new_pairs
        return out

    def export_vault_dict(self) -> Dict[str, Any]:
        return {
            "vault_schema": "starshield-token-vault/v1",
            "tool_version": f"starshield-forensics/{__version__}",
            "session_id": self.session_id,
            "session_tag": self.session_tag,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "storage_security_notice": (
                "OS 0600-protected plaintext lookup table (Python stdlib has no native AES-GCM). "
                "Prefer RAM-backed tmpfs (/dev/shm on Linux) or a chmod 0700 private directory "
                "(e.g. ~/.starshield on macOS), and execute `starshield shred-vault --vault <path>` "
                "immediately after detokenization."
            ),
            "token_counts": self.token_counts(),
            "cap_exceeded_categories": self.cap_exceeded_categories(),
            "token_to_raw": dict(self._token_to_raw),
        }

    def save_vault_atomic(self, vault_path: Path) -> None:
        """Persist reverse token vault locally with strict `0600` permissions, `O_NOFOLLOW`, and anti-clobber check."""
        target = Path(vault_path)
        existing_st: os.stat_result | None = None
        try:
            existing_st = os.lstat(target)
        except FileNotFoundError:
            existing_st = None

        if existing_st is not None:
            if stat.S_ISLNK(existing_st.st_mode) or not stat.S_ISREG(existing_st.st_mode):
                raise OSError("Refusing to write token vault through a symbolic link or non-regular file")
            try:
                load_vault_strict(target)
            except (
                OSError,
                ValueError,
                json.JSONDecodeError,
                UnicodeDecodeError,
                RecursionError,
                MemoryError,
            ) as exc:
                raise SafeDiagnosticError(
                    "Refusing to overwrite existing file: target is not a valid starshield-token-vault/v1 file"
                ) from exc

        parent = target.parent
        if parent.is_symlink():
            raise OSError("Refusing to write token vault inside a symbolic-link directory")
        if parent and not parent.exists():
            grandparent = parent.parent
            if (
                not grandparent
                or grandparent == parent
                or grandparent.is_symlink()
                or not grandparent.exists()
                or not grandparent.is_dir()
            ):
                raise OSError("Token vault parent directory does not exist")
            try:
                parent.mkdir(mode=0o700, exist_ok=True)
            except OSError as exc:
                raise OSError("Token vault parent directory does not exist") from exc

        serialized = dumps_strict_json(self.export_vault_dict(), indent=2).encode("utf-8")
        if len(serialized) > MAX_VAULT_BYTES:
            raise ValueError(f"Token vault exceeds {MAX_VAULT_BYTES} byte safety cap")

        tmp_name = f".{target.name}.tmp.{secrets.token_hex(6)}"
        tmp_path = parent / tmp_name
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(serialized)
                fh.flush()
                if hasattr(os, "fchmod"):
                    os.fchmod(fh.fileno(), 0o600)
                os.fsync(fh.fileno())
                tmp_st = os.fstat(fh.fileno())
            cur_tmp_st = os.lstat(tmp_path)
            if not stat.S_ISREG(cur_tmp_st.st_mode) or (cur_tmp_st.st_dev, cur_tmp_st.st_ino) != (
                tmp_st.st_dev,
                tmp_st.st_ino,
            ):
                raise OSError("Temporary token vault inode changed during write (TOCTOU detected)")
            os.chmod(tmp_path, 0o600)
            try:
                cur_target_st = os.lstat(target)
            except FileNotFoundError:
                cur_target_st = None
            if existing_st is None:
                if cur_target_st is not None:
                    raise OSError("Refusing to replace newly appeared file at token vault path (TOCTOU detected)")
            else:
                if (
                    cur_target_st is None
                    or not stat.S_ISREG(cur_target_st.st_mode)
                    or (cur_target_st.st_dev, cur_target_st.st_ino) != (existing_st.st_dev, existing_st.st_ino)
                ):
                    raise OSError("Refusing to replace token vault: target inode changed during write (TOCTOU detected)")
            os.replace(tmp_path, target)
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


def load_vault_strict(vault_path: Path) -> Tuple[Dict[str, str], str]:
    """Load `starshield-token-vault/v1` JSON (`O_NOFOLLOW`) and return `(token_to_raw, session_tag)`."""
    target = Path(vault_path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | nofollow)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Token vault path must be a regular file")
        if st.st_size > MAX_VAULT_BYTES:
            raise ValueError(f"Token vault exceeds {MAX_VAULT_BYTES} byte safety limit")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw = fh.read(MAX_VAULT_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)

    if len(raw) > MAX_VAULT_BYTES:
        raise ValueError(f"Token vault exceeds {MAX_VAULT_BYTES} byte safety limit")

    try:
        parsed = json.loads(raw.decode("utf-8"), parse_int=_parse_bounded_vault_int)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError, ValueError) as exc:
        raise ValueError("Invalid or unsupported StarShield token vault JSON") from exc
    if not isinstance(parsed, dict) or parsed.get("vault_schema") != "starshield-token-vault/v1":
        raise ValueError("Invalid or unsupported StarShield token vault schema")
    session_tag = str(parsed.get("session_tag", "")).strip().upper()
    if not _SESSION_TAG_RE.fullmatch(session_tag):
        raise ValueError("Token vault missing valid 4-hex 'session_tag'")
    mapping = parsed.get("token_to_raw")
    if not isinstance(mapping, dict):
        raise ValueError("Token vault missing 'token_to_raw' mapping object")

    out: Dict[str, str] = {}
    for k, v in mapping.items():
        if isinstance(k, str) and isinstance(v, str):
            m = _TOKEN_PLACEHOLDER_RE.fullmatch(k)
            if m and m.group(2) == session_tag:
                out[k] = v
    return out, session_tag


def detokenize_text(
    text: str,
    token_to_raw: Dict[str, str],
    *,
    expected_session_tag: str | None = None,
) -> Tuple[str, int, List[str]]:
    """
    Single-pass non-recursive substitution of `<CATEGORY_[CC_]<TAG4>_NN>` placeholders.

    Returns `(restored_text, restored_count, unmatched_or_foreign_tokens)`. Any placeholder
    carrying a foreign `session_tag` (e.g., from a different case) is left untouched and
    reported in `unmatched_or_foreign_tokens` to prevent silent cross-case mixups.
    """
    replaced_count = 0
    unmatched: List[str] = []
    unmatched_seen: set[str] = set()
    norm_expected = expected_session_tag.strip().upper() if expected_session_tag else None

    def _repl(m: re.Match[str]) -> str:
        nonlocal replaced_count
        tok = m.group(0)
        tok_tag = m.group(2)
        if (norm_expected is None or tok_tag == norm_expected) and tok in token_to_raw:
            replaced_count += 1
            return token_to_raw[tok]
        if tok not in unmatched_seen:
            unmatched_seen.add(tok)
            unmatched.append(tok)
        return tok

    restored = _TOKEN_PLACEHOLDER_RE.sub(_repl, text)
    return restored, replaced_count, unmatched


def _write_all(fd: int, buf: bytes) -> None:
    """Write all bytes in `buf` to file descriptor `fd`, looping across short OS writes."""
    mv = memoryview(buf)
    written = 0
    total = len(mv)
    while written < total:
        n = os.write(fd, mv[written:])
        if n <= 0:
            raise OSError("Short or zero-byte write while overwriting token vault")
        written += n


def _read_fd_bounded(fd: int, max_bytes: int) -> bytes:
    """Read from `fd` from offset 0 up to `max_bytes + 1` bytes without closing `fd`."""
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: List[bytes] = []
    total = 0
    while True:
        want = min(65536, (max_bytes + 1) - total)
        part = os.read(fd, want)
        if not part:
            break
        chunks.append(part)
        total += len(part)
        if total > max_bytes:
            break
    return b"".join(chunks)


def shred_vault_file(vault_path: Path) -> Dict[str, Any]:
    """Best-effort logical overwrite (`random` + `0x00` + `fsync`) and inode-verified unlink (`O_NOFOLLOW`)."""
    target = Path(vault_path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), os.O_RDWR | getattr(os, "O_NONBLOCK", 0) | nofollow)
    size = 0
    orig_dev = -1
    orig_ino = -1
    refusal_msg = "Refusing to shred file: target does not carry a valid starshield-token-vault/v1 header"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError("Refusing to shred non-regular file")
        orig_dev, orig_ino = st.st_dev, st.st_ino
        if st.st_size > MAX_VAULT_BYTES:
            raise ValueError(f"File exceeds {MAX_VAULT_BYTES} byte vault cap; refusing to shred")
        if st.st_size <= 0:
            raise ValueError(refusal_msg)

        raw_existing = _read_fd_bounded(fd, MAX_VAULT_BYTES)
        if not raw_existing or len(raw_existing) > MAX_VAULT_BYTES:
            raise ValueError(f"File exceeds {MAX_VAULT_BYTES} byte vault cap; refusing to shred")
        try:
            parsed = json.loads(raw_existing.decode("utf-8"), parse_int=_parse_bounded_vault_int)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError, ValueError) as exc:
            raise ValueError(refusal_msg) from exc

        if (
            not isinstance(parsed, dict)
            or parsed.get("vault_schema") != "starshield-token-vault/v1"
            or not _SESSION_TAG_RE.fullmatch(str(parsed.get("session_tag", "")).strip().upper())
            or not isinstance(parsed.get("token_to_raw"), dict)
        ):
            raise ValueError(refusal_msg)

        size = max(len(raw_existing), st.st_size, 256)
        os.lseek(fd, 0, os.SEEK_SET)
        _write_all(fd, secrets.token_bytes(size))
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        _write_all(fd, b"\x00" * size)
        os.fsync(fd)
    finally:
        os.close(fd)

    cur_st = os.lstat(target)
    if not stat.S_ISREG(cur_st.st_mode) or (cur_st.st_dev, cur_st.st_ino) != (orig_dev, orig_ino):
        raise OSError("Refusing to unlink token vault: target inode changed before unlink (TOCTOU detected)")
    os.unlink(target)
    return {
        "shredded": True,
        "erasure_guarantee": "best_effort_logical_overwrite_and_unlink_only",
        "bytes_overwritten_per_pass": size,
        "passes": 2,
        "filesystem_caveat": (
            "Best-effort logical overwrite + unlink only: clears directory entry and logical file data, "
            "but does NOT guarantee unrecoverable physical block erasure on wear-leveled SSD/NVMe media "
            "or copy-on-write (APFS/Btrfs/ZFS) volumes—prefer RAM-backed tmpfs (/dev/shm) where available."
        ),
    }
