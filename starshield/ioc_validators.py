#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
#
# SPDX-License-Identifier: MIT
"""
Validated Multi-Jurisdiction Financial Indicator Extractor (`ioc_validators.py`).

Implements standard banking, legal-entity, and crypto-asset checksum verification:
- Payment Cards (ISO/IEC 7812): Luhn check-digit verification; cleanly separates
  `luhn_validated_cards` from `unvalidated_card_candidates`.
- IBAN (ISO 13616): Complete SWIFT IBAN Registry country-length table (rejecting
  unregistered country codes like `ZZ..`, supporting 15-to-34 char IBANs including
  15-char Norway `NO` and 30-char Yemen `YE`) + Rearrange + `mod 97 == 1` checksum.
- SWIFT / BIC (ISO 9362): Complete 249-code ISO 3166-1 alpha-2 table (plus `XK`) at
  chars 4..6 AND explicit banking/SWIFT context check for 8-letter all-alpha tokens
  so ordinary English words (`WORKSHOP`, `DOCUMENT`, `ABCDEFGH`) are never misflagged.
- US ABA Routing Numbers (9-digit): Federal Reserve prefix validation + `3-7-1 mod 10`
  weight check within an explicit 80-character banking/wire context window.
- ISO 11649 Creditor Reference (`RFxx...`): `mod 97 == 1` international remittance check.
- ISO 17442 LEI (20-char Legal Entity Identifier): LOU/context check + `mod 97 == 1`.
- TRON TRC-20 (`T...`) Base58Check (`0x41` + double-SHA256) & Ethereum EIP-55
  mixed-case checksum (pure-stdlib Keccak-256 `0x01` domain separator).
- UK Sort Code + Account Number: Restricts 8-digit account pairing to a local
  120-character window around a Sort Code strictly inside the SAME single message.
- Keyed Ephemeral Redaction: Default redaction uses per-run `HMAC-SHA256` tokens rather
  than partial prefix/suffix masking to prevent dictionary confirmation across reports.

Epistemic & Evidentiary Scope Note:
  Check-digit and format validation confirms mathematical syntax only (catching OCR or
  transcription errors); a passing check digit does NOT indicate fraud, malicious intent,
  or prove that a financial transaction actually occurred.
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, Hashable, List

DEFAULT_EPHEMERAL_SALT = secrets.token_bytes(32)
VALIDATION_SCOPE_NOTE = (
    "Check-digit and format validation confirms mathematical syntax only; "
    "it does NOT indicate fraud or prove that a payment occurred."
)

# Complete official ISO 3166-1 alpha-2 country codes (249 codes) + XK (SWIFT Kosovo)
ISO_3166_ALPHA2 = {
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU",
    "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL",
    "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC",
    "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV",
    "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
    "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD",
    "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT",
    "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM",
    "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH",
    "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK",
    "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH",
    "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR",
    "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR",
    "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC",
    "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
    "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY",
    "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT",
    "ZA", "ZM", "ZW",
}

# Official ISO 13616 / SWIFT IBAN Registry (all 89 registered jurisdictions)
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}

COMMON_ENGLISH_8LETTER_STOPWORDS = frozenset(
    {
        "WORKSHOP", "TRANSFER", "DOCUMENT", "SECURITY", "PASSPORT", "OFFICIAL",
        "CHECKING", "RECEIVED", "REQUIRED", "RESPONSE", "EVIDENCE", "NATIONAL",
        "CUSTOMER", "PERSONAL", "BUSINESS", "APPROVED", "REJECTED", "COMPLETE",
        "SUPPLIER", "HOLDINGS", "ATTACHED", "ORIGINAL", "CLEARING", "OVERSEAS",
        "CURRENCY", "DISPATCH", "REVISION", "VERIFIED", "PLATFORM", "PAYMENTS",
        "CREDITOR", "DEPOSITS", "DELIVERY", "INCLUDED", "EXCLUDED", "PROVIDED",
        "DETAILED", "MODIFIED", "NOTIFIED", "UNSIGNED", "ASSIGNED", "BALANCES",
        "BRANCHES", "POLICIES", "PROJECTS", "PREVIOUS", "ADVISORY", "MANAGERS",
        "PARTNERS", "REGISTER", "DATABASE", "DECISION", "PHYSICAL", "JUDICIAL",
        "DOMESTIC", "TERMINAL", "TRACKING", "ACCOUNTS", "INVOICES", "CONTRACT",
        "MERCHANT", "PURCHASE", "SHIPPING", "APPROVAL", "DISPUTED", "REFUNDED",
        "BENEFICIARY", "TRANSACTION", "INSTRUCTION", "REMITTANCES", "DECLARATION",
        "REQUIREMENT", "INDEPENDENT", "ENVIRONMENT",
    }
)


def _ioc_item_key(item: Any) -> Hashable:
    if isinstance(item, dict):
        return (item.get("sort_code"), item.get("account_number"))
    return item


def empty_ioc_dict() -> Dict[str, List[Any]]:
    return {
        "luhn_validated_cards": [],
        "unvalidated_card_candidates": [],
        "mod97_validated_ibans": [],
        "context_paired_uk_accounts": [],
        "unpaired_uk_sort_codes": [],
        "validated_swift_bics": [],
        "aba_validated_routing_numbers": [],
        "iso11649_creditor_references": [],
        "validated_leis": [],
        "base58check_tron_addresses": [],
        "eip55_eth_addresses": [],
    }


def merge_ioc_dicts(
    dst: Dict[str, List[Any]],
    src: Dict[str, List[Any]],
    seen_cache: Dict[str, set[Hashable]] | None = None,
) -> None:
    """
    Merge per-message IOC results without cross-message proximity contamination.

    Pass a shared `seen_cache` dictionary across multi-message loops so per-bucket deduplication
    sets are initialized once and updated in amortized O(1) time (guaranteeing O(M) corpus triage).
    """
    for k, items in src.items():
        if not items:
            continue
        bucket = dst.setdefault(k, [])
        if seen_cache is not None:
            seen = seen_cache.get(k)
            if seen is None:
                seen = {_ioc_item_key(existing) for existing in bucket}
                seen_cache[k] = seen
        else:
            seen = {_ioc_item_key(existing) for existing in bucket}
        for item in items:
            key = _ioc_item_key(item)
            if key not in seen:
                seen.add(key)
                bucket.append(item)


def luhn_valid(digits: str) -> bool:
    if not digits.isascii() or not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_mod97_valid(iban: str) -> bool:
    cleaned = re.sub(r"[\s-]+", "", iban).upper()
    if not cleaned.isascii() or len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not cleaned[:2].isalpha() or not cleaned[2:4].isdigit() or not cleaned.isalnum():
        return False
    country = cleaned[:2]
    expected_len = IBAN_LENGTHS.get(country)
    if expected_len is None or len(cleaned) != expected_len:
        return False

    rearranged = cleaned[4:] + cleaned[:4]
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(numeric_str) % 97 == 1


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_VALS = {ch: idx for idx, ch in enumerate(_BASE58_ALPHABET)}
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _build_keccak_constants() -> tuple[tuple[int, ...], tuple[int, ...]]:
    rc_list: List[int] = []
    lfsr = 1
    for _ in range(24):
        rc = 0
        for j in range(7):
            if lfsr & 1:
                rc |= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ (0x71 if (lfsr & 0x80) else 0)) & 0xFF
        rc_list.append(rc)
    rot = [0] * 25
    x, y = 1, 0
    for t in range(24):
        rot[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return tuple(rc_list), tuple(rot)


_KECCAK_RC, _KECCAK_ROT = _build_keccak_constants()


def _rotl64(val: int, shift: int) -> int:
    if shift == 0:
        return val
    return ((val << shift) | (val >> (64 - shift))) & _MASK64


def _keccak_f1600(state: List[int]) -> None:
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            state[i] ^= d[i % 5]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                idx = x + 5 * y
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[idx], _KECCAK_ROT[idx])
        for y in range(5):
            row = 5 * y
            for x in range(5):
                state[x + row] = b[x + row] ^ ((~b[((x + 1) % 5) + row] & _MASK64) & b[((x + 2) % 5) + row])
        state[0] ^= _KECCAK_RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (0x01 domain separator, as required by Ethereum EIP-55) in pure stdlib."""
    rate = 136
    pad_len = rate - (len(data) % rate)
    padded = bytearray(data) + b"\x01" + (b"\x00" * (pad_len - 1))
    padded[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for lane in range(17):
            state[lane] ^= int.from_bytes(block[lane * 8 : (lane + 1) * 8], "little")
        _keccak_f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def aba_routing_valid(digits: str) -> bool:
    """Validate 9-digit US ABA routing number (Fedwire symbol prefix incl. 00 US Treasury + 3-7-1 mod 10 check)."""
    if not digits.isascii() or len(digits) != 9 or not digits.isdigit() or digits == "000000000":
        return False
    prefix = int(digits[:2])
    if not ((0 <= prefix <= 12) or (21 <= prefix <= 32) or (61 <= prefix <= 72) or prefix == 80):
        return False
    d = [int(ch) for ch in digits]
    checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return checksum % 10 == 0


def iso11649_creditor_ref_valid(ref: str) -> bool:
    """Validate ISO 11649 structured Creditor Reference (`RF` + 2 check digits, mod 97 == 1)."""
    cleaned = re.sub(r"[\s-]+", "", ref).upper()
    if not cleaned.isascii() or not re.fullmatch(r"RF[0-9]{2}[A-Z0-9]{1,21}", cleaned):
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(numeric_str) % 97 == 1


def lei_iso17442_valid(lei: str) -> bool:
    """Validate 20-character ISO 17442 Legal Entity Identifier (mod 97 == 1)."""
    cleaned = re.sub(r"[\s-]+", "", lei).upper()
    if not cleaned.isascii() or not re.fullmatch(r"[0-9A-Z]{18}[0-9]{2}", cleaned):
        return False
    numeric_str = "".join(str(ord(c) - 55) if c.isalpha() else c for c in cleaned)
    return int(numeric_str) % 97 == 1


def tron_trc20_address_valid(addr: str) -> bool:
    """Validate 34-char Base58Check TRON address (`T...`, version byte 0x41 + double-SHA256)."""
    if not addr.isascii() or not re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", addr):
        return False
    num = 0
    for ch in addr:
        val = _BASE58_VALS.get(ch)
        if val is None:
            return False
        num = num * 58 + val
    try:
        raw = num.to_bytes(25, "big")
    except OverflowError:
        return False
    if raw[0] != 0x41:
        return False
    chk = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return hmac.compare_digest(raw[21:], chk)


def eth_eip55_checksum_valid(addr: str) -> bool:
    """
    Validate Ethereum EIP-55 checksummed address using pure-stdlib Keccak-256 (`0x01` padding).

    Triage rules:
    1. Require >= 1 hex alpha character (`a-f` / `A-F`) so all-digit `0x000...` strings with
       zero case-checksum bits are never accepted.
    2. Verify every hex alpha character strictly matches its Keccak-256 nibble (`>= 8` uppercase,
       `< 8` lowercase), supporting all official EIP-55 test vectors (including single-alpha and
       all-upper/all-lower addresses whose Keccak nibbles legitimately align).
    """
    if not addr.isascii() or not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
        return False
    hex_part = addr[2:]
    if not any(c.isalpha() for c in hex_part):
        return False
    digest_hex = keccak256(hex_part.lower().encode("ascii")).hex()
    for i, ch in enumerate(hex_part):
        if ch.isalpha():
            should_upper = int(digest_hex[i], 16) >= 8
            if ch.isupper() != should_upper:
                return False
    return True


SUPPORTED_HMAC_DIGESTS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "blake2b": hashlib.blake2b,
}
_ACTIVE_HMAC_DIGEST_VAR: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ACTIVE_HMAC_DIGEST",
    default="sha256",
)


def set_active_hmac_digest(alg: str) -> None:
    if alg not in SUPPORTED_HMAC_DIGESTS:
        raise ValueError(f"Unsupported HMAC digest algorithm: {alg}")
    _ACTIVE_HMAC_DIGEST_VAR.set(alg)


def get_active_hmac_digest() -> str:
    return _ACTIVE_HMAC_DIGEST_VAR.get()


def get_active_hmac_callable():
    return SUPPORTED_HMAC_DIGESTS[_ACTIVE_HMAC_DIGEST_VAR.get()]


def mask_identifier(val: str, salt: bytes | None = None, digest_alg: str | None = None) -> str:
    """Keyed HMAC redaction with cryptographic algorithm agility (resists dictionary confirmation)."""
    if not val:
        return ""
    if digest_alg is not None and digest_alg not in SUPPORTED_HMAC_DIGESTS:
        raise ValueError(f"Unsupported HMAC digest algorithm: {digest_alg}")
    key = salt if salt is not None else DEFAULT_EPHEMERAL_SALT
    fn = SUPPORTED_HMAC_DIGESTS[digest_alg] if digest_alg else get_active_hmac_callable()
    digest = hmac.new(key, val.encode("utf-8", errors="replace"), fn).hexdigest()[:12]
    return f"[REDACTED_HMAC:{digest}]"


_CARD_RE = re.compile(r"(?<![0-9])(?:4[0-9]|5[1-5]|62)(?:[\s-]?[0-9]){11,17}(?![0-9])")
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}(?:[ \t\u00a0\u202f\u2009\u2007-]?[A-Z0-9]){11,30}\b", re.ASCII)
_UK_SORT_RE = re.compile(r"(?<![0-9])[0-9]{2}-[0-9]{2}-[0-9]{2}(?![0-9])")
_UK_ACC_RE = re.compile(r"(?<![0-9])[0-9]{8}(?![0-9])")
_SWIFT_CTX_RE = re.compile(r"\b(?:swift|bic|routing|wire|beneficiary|iban)\b", re.IGNORECASE | re.ASCII)
_BIC_RE = re.compile(r"\b([A-Z]{4})([A-Z]{2})([A-Z0-9]{2})([A-Z0-9]{3})?\b", re.ASCII)
_ABA_RE = re.compile(r"(?<![0-9])([0-9]{9})(?![0-9])")
_ABA_CTX_RE = re.compile(r"\b(?:aba|routing|rtn|ach|fedwire|wire|transit)\b", re.IGNORECASE | re.ASCII)
_RF_RE = re.compile(r"\bRF[0-9]{2}(?:[ \t\u00a0\u202f\u2009\u2007-]?[A-Z0-9]){1,21}\b", re.ASCII)
_LEI_RE = re.compile(r"\b([0-9A-Z]{18}[0-9]{2})\b", re.ASCII)
_LEI_CTX_RE = re.compile(r"\b(?:lei|legal\s+entity)\b", re.IGNORECASE | re.ASCII)
_TRON_RE = re.compile(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b", re.ASCII)
_ETH_RE = re.compile(r"\b(0x[0-9a-fA-F]{40})\b", re.ASCII)


def extract_validated_iocs(
    text: str,
    redact: bool = True,
    salt: bytes | None = None,
) -> Dict[str, Any]:
    out = empty_ioc_dict()
    if not text:
        return out

    seen: Dict[str, set[Hashable]] = {k: set() for k in out}

    def add_unique(bucket: str, item: Any) -> None:
        item_key = _ioc_item_key(item)
        if item_key not in seen[bucket]:
            seen[bucket].add(item_key)
            out[bucket].append(item)

    def fmt(s: str) -> str:
        return mask_identifier(s, salt=salt) if redact else s

    # 1. ISO/IEC 7812 payment cards (major network IIN ranges 4/5/62) allowing spaces or hyphens
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[\s-]", "", m.group(0))
        if not digits.isascii() or not (13 <= len(digits) <= 19):
            continue
        rendered = fmt(digits)
        if luhn_valid(digits):
            add_unique("luhn_validated_cards", rendered)
        else:
            add_unique("unvalidated_card_candidates", rendered)

    # 2. IBAN (unambiguous O(N) linear scan + ISO 13616 Mod-97 & registered country length 15..34)
    for m in _IBAN_RE.finditer(text):
        raw_match = m.group(0)
        cand = re.sub(r"[\s-]+", "", raw_match)
        if iban_mod97_valid(cand):
            add_unique("mod97_validated_ibans", fmt(cand))
        elif any(ch.isspace() for ch in raw_match):
            # Handle IBAN followed across whitespace/newline by an uppercase token (e.g. "GB82...32\nSWIFT")
            exp_len = IBAN_LENGTHS.get(cand[:2])
            if exp_len is not None and len(cand) > exp_len:
                acc_tokens: List[str] = []
                acc_len = 0
                for tok in raw_match.split():
                    cleaned_tok = tok.replace("-", "")
                    if acc_len + len(cleaned_tok) > exp_len:
                        break
                    acc_tokens.append(cleaned_tok)
                    acc_len += len(cleaned_tok)
                    if acc_len == exp_len:
                        prefix_cand = "".join(acc_tokens)
                        if iban_mod97_valid(prefix_cand):
                            add_unique("mod97_validated_ibans", fmt(prefix_cand))
                        break

    # 3. UK Sort Code + local-window (<=120 chars) 8-digit Account Number pairing (intra-message only)
    for sc_match in _UK_SORT_RE.finditer(text):
        sc = sc_match.group(0)
        win_start = max(0, sc_match.start() - 120)
        win_end = min(len(text), sc_match.end() + 120)
        window = text[win_start:win_end]
        acc_matches = _UK_ACC_RE.findall(window)
        if acc_matches:
            for acc in acc_matches:
                pair = {
                    "sort_code": fmt(sc),
                    "account_number": fmt(acc),
                    "validation_note": "Context-paired within 120 chars in same message (Pay.UK Vocalink modulus table not bundled)",
                }
                add_unique("context_paired_uk_accounts", pair)
        else:
            add_unique("unpaired_uk_sort_codes", fmt(sc))

    # 4. SWIFT / BIC (ISO 9362): valid ISO 3166 country at [4:6] + stopword rejection + local +/-120-char context
    for bic_m in _BIC_RE.finditer(text):
        full_bic = bic_m.group(0)
        country = bic_m.group(2)
        if country not in ISO_3166_ALPHA2:
            continue
        if full_bic in COMMON_ENGLISH_8LETTER_STOPWORDS:
            continue
        if full_bic.isalpha():
            bic_win = text[max(0, bic_m.start() - 120) : min(len(text), bic_m.end() + 120)]
            if not _SWIFT_CTX_RE.search(bic_win):
                continue
        if len(full_bic) in (8, 11):
            add_unique("validated_swift_bics", fmt(full_bic))

    # 5. US ABA Routing Number (9 digits, 3-7-1 mod 10, +/-80-char banking context window)
    for aba_m in _ABA_RE.finditer(text):
        cand_aba = aba_m.group(1)
        win = text[max(0, aba_m.start() - 80) : min(len(text), aba_m.end() + 80)]
        if _ABA_CTX_RE.search(win) and aba_routing_valid(cand_aba):
            add_unique("aba_validated_routing_numbers", fmt(cand_aba))

    # 6. ISO 11649 Creditor Reference (RFxx..., mod 97 == 1, arbitrary valid whitespace/hyphen groupings)
    for rf_m in _RF_RE.finditer(text):
        raw_rf = rf_m.group(0)
        cand_rf = re.sub(r"[\s-]+", "", raw_rf).upper()
        if iso11649_creditor_ref_valid(cand_rf):
            add_unique("iso11649_creditor_references", fmt(cand_rf))
        elif any(ch.isspace() for ch in raw_rf):
            # Trim trailing uppercase alpha words (e.g. "RF18 5390 0754 7034\nUSD") without dropping numeric groups
            parts = raw_rf.split()
            while len(parts) > 1 and parts[-1].isalpha():
                parts.pop()
                trimmed_rf = re.sub(r"[\s-]+", "", "".join(parts)).upper()
                if iso11649_creditor_ref_valid(trimmed_rf):
                    add_unique("iso11649_creditor_references", fmt(trimmed_rf))
                    break

    # 7. ISO 17442 LEI (20 chars, mod 97 == 1 + numeric LOU or explicit LEI context)
    for lei_m in _LEI_RE.finditer(text):
        cand_lei = lei_m.group(1)
        win = text[max(0, lei_m.start() - 80) : min(len(text), lei_m.end() + 80)]
        has_lei_ctx = bool(_LEI_CTX_RE.search(win))
        if cand_lei[:4].isdigit() or has_lei_ctx:
            if lei_iso17442_valid(cand_lei):
                add_unique("validated_leis", fmt(cand_lei))

    # 8. TRON TRC-20 Base58Check (`T...`)
    for tron_m in _TRON_RE.finditer(text):
        cand_tron = tron_m.group(1)
        if tron_trc20_address_valid(cand_tron):
            add_unique("base58check_tron_addresses", fmt(cand_tron))

    # 9. Ethereum EIP-55 checksum address (`0x...`)
    for eth_m in _ETH_RE.finditer(text):
        cand_eth = eth_m.group(1)
        if eth_eip55_checksum_valid(cand_eth):
            add_unique("eip55_eth_addresses", fmt(cand_eth))

    return out
