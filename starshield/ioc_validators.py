#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validated Multi-Jurisdiction Financial Indicator Extractor (`ioc_validators.py`).

Implements standard banking format and check-digit verification:
- Payment Cards (ISO/IEC 7812): Luhn check-digit verification; cleanly separates
  `luhn_validated_cards` from `unvalidated_card_candidates`.
- IBAN (ISO 13616): Complete SWIFT IBAN Registry country-length table (rejecting
  unregistered country codes like `ZZ..`, supporting 15-to-34 char IBANs including
  15-char Norway `NO` and 30-char Yemen `YE`) + Rearrange + `mod 97 == 1` checksum.
- SWIFT / BIC (ISO 9362): Complete 249-code ISO 3166-1 alpha-2 table (plus `XK`) at
  chars 4..6 AND explicit banking/SWIFT context check for 8-letter all-alpha tokens
  so ordinary English words (`WORKSHOP`, `DOCUMENT`, `ABCDEFGH`) are never misflagged.
- UK Sort Code + Account Number: Restricts 8-digit account pairing to a local
  120-character window around a Sort Code strictly inside the SAME single message.
- Keyed Ephemeral Redaction: Default redaction uses per-run `HMAC-SHA256` tokens rather
  than partial prefix/suffix masking to prevent dictionary confirmation across reports.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, List

DEFAULT_EPHEMERAL_SALT = secrets.token_bytes(32)

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

COMMON_ENGLISH_8LETTER_STOPWORDS = {
    "WORKSHOP", "TRANSFER", "DOCUMENT", "SECURITY", "PASSPORT", "OFFICIAL",
    "CHECKING", "RECEIVED", "REQUIRED", "RESPONSE", "EVIDENCE", "NATIONAL",
    "CUSTOMER", "PERSONAL", "BUSINESS", "APPROVED", "REJECTED", "COMPLETE",
}


def empty_ioc_dict() -> Dict[str, List[Any]]:
    return {
        "luhn_validated_cards": [],
        "unvalidated_card_candidates": [],
        "mod97_validated_ibans": [],
        "context_paired_uk_accounts": [],
        "unpaired_uk_sort_codes": [],
        "validated_swift_bics": [],
    }


def merge_ioc_dicts(dst: Dict[str, List[Any]], src: Dict[str, List[Any]]) -> None:
    """Merge per-message IOC results without cross-message proximity contamination."""
    for k, items in src.items():
        bucket = dst.setdefault(k, [])
        for item in items:
            if item not in bucket:
                bucket.append(item)


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
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
    if len(cleaned) < 15 or len(cleaned) > 34:
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


def mask_identifier(val: str, salt: bytes | None = None) -> str:
    """Keyed HMAC-SHA256 redaction without leaking prefix/suffix characters."""
    if not val:
        return ""
    key = salt if salt is not None else DEFAULT_EPHEMERAL_SALT
    digest = hmac.new(key, val.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"[REDACTED_HMAC:{digest}]"


def extract_validated_iocs(
    text: str,
    redact: bool = True,
    salt: bytes | None = None,
) -> Dict[str, Any]:
    out = empty_ioc_dict()
    if not text:
        return out

    def fmt(s: str) -> str:
        return mask_identifier(s, salt=salt) if redact else s

    # 1. ISO/IEC 7812 payment cards (major network IIN ranges 4/5/62) allowing spaces or hyphens
    for m in re.finditer(r"(?<!\d)(?:4\d|5[1-5]|62)(?:[\s-]?\d){11,17}(?!\d)", text):
        digits = re.sub(r"[\s-]", "", m.group(0))
        if not (13 <= len(digits) <= 19):
            continue
        rendered = fmt(digits)
        if luhn_valid(digits):
            if rendered not in out["luhn_validated_cards"]:
                out["luhn_validated_cards"].append(rendered)
        else:
            if rendered not in out["unvalidated_card_candidates"]:
                out["unvalidated_card_candidates"].append(rendered)

    # 2. IBAN (ISO 13616 Mod-97 + strict registered country length 15..34)
    for m in re.finditer(r"\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]{2,4}){2,8}(?:[\s-]?[A-Z0-9]{1,3})?\b", text):
        cand = re.sub(r"[\s-]+", "", m.group(0))
        if iban_mod97_valid(cand):
            rendered = fmt(cand)
            if rendered not in out["mod97_validated_ibans"]:
                out["mod97_validated_ibans"].append(rendered)

    # 3. UK Sort Code + local-window (<=120 chars) 8-digit Account Number pairing (intra-message only)
    for sc_match in re.finditer(r"(?<!\d)\d{2}-\d{2}-\d{2}(?!\d)", text):
        sc = sc_match.group(0)
        win_start = max(0, sc_match.start() - 120)
        win_end = min(len(text), sc_match.end() + 120)
        window = text[win_start:win_end]
        acc_matches = re.findall(r"(?<!\d)\d{8}(?!\d)", window)
        if acc_matches:
            for acc in acc_matches:
                pair = {
                    "sort_code": fmt(sc),
                    "account_number": fmt(acc),
                    "validation_note": "Context-paired within 120 chars in same message (Pay.UK Vocalink modulus table not bundled)",
                }
                if pair not in out["context_paired_uk_accounts"]:
                    out["context_paired_uk_accounts"].append(pair)
        else:
            rendered_sc = fmt(sc)
            if rendered_sc not in out["unpaired_uk_sort_codes"]:
                out["unpaired_uk_sort_codes"].append(rendered_sc)

    # 4. SWIFT / BIC (ISO 9362): valid ISO 3166 country at [4:6] + stopword rejection + context check
    has_swift_ctx = bool(re.search(r"\b(swift|bic|routing|wire|beneficiary|iban)\b", text, re.IGNORECASE))
    for bic_m in re.finditer(r"\b([A-Z]{4})([A-Z]{2})([A-Z0-9]{2})([A-Z0-9]{3})?\b", text):
        full_bic = bic_m.group(0)
        country = bic_m.group(2)
        branch = bic_m.group(4)
        if country not in ISO_3166_ALPHA2:
            continue
        if full_bic in COMMON_ENGLISH_8LETTER_STOPWORDS:
            continue
        if len(full_bic) == 8 and full_bic.isalpha() and not has_swift_ctx:
            continue
        if branch is None or len(full_bic) in (8, 11):
            rendered_bic = fmt(full_bic)
            if rendered_bic not in out["validated_swift_bics"]:
                out["validated_swift_bics"].append(rendered_bic)

    return out
