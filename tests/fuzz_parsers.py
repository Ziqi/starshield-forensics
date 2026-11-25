#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Dual-Mode Continuous Fuzzing Harness (`tests/fuzz_parsers.py`).

Supports both:
  1. Native Google Atheris / ClusterFuzzLite coverage-guided libFuzzer execution.
  2. Zero-dependency deterministic & structure-aware mutation fuzzing (`--stdlib`)
     executed on every CI push and pull request without third-party packages.

Targets:
  - `starshield.leveldb_log.parse_leveldb_wal`: 32 KiB block framing, masked CRC32C,
    cross-block WriteBatch reassembly, and UTF-8 / UTF-16LE JSON carving.
  - `starshield.image_containers.inspect_image_container`: RFC 2083 PNG chunk CRC32,
    bounded zlib `iCCP` decompression, and ISO 10918-1 JPEG `APP2` / `8BIM` scanning.
  - `starshield.pdf_containers.inspect_pdf_container` + `apply_pdf_redaction`: ISO 32000-1
    multi-revision `%%EOF` / `xref` / `startxref` inspection, O(N) nested-parenthesis string
    decoding, XMP scanning, bounded `FlateDecode` decompression, and non-mutating redaction.
  - `starshield.ioc_validators`: ISO/IEC 7812 Luhn, ISO 13616 IBAN Mod-97, BIC, US ABA 3-7-1,
    ISO 11649 RF Mod-97, ISO 17442 LEI, TRON TRC-20 Base58Check, and Ethereum EIP-55 Keccak-256.
"""

from __future__ import annotations

import argparse
import codecs
import copy
import json
import pathlib
import random
import sys
import time
import zlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield.cli import (  # noqa: E402
    apply_image_redaction,
    build_synthetic_leveldb_sstable_bytes,
    build_synthetic_leveldb_wal_bytes,
)
from starshield.image_containers import (  # noqa: E402
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (  # noqa: E402
    aba_routing_valid,
    eth_eip55_checksum_valid,
    extract_validated_iocs,
    iban_mod97_valid,
    iso11649_creditor_ref_valid,
    lei_iso17442_valid,
    luhn_valid,
    tron_trc20_address_valid,
)
from starshield.leveldb_log import VALID_SCHEMA_MODES, parse_leveldb_wal  # noqa: E402
from starshield.leveldb_sstable import (  # noqa: E402
    decompress_snappy,
    parse_leveldb_manifest,
    parse_leveldb_sstable,
)
from starshield.pdf_containers import (  # noqa: E402
    apply_pdf_redaction,
    build_synthetic_incremental_pdf,
    inspect_pdf_container,
)


def fuzz_one_bytes(data: bytes) -> None:
    """Exercise all binary and mathematical parsers on arbitrary untrusted byte streams."""
    t_start = time.perf_counter()
    mode = VALID_SCHEMA_MODES[data[0] % len(VALID_SCHEMA_MODES)] if data else "auto"

    wal_res = parse_leveldb_wal(data, schema_mode=mode)
    if wal_res["corrupted_frames_count"] < 0 or wal_res["valid_physical_frames"] < 0:
        raise AssertionError("Negative frame count invariant violated")

    sst_res = parse_leveldb_sstable(
        data,
        schema_mode=mode,
        budget_state={"remaining": 4 * 1024 * 1024},
    )
    if sst_res["corrupted_blocks_count"] < 0 or sst_res["data_blocks_verified"] < 0:
        raise AssertionError("Negative SSTable block count invariant violated")

    man_res = parse_leveldb_manifest(data)
    if man_res["version_edits_applied"] < 0 or man_res["corrupted_frames_count"] < 0:
        raise AssertionError("Negative MANIFEST count invariant violated")

    try:
        decompress_snappy(data, max_uncompressed_bytes=1024 * 1024)
    except (ValueError, BufferError):
        pass

    img_res = inspect_image_container(data, label="fuzz_input")
    if not isinstance(img_res.get("valid_container"), bool):
        raise AssertionError("Container inspector failed to emit boolean valid_container")
    img_snapshot = copy.deepcopy(img_res)
    red_img = apply_image_redaction(img_res, redact=True)
    if img_res != img_snapshot:
        raise AssertionError("apply_image_redaction mutated input img_report in-place")
    if red_img.get("artifact") != "[REDACTED_IMAGE_LABEL]":
        raise AssertionError("apply_image_redaction failed to redact artifact label")
    for prof in red_img.get("icc_profiles", []):
        if isinstance(prof, dict) and prof.get("description_hint") is not None:
            if not str(prof["description_hint"]).startswith("[REDACTED_HMAC:"):
                raise AssertionError("apply_image_redaction leaked unmasked description_hint")

    pdf_res = inspect_pdf_container(data, label="fuzz_pdf")
    if not isinstance(pdf_res.get("valid_container"), bool):
        raise AssertionError("PDF inspector failed to emit boolean valid_container")
    pdf_snapshot = copy.deepcopy(pdf_res)
    red_pdf = apply_pdf_redaction(pdf_res, redact=True)
    if pdf_res != pdf_snapshot:
        raise AssertionError("apply_pdf_redaction mutated input pdf_report in-place")
    if (
        red_pdf.get("artifact") != "[REDACTED_PDF_LABEL]"
        or red_pdf.get("file_size_bytes") is not None
        or red_pdf.get("trailing_bytes_after_final_eof") is not None
    ):
        raise AssertionError("apply_pdf_redaction failed to redact artifact, file_size_bytes, or trailing_bytes")
    for off_k in (
        "header_offset",
        "eof_offsets",
        "startxref_offsets",
        "xref_offsets",
        "xref_stream_offsets",
    ):
        if off_k in red_pdf and red_pdf[off_k] is not None:
            raise AssertionError(f"apply_pdf_redaction leaked structural offset field {off_k}")
    for vals in red_pdf.get("info_metadata", {}).values():
        if not all(isinstance(v, str) and v.startswith("[REDACTED_") for v in vals):
            raise AssertionError("apply_pdf_redaction leaked unredacted info_metadata value")
    for xmp in red_pdf.get("xmp_metadata", []):
        if xmp.get("source_offset") is not None:
            raise AssertionError("apply_pdf_redaction leaked xmp source_offset")
        for dt_k in ("create_date", "modify_date"):
            if xmp.get(dt_k) not in (None, "[REDACTED_PDF_TIMESTAMP]"):
                raise AssertionError(f"apply_pdf_redaction leaked XMP {dt_k}")
        for id_k in ("creator_tool", "producer", "document_id", "instance_id"):
            val = xmp.get(id_k)
            if val is not None and not str(val).startswith("[REDACTED_HMAC:"):
                raise AssertionError(f"apply_pdf_redaction leaked XMP {id_k}")

    text = data.decode("utf-8", errors="replace")
    iocs = extract_validated_iocs(text, redact=False)
    for iban in iocs["mod97_validated_ibans"]:
        if not iban_mod97_valid(iban):
            raise AssertionError(f"Unvalidated IBAN leaked through Mod-97 gate: {iban!r}")
    for card in iocs["luhn_validated_cards"]:
        if not luhn_valid(card):
            raise AssertionError(f"Unvalidated card leaked through Luhn gate: {card!r}")
    for aba in iocs["aba_validated_routing_numbers"]:
        if not aba_routing_valid(aba):
            raise AssertionError(f"Unvalidated ABA routing leaked through 3-7-1 gate: {aba!r}")
    for rf in iocs["iso11649_creditor_references"]:
        if not iso11649_creditor_ref_valid(rf):
            raise AssertionError(f"Unvalidated ISO 11649 ref leaked through Mod-97 gate: {rf!r}")
    for lei in iocs["validated_leis"]:
        if not lei_iso17442_valid(lei):
            raise AssertionError(f"Unvalidated LEI leaked through ISO 17442 gate: {lei!r}")
    for tron in iocs["base58check_tron_addresses"]:
        if not tron_trc20_address_valid(tron):
            raise AssertionError(f"Unvalidated TRON address leaked through Base58Check gate: {tron!r}")
    for eth in iocs["eip55_eth_addresses"]:
        if not eth_eip55_checksum_valid(eth):
            raise AssertionError(f"Unvalidated Ethereum address leaked through EIP-55 gate: {eth!r}")

    masked_iocs = extract_validated_iocs(text, redact=True)
    serialized_masked = json.dumps(masked_iocs)
    for bucket_name, items in masked_iocs.items():
        if bucket_name == "context_paired_uk_accounts":
            for pair in items:
                if not (
                    pair["sort_code"].startswith("[REDACTED_HMAC:")
                    and pair["account_number"].startswith("[REDACTED_HMAC:")
                ):
                    raise AssertionError("Unredacted UK sort/account leaked in masked IOC output")
        else:
            for tok in items:
                if not tok.startswith("[REDACTED_HMAC:"):
                    raise AssertionError(f"Unredacted token in {bucket_name}: {tok!r}")
    for sensitive_bucket in (
        "mod97_validated_ibans",
        "aba_validated_routing_numbers",
        "iso11649_creditor_references",
        "validated_leis",
        "base58check_tron_addresses",
        "eip55_eth_addresses",
    ):
        for raw_val in iocs[sensitive_bucket]:
            if raw_val in serialized_masked:
                raise AssertionError(f"Raw {sensitive_bucket} indicator leaked into masked IOC output")

    elapsed = time.perf_counter() - t_start
    if elapsed >= 1.0:
        raise AssertionError(f"Per-input fuzz wall-clock oracle violated: {elapsed:.3f}s >= 1.0s")


def _mutate_seed(seed_bytes: bytes, rng: random.Random) -> bytes:
    if not seed_bytes:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 128)))
    buf = bytearray(seed_bytes)
    op = rng.randrange(4)
    if op == 0:
        # Multi-byte random bit/byte flips
        for _ in range(rng.randint(1, 16)):
            idx = rng.randrange(len(buf))
            buf[idx] ^= rng.randint(1, 255)
    elif op == 1:
        # Arbitrary truncation (simulating torn writes / power loss)
        cut = rng.randrange(len(buf))
        del buf[cut:]
    elif op == 2:
        # Splice garbage header/trailer bytes across 32 KiB boundaries
        pos = rng.randrange(len(buf) + 1)
        patch = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        buf[pos:pos] = patch
    else:
        # Duplicate slice
        start = rng.randrange(len(buf))
        end = min(len(buf), start + rng.randint(1, 128))
        buf.extend(buf[start:end])
    return bytes(buf)


def run_stdlib_campaign(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    valid_xmp_comp = zlib.compress(
        b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        b'<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
        b'xmp:CreatorTool="FuzzSuite 1.0" xmp:CreateDate="2026-03-18T10:00:00Z"/>'
        b'<?xpacket end="w"?>'
    )
    truncated_flate = valid_xmp_comp[:-6]
    utf16le_hex = (codecs.BOM_UTF16_LE + "MeridianLE".encode("utf-16-le")).hex().upper().encode("ascii")
    utf8_lit = codecs.BOM_UTF8 + b"MeridianUTF8 (v2)"
    rich_pdf_seed = (
        build_synthetic_incremental_pdf()
        + b"\n5 0 obj\n<< /Author % inline comment\n(" + utf8_lit + b") /Title <" + utf16le_hex + b"> "
        + b"/Filter /FlateDecode >>\nstream\n" + valid_xmp_comp + b"endstream\nendobj\n%%EOF\n"
    )
    cobj = zlib.compressobj(level=1)
    partial_corrupt_flate = cobj.compress(b"\x00" * 131072) + cobj.flush(zlib.Z_SYNC_FLUSH) + b"\x06"
    stored_with_fake_endstream = zlib.compress(b"4 0 << /Producer (ObjStmFuzz) >>\nendstream \n/JS", level=0)
    hex_escaped_pdf_seed = (
        b"%PDF-1.5\n"
        b"1 0 obj\n<< /Pro#64ucer (HexEscapedProducer) /S /Java#53cript /J#53 (1) >>\nendobj\n"
        + f"2 0 obj\n<< /Type /ObjStm /Filter /Flate#44ecode /Length {len(stored_with_fake_endstream)} >>\nstream\n".encode(
            "ascii"
        )
        + stored_with_fake_endstream
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    ascii_hex_objstm_body = b"1 0 << /Producer (HexStreamProd) /S /JavaScript >>".hex().upper().encode("ascii") + b">"
    ascii_hex_objstm_seed = (
        b"%PDF-1.6\n1 0 obj\n<< /Type /ObjStm /Filter /ASCIIHexDecode >>\nstream\n"
        + ascii_hex_objstm_body
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    lf_comment_flate = zlib.compress(b"%\n" * 50000, level=1)
    benign_comp = zlib.compress(b"benign")
    lying_mid = (
        benign_comp
        + b"\nendstream\nendobj\n2 0 obj\n<< /OpenAction << /S /JavaScript /JS (1) >> /Producer (Swallowed) >>\n"
        b"endobj\n3 0 obj\n<< /Length 5 >>\nstream\nhello"
    )
    lying_len_pdf = (
        f"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length {len(lying_mid)} >>\nstream\n".encode("ascii")
        + lying_mid
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    dct_smuggle_body = (
        b"\xff\xd8\xff\xe0\n2 0 obj\n<< /OpenAction << /S /JavaScript /JS (1) >> /AcroForm << >> >>\nendobj\n"
        b"4 0 obj\n<< /Producer (HiddenForge 9) >>\nendobj\n\xff\xd9"
    )
    dct_smuggle_pdf = (
        f"%PDF-1.4\n1 0 obj\n<< /Subtype /Image /Filter /DCTDecode /Length {len(dct_smuggle_body)} >>\nstream\n".encode(
            "ascii"
        )
        + dct_smuggle_body
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    r3_combined_pdf_seed = (
        b"%PDF-1.6\n"
        b"1 0 obj\n<< /Note (/Filter /DCTDecode /Length 9999) % /Filter /DCTDecode\n"
        b"/Sub << /Filter /DCTDecode >> >>\nstream\n/S /JavaScript /JS (1) /OpenAction 1\nendstream\nendobj\n"
        b"2 0 obj\n<< /Pad (" + (b"A" * 5000) + b") /Filter /FlateDecode >>" + (b" " * 513) + b"stream\n"
        + valid_xmp_comp
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    seeds = [
        build_synthetic_leveldb_wal_bytes(),
        build_synthetic_leveldb_sstable_bytes(),
        build_valid_png_with_iccp(profile_desc="Display P3", platform="APPL"),
        build_valid_jpeg_with_icc_and_8bim(profile_desc="sRGB IEC61966-2.1", platform="MSFT"),
        build_synthetic_incremental_pdf(),
        rich_pdf_seed,
        hex_escaped_pdf_seed,
        ascii_hex_objstm_seed,
        r3_combined_pdf_seed,
        dct_smuggle_pdf,
        (
            b"Wire GBP 18,400.00 to GB82WEST12345698765432 or NO9386011117947 card 6200000000000005 "
            b"SWIFT NWBKGB2L ABA routing 021000021 RF18539007547034 LEI 5493001KJTIIGC8Y1R12 "
            b"TRON TYzVpTxq4B6s9cXMUUV5NCaZ3YCKz6UzfM ETH 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ),
    ]
    edge_cases = [
        b"",
        b"\x00" * 7,
        b"\x00" * 32768,
        b"\xff" * 64,
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        b"\xff\xd8\xff\xe2\x00\x10ICC_PROFILE\x00\x01\x01",
        b"\xff\xd8\xff\xda\x00\x02\xff\x00\xff\xd9",
        b"%PDF-1.4\n" + (b"/Producer (" * 512),
        b"%PDF-1.4\n/Producer " + (b"(" * 5000) + b"\n%%EOF\n",
        b"%PDF-1.4\n(\n1 0 obj\n<< /Producer (ResyncedAfterStrayParen) /Filter /FlateDecode >>\nstream\n"
        + valid_xmp_comp
        + b"\nendstream\nendobj\n%%EOF\n",
        b"%PDF-1.4\n<<\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + valid_xmp_comp + b"\nendstream\nendobj\n%%EOF\n",
        b"%PDF-1.4\n<<\n<< /Filter /FlateDecode >>\nstream\n" + valid_xmp_comp + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\n" + (b"stream\nAAAA" * 256),
        b"%PDF-1.7 " + (b" streamX" * 2048) + b" %%EOF",
        b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + lf_comment_flate + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\n<< /Filter /FlateDecode /X /stream\n/Comment (a\nstream\nb) >>\nstream\n"
        + valid_xmp_comp
        + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\n<< /Note (/Filter /DCTDecode) >>\nstream\n/S /JavaScript /JS (1)\nendstream\n%%EOF\n",
        b"%PDF-1.4\n<< /Filter /FlateDecode >>" + (b" " * 513) + b"stream\n" + valid_xmp_comp + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\n<< /Pad (" + (b"A" * 5000) + b") /Filter /FlateDecode >>\nstream\n"
        + valid_xmp_comp
        + b"\nendstream\n%%EOF\n",
        dct_smuggle_pdf,
        lying_len_pdf,
        b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + truncated_flate + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n" + partial_corrupt_flate + b"\nendstream\n%%EOF\n",
        b"%PDF-1.4\nstartxref\n" + (b"9" * 5000) + b"\n%%EOF\n",
        b"AA00" + (b"A" * 36) + b" ",
        b"%PDF-1.4\n" + (b'<?xpacket begin=""?><xmp:CreatorTool>B</xmp:CreatorTool><?xpacket end="w"?>' * 300) + b"\n%%EOF\n",
    ]
    for sample in seeds + edge_cases:
        fuzz_one_bytes(sample)

    for i in range(iterations):
        if i % 5 == 0:
            raw = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 4096)))
        else:
            raw = _mutate_seed(seeds[i % len(seeds)], rng)
        fuzz_one_bytes(raw)

    print(
        f"FUZZ_OK iterations={iterations} seeds={len(seeds)} edge_cases={len(edge_cases)} crashes=0"
    )
    return 0


def run_atheris() -> None:
    import atheris  # OpenSSF Scorecard recognized Python coverage-guided fuzzer

    atheris.Setup(sys.argv, fuzz_one_bytes)
    atheris.Fuzz()


def main() -> int:
    parser = argparse.ArgumentParser(description="StarShield Dual-Mode Parser Fuzzing Harness")
    parser.add_argument("--stdlib", action="store_true", help="Force zero-dependency stdlib fuzz campaign")
    parser.add_argument("--atheris", action="store_true", help="Force native Google Atheris libFuzzer loop")
    parser.add_argument("--iterations", type=int, default=2000, help="Iterations for stdlib campaign")
    parser.add_argument("--seed", type=int, default=20261114, help="Deterministic PRNG seed")
    args, _unknown = parser.parse_known_args()

    if args.stdlib:
        return run_stdlib_campaign(args.iterations, args.seed)
    if args.atheris:
        run_atheris()
        return 0
    try:
        import atheris as _probe  # noqa: F401
    except ImportError:
        return run_stdlib_campaign(args.iterations, args.seed)
    run_atheris()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
