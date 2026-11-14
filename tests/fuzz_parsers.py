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
  - `starshield.ioc_validators`: ISO/IEC 7812 Luhn, ISO 13616 IBAN Mod-97, and BIC checks.
"""

from __future__ import annotations

import argparse
import pathlib
import random
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield.cli import build_synthetic_leveldb_wal_bytes  # noqa: E402
from starshield.image_containers import (  # noqa: E402
    build_valid_jpeg_with_icc_and_8bim,
    build_valid_png_with_iccp,
    inspect_image_container,
)
from starshield.ioc_validators import (  # noqa: E402
    extract_validated_iocs,
    iban_mod97_valid,
    luhn_valid,
)
from starshield.leveldb_log import VALID_SCHEMA_MODES, parse_leveldb_wal  # noqa: E402


def fuzz_one_bytes(data: bytes) -> None:
    """Exercise all binary and mathematical parsers on arbitrary untrusted byte streams."""
    mode = VALID_SCHEMA_MODES[data[0] % len(VALID_SCHEMA_MODES)] if data else "auto"

    wal_res = parse_leveldb_wal(data, schema_mode=mode)
    if wal_res["corrupted_frames_count"] < 0 or wal_res["valid_physical_frames"] < 0:
        raise AssertionError("Negative frame count invariant violated")

    img_res = inspect_image_container(data, label="fuzz_input")
    if not isinstance(img_res.get("valid_container"), bool):
        raise AssertionError("Container inspector failed to emit boolean valid_container")

    text = data.decode("utf-8", errors="replace")
    iocs = extract_validated_iocs(text, redact=False)
    for iban in iocs["mod97_validated_ibans"]:
        if not iban_mod97_valid(iban):
            raise AssertionError(f"Unvalidated IBAN leaked through Mod-97 gate: {iban!r}")
    for card in iocs["luhn_validated_cards"]:
        if not luhn_valid(card):
            raise AssertionError(f"Unvalidated card leaked through Luhn gate: {card!r}")


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
    seeds = [
        build_synthetic_leveldb_wal_bytes(),
        build_valid_png_with_iccp(profile_desc="Display P3", platform="APPL"),
        build_valid_jpeg_with_icc_and_8bim(profile_desc="sRGB IEC61966-2.1", platform="MSFT"),
        b"Wire GBP 18,400.00 to GB82WEST12345698765432 or NO9386011117947 card 6200000000000005 SWIFT NWBKGB2L",
    ]
    edge_cases = [
        b"",
        b"\x00" * 7,
        b"\x00" * 32768,
        b"\xff" * 64,
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
        b"\xff\xd8\xff\xe2\x00\x10ICC_PROFILE\x00\x01\x01",
        b"\xff\xd8\xff\xda\x00\x02\xff\x00\xff\xd9",
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
