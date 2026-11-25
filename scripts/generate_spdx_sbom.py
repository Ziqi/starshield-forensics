#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Deterministic ISO/IEC 5962:2021 (SPDX-2.3) JSON SBOM generator for starshield-forensics.

Emits a reproducible SPDX 2.3 JSON document describing the zero-third-party-dependency
release artifacts (`starshield.pyz`, wheel, and sdist), enforcing strict version parity
against `starshield.__version__` and computing exact SHA-256 digests from built distributions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield import __version__ as STARSHIELD_VERSION  # noqa: E402

RELEASE_VERSION = "0.4.0"
CREATED_UTC = "2026-11-25T00:00:00Z"

PINNED_PYZ_SHA256 = "19795b019d1f7f605f9bf7f17ba886bd261311faeac24bdb8488724c03086272"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_spdx_document(
    *,
    wheel_sha256: str | None = None,
    sdist_sha256: str | None = None,
) -> dict[str, object]:
    release_base = f"https://github.com/Ziqi/starshield-forensics/releases/download/v{RELEASE_VERSION}"
    supplier = "Person: Ziqi Xiao (2196305+Ziqi@users.noreply.github.com)"
    copyright_text = "Copyright (c) 2026 Ziqi Xiao"

    wheel_pkg: dict[str, object] = {
        "SPDXID": "SPDXRef-Distribution-Wheel",
        "name": "starshield-forensics-wheel",
        "versionInfo": RELEASE_VERSION,
        "packageFileName": f"starshield_forensics-{RELEASE_VERSION}-py3-none-any.whl",
        "supplier": supplier,
        "downloadLocation": f"{release_base}/starshield_forensics-{RELEASE_VERSION}-py3-none-any.whl",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": copyright_text,
        "primaryPackagePurpose": "LIBRARY",
    }
    if wheel_sha256 is not None:
        wheel_pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": wheel_sha256}]

    sdist_pkg: dict[str, object] = {
        "SPDXID": "SPDXRef-Distribution-Sdist",
        "name": "starshield-forensics-sdist",
        "versionInfo": RELEASE_VERSION,
        "packageFileName": f"starshield_forensics-{RELEASE_VERSION}.tar.gz",
        "supplier": supplier,
        "downloadLocation": f"{release_base}/starshield_forensics-{RELEASE_VERSION}.tar.gz",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": copyright_text,
        "primaryPackagePurpose": "SOURCE",
    }
    if sdist_sha256 is not None:
        sdist_pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": sdist_sha256}]

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"starshield-forensics-{RELEASE_VERSION}",
        "documentNamespace": f"https://ziqi.github.io/starshield/spdx/starshield-forensics-{RELEASE_VERSION}",
        "creationInfo": {
            "created": CREATED_UTC,
            "creators": [
                supplier,
                "Tool: starshield-spdx-generator-1.1",
            ],
            "licenseListVersion": "3.25",
            "comment": (
                f"Deterministic SPDX 2.3 SBOM for starshield-forensics v{RELEASE_VERSION} "
                "(Python >=3.10 standard library only; zero external runtime dependencies)."
            ),
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-starshield-forensics",
                "name": "starshield-forensics",
                "versionInfo": RELEASE_VERSION,
                "packageFileName": "starshield.pyz",
                "supplier": supplier,
                "originator": supplier,
                "downloadLocation": f"{release_base}/starshield.pyz",
                "filesAnalyzed": False,
                "homepage": "https://ziqi.github.io/starshield/",
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": copyright_text,
                "primaryPackagePurpose": "APPLICATION",
                "summary": (
                    "Offline Chromium/Electron LevelDB .log & Snappy .ldb/MANIFEST carver, "
                    "PNG/JPEG/PDF container structure inspector, identifier checksum verifier, "
                    "and structural MCP server."
                ),
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": PINNED_PYZ_SHA256,
                    }
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/starshield-forensics@{RELEASE_VERSION}",
                    }
                ],
            },
            wheel_pkg,
            sdist_pkg,
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-starshield-forensics",
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Distribution-Wheel",
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Distribution-Sdist",
            },
        ],
    }


def validate_spdx_document(
    doc: dict[str, object],
    pyz_path: Path | None = None,
    *,
    require_dists: bool = False,
    wheel_path: Path | None = None,
    sdist_path: Path | None = None,
) -> None:
    if RELEASE_VERSION != STARSHIELD_VERSION:
        raise SystemExit(
            f"SPDX version mismatch: RELEASE_VERSION={RELEASE_VERSION!r} != starshield.__version__={STARSHIELD_VERSION!r}"
        )
    required_top = {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages"}
    missing = required_top - set(doc.keys())
    if missing:
        raise SystemExit(f"SPDX validation failed: missing top-level keys {sorted(missing)}")
    if doc.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit(f"Unexpected spdxVersion: {doc.get('spdxVersion')}")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SystemExit(f"Unexpected SPDXID: {doc.get('SPDXID')}")
    if doc.get("name") != f"starshield-forensics-{STARSHIELD_VERSION}":
        raise SystemExit(f"Unexpected SPDX name: {doc.get('name')}")

    if require_dists:
        for label, p in (("pyz", pyz_path), ("wheel", wheel_path), ("sdist", sdist_path)):
            if p is None or not p.is_file():
                raise SystemExit(f"--require-dists failed: missing {label} artifact at {p}")

    if pyz_path is not None and pyz_path.is_file():
        actual = _sha256_file(pyz_path)
        if actual != PINNED_PYZ_SHA256:
            raise SystemExit(f"PYZ digest mismatch: expected {PINNED_PYZ_SHA256}, got {actual}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate deterministic SPDX 2.3 JSON SBOM for starshield-forensics")
    ap.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "dist" / f"starshield-forensics-{RELEASE_VERSION}.spdx.json",
        help="Destination path for SPDX 2.3 JSON file",
    )
    ap.add_argument(
        "--verify-pyz",
        type=Path,
        default=None,
        help="Optional path to starshield.pyz to cross-verify pinned SHA-256 digest",
    )
    ap.add_argument(
        "--wheel",
        type=Path,
        default=REPO_ROOT / "dist" / f"starshield_forensics-{RELEASE_VERSION}-py3-none-any.whl",
        help="Optional path to built wheel for SHA-256 recording",
    )
    ap.add_argument(
        "--sdist",
        type=Path,
        default=REPO_ROOT / "dist" / f"starshield_forensics-{RELEASE_VERSION}.tar.gz",
        help="Optional path to built sdist for SHA-256 recording",
    )
    ap.add_argument(
        "--require-dists",
        action="store_true",
        help="Fail with non-zero exit unless pyz, wheel, and sdist all exist on disk",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="Validate generated SPDX 2.3 structure, version parity, and deterministic serialization",
    )
    args = ap.parse_args()

    effective_pyz = args.verify_pyz
    if effective_pyz is None:
        default_pyz = REPO_ROOT / "dist" / "starshield.pyz"
        if default_pyz.is_file():
            effective_pyz = default_pyz

    wheel_sha = _sha256_file(args.wheel) if args.wheel.is_file() else None
    sdist_sha = _sha256_file(args.sdist) if args.sdist.is_file() else None

    doc = build_spdx_document(wheel_sha256=wheel_sha, sdist_sha256=sdist_sha)
    if args.verify or effective_pyz is not None or args.require_dists:
        validate_spdx_document(
            doc,
            effective_pyz,
            require_dists=args.require_dists,
            wheel_path=args.wheel,
            sdist_path=args.sdist,
        )

    serialized = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    if args.verify:
        second = json.dumps(
            build_spdx_document(wheel_sha256=wheel_sha, sdist_sha256=sdist_sha),
            indent=2,
            sort_keys=False,
        ) + "\n"
        if serialized != second:
            raise SystemExit("SPDX serialization is not deterministic")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialized.encode("utf-8"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    mode_tag = "pyz+wheel+sdist" if (wheel_sha and sdist_sha) else "pyz-only"
    print(f"SPDX_2_3_OK version={RELEASE_VERSION} dists={mode_tag} sha256={digest} path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
