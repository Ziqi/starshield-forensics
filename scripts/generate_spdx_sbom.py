#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Deterministic ISO/IEC 5962:2021 (SPDX-2.3) JSON SBOM generator for starshield-forensics.

Emits a reproducible SPDX 2.3 JSON document describing the zero-third-party-dependency
release artifacts (`starshield.pyz`, wheel, and sdist) with pinned SHA-256 digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_VERSION = "0.3.7"
CREATED_UTC = "2026-11-12T00:00:00Z"

PINNED_PYZ_SHA256 = "e6603ef083b20a5460bf56818f63a3a94b856deb377a5b6330be2394e0e21232"
PINNED_WHEEL_SHA256 = "4ffe6454c4ec78d3485326a4ac763ce1abaa1205009b057d07f69ad99dc37730"
PINNED_SDIST_SHA256 = "2dd56e823d46fd41d570ee6281d98db120ad64e64b55950827ef57c186e40edd"


def build_spdx_document() -> dict[str, object]:
    release_base = f"https://github.com/Ziqi/starshield-forensics/releases/download/v{RELEASE_VERSION}"
    supplier = "Person: Ziqi Xiao (2196305+Ziqi@users.noreply.github.com)"
    copyright_text = "Copyright (c) 2026 Ziqi Xiao"

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
                "Tool: starshield-spdx-generator-1.0",
            ],
            "licenseListVersion": "3.25",
            "comment": (
                "Deterministic SPDX 2.3 SBOM for starshield-forensics v0.3.7 "
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
                    "Offline Chromium IndexedDB/LevelDB .log carver, PNG/JPEG ICC inspector, "
                    "and ISO-13616/Luhn checksum validator."
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
            {
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
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": PINNED_WHEEL_SHA256,
                    }
                ],
            },
            {
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
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": PINNED_SDIST_SHA256,
                    }
                ],
            },
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


def validate_spdx_document(doc: dict[str, object], pyz_path: Path | None = None) -> None:
    required_top = {"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages"}
    missing = required_top - set(doc.keys())
    if missing:
        raise SystemExit(f"SPDX validation failed: missing top-level keys {sorted(missing)}")
    if doc.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit(f"Unexpected spdxVersion: {doc.get('spdxVersion')}")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SystemExit(f"Unexpected SPDXID: {doc.get('SPDXID')}")
    if pyz_path is not None and pyz_path.is_file():
        actual = hashlib.sha256(pyz_path.read_bytes()).hexdigest()
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
        "--verify",
        action="store_true",
        help="Validate generated SPDX 2.3 structure and deterministic serialization",
    )
    args = ap.parse_args()

    doc = build_spdx_document()
    if args.verify or args.verify_pyz is not None:
        validate_spdx_document(doc, args.verify_pyz)

    serialized = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    if args.verify:
        second = json.dumps(build_spdx_document(), indent=2, sort_keys=False) + "\n"
        if serialized != second:
            raise SystemExit("SPDX serialization is not deterministic")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(serialized.encode("utf-8"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    print(f"SPDX_2_3_OK sha256={digest} path={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
