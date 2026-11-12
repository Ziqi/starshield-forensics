#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bit-for-bit reproducible single-file zipapp builder (`starshield.pyz`).

Normalizes file ordering, permissions, and ZIP header timestamps (2026-01-01 00:00:00 UTC)
so repeated builds from identical source trees yield identical SHA-256 digests (`build_repeatable`).
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import tempfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
SHEBANG = b"#!/usr/bin/env python3\n"
ENTRYPOINT_MAIN = (
    "# -*- coding: utf-8 -*-\n"
    "from starshield.cli import main\n"
    "if __name__ == '__main__':\n"
    "    raise SystemExit(main())\n"
).encode("utf-8")


def build_deterministic_pyz(out_path: Path) -> str:
    pkg_dir = REPO_ROOT / "starshield"
    source_files = sorted(
        p for p in pkg_dir.rglob("*") if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(".pyc")
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_zip = Path(tmp.name)

    try:
        with zipfile.ZipFile(tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            main_info = zipfile.ZipInfo("__main__.py", date_time=FIXED_ZIP_DT)
            main_info.compress_type = zipfile.ZIP_DEFLATED
            main_info.external_attr = 0o644 << 16
            main_info.create_system = 3
            zf.writestr(main_info, ENTRYPOINT_MAIN)

            for src in source_files:
                rel = src.relative_to(REPO_ROOT).as_posix()
                zinfo = zipfile.ZipInfo(rel, date_time=FIXED_ZIP_DT)
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zinfo.external_attr = 0o644 << 16
                zinfo.create_system = 3
                data = src.read_bytes()
                if src.suffix in {".py", ".json"}:
                    data = data.replace(b"\r\n", b"\n")
                zf.writestr(zinfo, data)

        payload = SHEBANG + tmp_zip.read_bytes()
        out_path.write_bytes(payload)
        out_path.chmod(0o755)
        return hashlib.sha256(payload).hexdigest()
    finally:
        tmp_zip.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build bit-for-bit reproducible starshield.pyz")
    ap.add_argument("--output", type=Path, default=REPO_ROOT / "dist" / "starshield.pyz")
    ap.add_argument("--verify", action="store_true", help="Build twice and assert identical bit-for-bit SHA-256")
    args = ap.parse_args()

    digest1 = build_deterministic_pyz(args.output)
    if args.verify:
        with tempfile.TemporaryDirectory() as td:
            digest2 = build_deterministic_pyz(Path(td) / "starshield_second.pyz")
        if digest1 != digest2:
            raise SystemExit(f"Reproducibility check FAILED: {digest1} != {digest2}")
        print(f"REPRODUCIBLE_OK sha256={digest1} path={args.output}")
    else:
        print(f"{digest1}  {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
