#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Ziqi Xiao
# SPDX-License-Identifier: MIT
"""
Bit-for-bit reproducible distribution builder (`starshield.pyz`, PEP 427 `.whl`, and PEP 625 `.tar.gz` sdist).

Normalizes file ordering, line endings, permissions, UID/GID (`0:0`, empty `uname`/`gname`), and archive
timestamps (`2026-01-01 00:00:00 UTC`, `mtime = 1767225600`, gzip `mtime = 0`) using Python >=3.10 stdlib only,
so isolated GitHub Actions runners and offline maintainer workstations produce identical SHA-256 digests.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from starshield import __version__ as STARSHIELD_VERSION  # noqa: E402

FIXED_ZIP_DT = (2026, 1, 1, 0, 0, 0)
FIXED_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
SHEBANG = b"#!/usr/bin/env python3\n"
ENTRYPOINT_MAIN = (
    "# -*- coding: utf-8 -*-\n"
    "from starshield.cli import main\n"
    "if __name__ == '__main__':\n"
    "    raise SystemExit(main())\n"
).encode("utf-8")

PACKAGE_SUMMARY = (
    "Deterministic, offline Chromium & Electron LevelDB (.log & Snappy .ldb/MANIFEST) carver, "
    "PNG/JPEG/PDF structural container inspector, identifier check-digit verifier, and read-only MCP server."
)
PACKAGE_KEYWORDS = (
    "digital-forensics,dfir,leveldb,indexeddb,electron,png-metadata,"
    "image-forensics,iban-validator,mcp,model-context-protocol,evidence-triage"
)
PACKAGE_CLASSIFIERS = (
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Science/Research",
    "Intended Audience :: Information Technology",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
)
TEXT_NORMALIZE_SUFFIXES = {".py", ".json", ".md", ".toml", ".yml", ".yaml", ".cff", ".in", ".txt", ".pub"}


def _read_normalized_bytes(src: Path) -> bytes:
    data = src.read_bytes()
    if src.suffix.lower() in TEXT_NORMALIZE_SUFFIXES or src.name in {"LICENSE", "CURRENT"}:
        data = data.replace(b"\r\n", b"\n")
    return data


def _build_core_metadata_bytes() -> bytes:
    readme_text = (REPO_ROOT / "README.md").read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    lines = [
        "Metadata-Version: 2.4",
        "Name: starshield-forensics",
        f"Version: {STARSHIELD_VERSION}",
        f"Summary: {PACKAGE_SUMMARY}",
        "Author: Ziqi Xiao",
        "License-Expression: MIT",
        "Project-URL: Homepage, https://ziqi.github.io/starshield/",
        "Project-URL: Repository, https://github.com/Ziqi/starshield-forensics",
        f"Keywords: {PACKAGE_KEYWORDS}",
    ]
    for clf in PACKAGE_CLASSIFIERS:
        lines.append(f"Classifier: {clf}")
    lines.extend(
        [
            "Requires-Python: >=3.10",
            "Description-Content-Type: text/markdown",
            "License-File: LICENSE",
            "",
            readme_text.rstrip("\n") + "\n",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={b64}"


def _collect_safe_pkg_files(pkg_dir: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir, followlinks=False):
        cur_d = Path(dirpath)
        for d in list(dirnames):
            dp = cur_d / d
            if dp.is_symlink():
                raise RuntimeError(f"Refusing symbolic-link directory inside package tree: {dp}")
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
        for fname in sorted(filenames):
            if fname.startswith(".") or fname.endswith((".pyc", ".pyo")):
                continue
            fp = cur_d / fname
            if fp.is_symlink():
                raise RuntimeError(f"Refusing symbolic-link file inside package tree: {fp}")
            if not fp.is_file():
                continue
            rel_parts = fp.relative_to(pkg_dir).parts
            if fp.suffix == ".py" or (fp.suffix == ".json" and "data" in rel_parts[:-1]):
                out.append(fp)
    return sorted(out, key=lambda p: p.relative_to(REPO_ROOT).as_posix())


def build_deterministic_pyz(out_path: Path) -> str:
    pkg_dir = REPO_ROOT / "starshield"
    source_files = _collect_safe_pkg_files(pkg_dir)
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
                zf.writestr(zinfo, _read_normalized_bytes(src))

        payload = SHEBANG + tmp_zip.read_bytes()
        out_path.write_bytes(payload)
        out_path.chmod(0o755)
        return hashlib.sha256(payload).hexdigest()
    finally:
        tmp_zip.unlink(missing_ok=True)


def build_deterministic_wheel(out_path: Path) -> str:
    pkg_dir = REPO_ROOT / "starshield"
    pkg_files = _collect_safe_pkg_files(pkg_dir)
    dist_info = f"starshield_forensics-{STARSHIELD_VERSION}.dist-info"
    license_bytes = _read_normalized_bytes(REPO_ROOT / "LICENSE")
    metadata_bytes = _build_core_metadata_bytes()
    wheel_bytes = (
        "Wheel-Version: 1.0\n"
        "Generator: starshield-reproducible-builder (1.0)\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n\n"
    ).encode("utf-8")
    entry_points_bytes = b"[console_scripts]\nstarshield = starshield.cli:main\n"
    top_level_bytes = b"starshield\n"

    entries: list[tuple[str, bytes]] = []
    for src in pkg_files:
        rel = src.relative_to(REPO_ROOT).as_posix()
        entries.append((rel, _read_normalized_bytes(src)))

    entries.extend(
        [
            (f"{dist_info}/licenses/LICENSE", license_bytes),
            (f"{dist_info}/METADATA", metadata_bytes),
            (f"{dist_info}/WHEEL", wheel_bytes),
            (f"{dist_info}/entry_points.txt", entry_points_bytes),
            (f"{dist_info}/top_level.txt", top_level_bytes),
        ]
    )

    record_lines = [f"{arc_path},{_record_hash(blob)},{len(blob)}" for arc_path, blob in entries]
    record_lines.append(f"{dist_info}/RECORD,,")
    record_bytes = ("\n".join(record_lines) + "\n").encode("utf-8")
    entries.append((f"{dist_info}/RECORD", record_bytes))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arc_path, blob in entries:
            zinfo = zipfile.ZipInfo(arc_path, date_time=FIXED_ZIP_DT)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = 0o644 << 16
            zinfo.create_system = 3
            zf.writestr(zinfo, blob)

    raw_whl = buf.getvalue()
    out_path.write_bytes(raw_whl)
    return hashlib.sha256(raw_whl).hexdigest()


def _collect_sdist_source_files() -> list[Path]:
    explicit_top = (
        "CITATION.cff",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "KEYS.pub",
        "LICENSE",
        "MANIFEST.in",
        "README.md",
        "README.zh-CN.md",
        "REUSE.toml",
        "SECURITY-INSIGHTS.yml",
        "SECURITY.md",
        "SECURITY_ASSURANCE_CASE.md",
        "funding.json",
        "pyproject.toml",
    )
    collected: set[Path] = set()
    for name in explicit_top:
        p = REPO_ROOT / name
        if p.is_symlink():
            raise RuntimeError(f"Refusing symbolic-link top-level file in sdist: {p}")
        if p.is_file():
            collected.add(p)

    collected.update(_collect_safe_pkg_files(REPO_ROOT / "starshield"))

    dir_rules: tuple[tuple[str, set[str], set[str]], ...] = (
        ("LICENSES", {".txt"}, set()),
        ("samples", {".json"}, set()),
        ("examples", {".py", ".md", ".ldb", ".log"}, {"CURRENT"}),
        ("tests", {".py"}, set()),
        ("scripts", {".py"}, set()),
        ("benchmark", {".py", ".md"}, set()),
    )
    for sub, exts, exact_names in dir_rules:
        base_d = REPO_ROOT / sub
        if base_d.is_symlink():
            raise RuntimeError(f"Refusing symbolic-link directory in sdist: {base_d}")
        if not base_d.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base_d, followlinks=False):
            cur_d = Path(dirpath)
            for d in list(dirnames):
                dp = cur_d / d
                if dp.is_symlink():
                    raise RuntimeError(f"Refusing symbolic-link directory in sdist: {dp}")
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
            for fname in sorted(filenames):
                if fname.startswith(".") or fname.endswith((".pyc", ".pyo")):
                    continue
                f = cur_d / fname
                if f.is_symlink():
                    raise RuntimeError(f"Refusing symbolic-link file in sdist: {f}")
                if not f.is_file():
                    continue
                if f.suffix.lower() in exts or f.name in exact_names or f.name.startswith("MANIFEST-"):
                    collected.add(f)

    return sorted(collected, key=lambda item: item.relative_to(REPO_ROOT).as_posix())


def build_deterministic_sdist(out_path: Path) -> str:
    root_prefix = f"starshield_forensics-{STARSHIELD_VERSION}"
    src_files = _collect_sdist_source_files()
    pkg_info_bytes = _build_core_metadata_bytes()

    file_map: dict[str, bytes] = {f"{root_prefix}/PKG-INFO": pkg_info_bytes}
    dir_set: set[str] = {root_prefix}

    for src in src_files:
        rel = src.relative_to(REPO_ROOT).as_posix()
        arc = f"{root_prefix}/{rel}"
        file_map[arc] = _read_normalized_bytes(src)
        parts = arc.split("/")
        for idx in range(1, len(parts)):
            dir_set.add("/".join(parts[:idx]))

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for d_arc in sorted(dir_set):
            d_info = tarfile.TarInfo(name=d_arc)
            d_info.type = tarfile.DIRTYPE
            d_info.mode = 0o755
            d_info.uid = 0
            d_info.gid = 0
            d_info.uname = ""
            d_info.gname = ""
            d_info.mtime = FIXED_EPOCH
            tf.addfile(d_info)

        for f_arc in sorted(file_map.keys()):
            blob = file_map[f_arc]
            f_info = tarfile.TarInfo(name=f_arc)
            f_info.type = tarfile.REGTYPE
            f_info.size = len(blob)
            f_info.mode = 0o644
            f_info.uid = 0
            f_info.gid = 0
            f_info.uname = ""
            f_info.gname = ""
            f_info.mtime = FIXED_EPOCH
            tf.addfile(f_info, io.BytesIO(blob))

    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, compresslevel=9, mtime=0) as gzf:
        gzf.write(tar_buf.getvalue())

    sdist_bytes = gz_buf.getvalue()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(sdist_bytes)
    return hashlib.sha256(sdist_bytes).hexdigest()


def _verify_sdist_zero_host_metadata(sdist_path: Path) -> None:
    with tarfile.open(sdist_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.uid != 0 or member.gid != 0 or member.uname != "" or member.gname != "":
                raise SystemExit(
                    f"Non-zero host UID/GID/uname leaked in {member.name}: "
                    f"uid={member.uid} gid={member.gid} uname={member.uname!r} gname={member.gname!r}"
                )
            if int(member.mtime) != FIXED_EPOCH:
                raise SystemExit(f"Non-deterministic mtime in {member.name}: {member.mtime}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build bit-for-bit reproducible starshield distributions")
    ap.add_argument("--output", type=Path, default=REPO_ROOT / "dist" / "starshield.pyz")
    ap.add_argument(
        "--all-dists",
        action="store_true",
        help="Build deterministic starshield.pyz, PEP 427 wheel, and zero-UID PEP 625 sdist into --dist-dir",
    )
    ap.add_argument("--dist-dir", type=Path, default=REPO_ROOT / "dist")
    ap.add_argument("--verify", action="store_true", help="Build twice and assert identical bit-for-bit SHA-256")
    args = ap.parse_args()

    if args.all_dists:
        dist_dir: Path = args.dist_dir
        pyz_out = dist_dir / "starshield.pyz"
        whl_out = dist_dir / f"starshield_forensics-{STARSHIELD_VERSION}-py3-none-any.whl"
        sdist_out = dist_dir / f"starshield_forensics-{STARSHIELD_VERSION}.tar.gz"

        d_pyz = build_deterministic_pyz(pyz_out)
        d_whl = build_deterministic_wheel(whl_out)
        d_sdist = build_deterministic_sdist(sdist_out)

        if args.verify:
            _verify_sdist_zero_host_metadata(sdist_out)
            with tempfile.TemporaryDirectory() as td:
                td_p = Path(td)
                if build_deterministic_pyz(td_p / pyz_out.name) != d_pyz:
                    raise SystemExit("Reproducibility check FAILED for starshield.pyz")
                if build_deterministic_wheel(td_p / whl_out.name) != d_whl:
                    raise SystemExit(f"Reproducibility check FAILED for {whl_out.name}")
                if build_deterministic_sdist(td_p / sdist_out.name) != d_sdist:
                    raise SystemExit(f"Reproducibility check FAILED for {sdist_out.name}")
            print(
                f"REPRODUCIBLE_ALL_OK pyz={d_pyz} wheel={d_whl} sdist={d_sdist}"
            )
        else:
            print(f"{d_pyz}  {pyz_out.name}")
            print(f"{d_whl}  {whl_out.name}")
            print(f"{d_sdist}  {sdist_out.name}")
        return 0

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
