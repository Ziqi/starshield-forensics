#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Structural PNG (RFC 2083) & JPEG (ISO/IEC 10918-1) Metadata & ICC Profile Inspector.

Replaces naive byte-substring matching with strict binary container framing:
- Verifies PNG 8-byte signature (`\\x89PNG\\r\\n\\x1a\\n`), enforces `IHDR` first chunk,
  at least one `IDAT` chunk, and terminal `IEND` chunk with zero trailing bytes,
  validates IEEE 802.3 CRC-32 per chunk, zlib-decompresses `iCCP` chunks, and parses
  the 128-byte ISO 15076-1 ICC Profile Header (`acsp` signature at offset 36..40).
- Verifies JPEG `SOI` (`\\xff\\xd8`), iterates segment markers (`SOFn`, `APP1` EXIF/XMP,
  multi-chunk `APP2` `ICC_PROFILE\\x00[seq][total]`, `APP13` `Photoshop 3.0\\x00` / `8BIM`),
  scans entropy-coded scan data after `SOS` (`\\xff\\xda`) for byte-stuffed `\\xff\\x00` /
  `RSTn` markers until `EOI` (`\\xff\\xd9`), and rejects truncated containers.

Epistemic Discipline:
- NEVER claims "mathematical proof of forgery". Outputs strictly `OBSERVED` / `DERIVED`
  container metadata alongside mandatory `alternative_explanations`.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any, Dict, List, Tuple

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xff\xd8"
MAX_ICC_DECOMPRESSED_BYTES = 16 * 1024 * 1024  # 16 MiB anti-zip-bomb limit


def _decompress_bounded(comp_bytes: bytes, max_len: int = MAX_ICC_DECOMPRESSED_BYTES) -> bytes:
    dobj = zlib.decompressobj()
    out = dobj.decompress(comp_bytes, max_len + 1)
    if len(out) > max_len or dobj.unconsumed_tail:
        raise zlib.error(f"Decompressed payload exceeds {max_len} byte safety limit")
    out += dobj.flush()
    return out


def _parse_icc_profile_bytes(icc_bytes: bytes, source_offset: int) -> Dict[str, Any]:
    if len(icc_bytes) < 128:
        return {
            "valid_icc_header": False,
            "source_offset": source_offset,
            "reason": f"ICC payload shorter than 128-byte ISO 15076-1 header ({len(icc_bytes)} bytes)",
        }

    prof_size = struct.unpack_from(">I", icc_bytes, 0)[0]
    cmm_type = icc_bytes[4:8].decode("ascii", errors="replace").strip()
    color_space = icc_bytes[16:20].decode("ascii", errors="replace").strip()
    pcs = icc_bytes[20:24].decode("ascii", errors="replace").strip()
    signature = icc_bytes[36:40]
    primary_platform = icc_bytes[40:44].decode("ascii", errors="replace").strip()
    creator = icc_bytes[80:84].decode("ascii", errors="replace").strip()

    if signature != b"acsp":
        return {
            "valid_icc_header": False,
            "source_offset": source_offset,
            "reason": f"Missing ISO 15076-1 'acsp' magic at ICC offset 36 (got {signature!r})",
        }

    ascii_view = icc_bytes.decode("latin-1", errors="ignore")
    profile_desc_hint = None
    for candidate in ("Display P3", "sRGB IEC61966-2.1", "Adobe RGB (1998)", "Generic RGB Profile"):
        if candidate in ascii_view:
            profile_desc_hint = candidate
            break

    return {
        "valid_icc_header": True,
        "source_offset": source_offset,
        "declared_profile_size": prof_size,
        "actual_profile_bytes": len(icc_bytes),
        "preferred_cmm": cmm_type,
        "color_space": color_space,
        "pcs": pcs,
        "primary_platform": primary_platform,
        "profile_creator": creator,
        "description_hint": profile_desc_hint,
    }


def _build_synthetic_icc_bytes(profile_desc: str = "Display P3", platform: str = "APPL") -> bytes:
    icc = bytearray(160)
    struct.pack_into(">I", icc, 0, 160)
    icc[4:8] = platform.encode("ascii")[:4].ljust(4, b" ")
    icc[16:20] = b"RGB "
    icc[20:24] = b"XYZ "
    icc[36:40] = b"acsp"
    icc[40:44] = platform.encode("ascii")[:4].ljust(4, b" ")
    desc_bytes = profile_desc.encode("ascii")[:28]
    icc[128 : 128 + len(desc_bytes)] = desc_bytes
    return bytes(icc)


def build_valid_png_with_iccp(
    profile_desc: str = "Display P3",
    platform: str = "APPL",
    software_text: str | None = None,
    iccp_name: str = "EmbeddedProfile",
) -> bytes:
    """Construct a valid RFC 2083 PNG with CRC-verified IHDR, iCCP (ISO 15076-1), optional tEXt, IDAT, and IEND."""
    def make_chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    icc = _build_synthetic_icc_bytes(profile_desc, platform)
    iccp_prefix = iccp_name.encode("latin-1", errors="replace")[:79]
    iccp_data = iccp_prefix + b"\x00\x00" + zlib.compress(icc)
    text_chunk = make_chunk(b"tEXt", software_text.encode("utf-8")) if software_text else b""
    raw_scanline = zlib.compress(b"\x00\xff\xff\xff")

    return (
        PNG_MAGIC
        + make_chunk(b"IHDR", ihdr_data)
        + make_chunk(b"iCCP", iccp_data)
        + text_chunk
        + make_chunk(b"IDAT", raw_scanline)
        + make_chunk(b"IEND", b"")
    )


def build_valid_jpeg_with_icc_and_8bim(
    profile_desc: str = "Display P3",
    platform: str = "APPL",
    split_icc_chunks: int = 2,
) -> bytes:
    """Construct a valid ISO/IEC 10918-1 JPEG with multi-chunk APP2 ICC, APP13 8BIM, SOF0, SOS, and EOI."""
    def make_seg(marker: int, payload: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload

    icc = _build_synthetic_icc_bytes(profile_desc, platform)
    app2_segs = bytearray()
    total = max(1, split_icc_chunks)
    step = (len(icc) + total - 1) // total
    for idx in range(total):
        part = icc[idx * step : (idx + 1) * step]
        header = b"ICC_PROFILE\x00" + bytes([idx + 1, total])
        app2_segs.extend(make_seg(0xE2, header + part))

    app13_payload = b"Photoshop 3.0\x008BIM\x04\x04\x00\x00\x00\x00\x00\x04test"
    sof0_payload = struct.pack(">BHHB", 8, 1, 1, 1) + bytes([1, 0x11, 0])
    sos_header = bytes([1, 1, 0x00, 0, 63, 0])
    # Include byte-stuffed 0xFF 0x00 in compressed scan data before EOI 0xFFD9
    entropy_stream = b"\x7f\xff\x00\x3a"

    return (
        JPEG_SOI
        + make_seg(0xE0, b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00")
        + bytes(app2_segs)
        + make_seg(0xED, app13_payload)
        + make_seg(0xC0, sof0_payload)
        + make_seg(0xDA, sos_header)
        + entropy_stream
        + b"\xff\xd9"
    )


def inspect_image_container(raw: bytes, label: str = "artifact") -> Dict[str, Any]:
    """Parse PNG or JPEG binary container structure without substring false positives."""
    if raw.startswith(PNG_MAGIC):
        return _inspect_png(raw, label)
    if raw.startswith(JPEG_SOI):
        return _inspect_jpeg(raw, label)

    return {
        "artifact": label,
        "container_format": "UNSUPPORTED_OR_NOT_AN_IMAGE",
        "epistemic_tier": "OBSERVED",
        "valid_container": False,
        "metadata_observations": [],
        "note": "Input does not start with RFC 2083 PNG magic or ISO 10918 JPEG SOI; skipped byte scanning to prevent text false positives.",
    }


def _inspect_png(raw: bytes, label: str) -> Dict[str, Any]:
    pos = 8
    chunks_summary: List[Dict[str, Any]] = []
    crc_errors: List[Dict[str, Any]] = []
    container_errors: List[Dict[str, Any]] = []
    icc_profiles: List[Dict[str, Any]] = []
    text_software_tags: List[Dict[str, Any]] = []
    saw_iend = False

    while pos + 8 <= len(raw):
        chunk_offset = pos
        length = struct.unpack_from(">I", raw, pos)[0]
        ctype_bytes = raw[pos + 4 : pos + 8]
        ctype = ctype_bytes.decode("latin-1", errors="replace")
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4

        if crc_end > len(raw):
            crc_errors.append({"byte_offset": chunk_offset, "chunk": ctype, "reason": "Truncated PNG chunk"})
            pos = len(raw)
            break

        chunk_data = raw[data_start:data_end]
        stored_crc = struct.unpack_from(">I", raw, data_end)[0]
        calc_crc = zlib.crc32(ctype_bytes + chunk_data) & 0xFFFFFFFF
        crc_ok = stored_crc == calc_crc

        chunks_summary.append({"chunk": ctype, "byte_offset": chunk_offset, "length": length, "crc_valid": crc_ok})
        if not crc_ok:
            crc_errors.append(
                {
                    "byte_offset": chunk_offset,
                    "chunk": ctype,
                    "reason": f"CRC32 mismatch (stored=0x{stored_crc:08x}, calc=0x{calc_crc:08x})",
                }
            )
        else:
            if ctype_bytes == b"IHDR":
                if length != 13:
                    container_errors.append({"byte_offset": chunk_offset, "reason": f"Invalid IHDR length {length} != 13"})
                else:
                    w, h = struct.unpack_from(">II", chunk_data, 0)
                    if w == 0 or h == 0:
                        container_errors.append({"byte_offset": chunk_offset, "reason": "IHDR zero width or height"})
            elif ctype_bytes == b"iCCP" and b"\x00" in chunk_data:
                nul_idx = chunk_data.index(b"\x00")
                prof_name = chunk_data[:nul_idx].decode("latin-1", errors="replace")
                if nul_idx + 2 <= len(chunk_data) and chunk_data[nul_idx + 1] == 0:
                    try:
                        decompressed = _decompress_bounded(chunk_data[nul_idx + 2 :])
                        parsed_icc = _parse_icc_profile_bytes(decompressed, chunk_offset)
                        parsed_icc["png_iccp_name"] = prof_name
                        icc_profiles.append(parsed_icc)
                    except zlib.error as exc:
                        crc_errors.append(
                            {"byte_offset": chunk_offset, "chunk": "iCCP", "reason": f"zlib error: {exc}"}
                        )
            elif ctype_bytes in (b"tEXt", b"iTXt") and any(
                k in chunk_data for k in (b"Software", b"Creator", b"Author", b"Comment", b"Adobe", b"Photoshop")
            ):
                text_software_tags.append(
                    {
                        "byte_offset": chunk_offset,
                        "chunk": ctype,
                        "preview": chunk_data[:120].decode("utf-8", errors="replace"),
                    }
                )

        pos = crc_end
        if ctype_bytes == b"IEND":
            if length != 0:
                container_errors.append({"byte_offset": chunk_offset, "reason": f"Non-zero IEND length {length}"})
            saw_iend = True
            break

    if not chunks_summary or chunks_summary[0]["chunk"] != "IHDR":
        container_errors.append({"byte_offset": 8, "reason": "Missing mandatory leading IHDR chunk"})
    has_idat = any(c["chunk"] == "IDAT" and c["crc_valid"] for c in chunks_summary)
    if not has_idat:
        container_errors.append({"byte_offset": pos, "reason": "Missing mandatory IDAT image data chunk"})
    if not saw_iend:
        container_errors.append({"byte_offset": pos, "reason": "Missing mandatory terminal IEND chunk (truncated PNG)"})
    elif pos < len(raw):
        container_errors.append({"byte_offset": pos, "reason": f"Unexpected trailing bytes after IEND ({len(raw) - pos} bytes)"})

    valid_container = bool(chunks_summary) and has_idat and saw_iend and not crc_errors and not container_errors
    return {
        "artifact": label,
        "container_format": "PNG",
        "valid_container": valid_container,
        "epistemic_tier": "DERIVED",
        "chunks_parsed": len(chunks_summary),
        "crc_errors": crc_errors,
        "container_errors": container_errors,
        "icc_profiles": icc_profiles,
        "software_text_chunks": text_software_tags,
        "alternative_explanations": [
            "Display P3 / APPL ICC profiles are standard in legitimate macOS/iOS screenshots and camera exports.",
            "Editing software metadata indicates pipeline touch, not standalone proof of fraudulent content; compare against the sender's claimed document provenance.",
        ],
    }


def _scan_jpeg_entropy_until_marker(raw: bytes, start_pos: int) -> Tuple[int, int | None]:
    """Scan compressed JPEG scan data skipping byte-stuffed 0xFF00 and RST0..RST7 markers."""
    n = len(raw)
    i = start_pos
    while i < n:
        if raw[i] != 0xFF:
            i += 1
            continue
        while i < n and raw[i] == 0xFF:
            i += 1
        if i >= n:
            return n, None
        marker = raw[i]
        if marker == 0x00:
            i += 1
            continue
        if 0xD0 <= marker <= 0xD7:
            i += 1
            continue
        return i - 1, marker
    return n, None


def _inspect_jpeg(raw: bytes, label: str) -> Dict[str, Any]:
    pos = 2
    segments: List[Dict[str, Any]] = []
    container_errors: List[Dict[str, Any]] = []
    icc_profiles: List[Dict[str, Any]] = []
    icc_chunks: Dict[int, Tuple[int, int, bytes]] = {}
    icc_declared_total: int | None = None
    photoshop_8bim_offsets: List[int] = []

    saw_sof = False
    saw_sos = False
    saw_eoi = False

    while pos < len(raw):
        if raw[pos] != 0xFF:
            container_errors.append({"byte_offset": pos, "reason": "Expected 0xFF JPEG marker prefix"})
            break
        while pos < len(raw) and raw[pos] == 0xFF:
            pos += 1
        if pos >= len(raw):
            container_errors.append({"byte_offset": pos - 1, "reason": "Truncated marker at EOF"})
            break

        marker = raw[pos]
        seg_offset = pos - 1
        pos += 1

        if marker == 0xD9:  # EOI
            segments.append({"marker": "0xFFD9", "byte_offset": seg_offset, "length": 0})
            saw_eoi = True
            if pos < len(raw):
                container_errors.append(
                    {"byte_offset": pos, "reason": f"Trailing bytes after JPEG EOI ({len(raw) - pos} bytes)"}
                )
            break

        if marker == 0xD8 or (0xD0 <= marker <= 0xD7) or marker == 0x01:
            continue

        if pos + 2 > len(raw):
            container_errors.append({"byte_offset": seg_offset, "reason": "Truncated JPEG segment length"})
            break

        seg_len = struct.unpack_from(">H", raw, pos)[0]
        if seg_len < 2 or pos + seg_len > len(raw):
            container_errors.append(
                {"byte_offset": seg_offset, "reason": f"Invalid or truncated JPEG segment length {seg_len}"}
            )
            break

        seg_data = raw[pos + 2 : pos + seg_len]
        segments.append({"marker": f"0xFF{marker:02X}", "byte_offset": seg_offset, "length": seg_len})

        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            saw_sof = True
        elif marker == 0xE2 and seg_data.startswith(b"ICC_PROFILE\x00"):
            if len(seg_data) < 14:
                container_errors.append({"byte_offset": seg_offset, "reason": "Truncated APP2 ICC_PROFILE header"})
            else:
                seq_no = seg_data[12]
                tot_no = seg_data[13]
                if seq_no < 1 or tot_no < 1 or seq_no > tot_no:
                    container_errors.append(
                        {"byte_offset": seg_offset, "reason": f"Invalid APP2 ICC chunk numbering {seq_no}/{tot_no}"}
                    )
                elif seq_no in icc_chunks:
                    container_errors.append(
                        {"byte_offset": seg_offset, "reason": f"Duplicate APP2 ICC chunk sequence {seq_no}"}
                    )
                else:
                    if icc_declared_total is None:
                        icc_declared_total = tot_no
                    elif icc_declared_total != tot_no:
                        container_errors.append(
                            {"byte_offset": seg_offset, "reason": "Inconsistent APP2 ICC total_chunks count"}
                        )
                    icc_chunks[seq_no] = (seg_offset, tot_no, seg_data[14:])
        elif marker == 0xED and b"Photoshop 3.0\x00" in seg_data and b"8BIM" in seg_data:
            photoshop_8bim_offsets.append(seg_offset)

        pos += seg_len

        if marker == 0xDA:  # SOS: advance across entropy-coded scan until next real marker
            saw_sos = True
            next_marker_offset, next_marker = _scan_jpeg_entropy_until_marker(raw, pos)
            if next_marker is None:
                container_errors.append(
                    {"byte_offset": seg_offset, "reason": "Truncated JPEG entropy scan: missing EOI (0xFFD9)"}
                )
                pos = len(raw)
                break
            pos = next_marker_offset

    if icc_declared_total is not None:
        expected_keys = list(range(1, icc_declared_total + 1))
        if sorted(icc_chunks.keys()) != expected_keys:
            container_errors.append(
                {
                    "byte_offset": segments[0]["byte_offset"] if segments else 2,
                    "reason": f"Incomplete multi-segment APP2 ICC profile (got {sorted(icc_chunks.keys())} of 1..{icc_declared_total})",
                }
            )
        else:
            first_offset = icc_chunks[1][0]
            assembled = b"".join(icc_chunks[k][2] for k in expected_keys)
            parsed_icc = _parse_icc_profile_bytes(assembled, first_offset)
            parsed_icc["jpeg_app2_chunks_reassembled"] = icc_declared_total
            icc_profiles.append(parsed_icc)

    if not saw_sof:
        container_errors.append({"byte_offset": pos, "reason": "Missing JPEG Start-of-Frame (SOFn) segment"})
    if not saw_sos:
        container_errors.append({"byte_offset": pos, "reason": "Missing JPEG Start-of-Scan (SOS) segment"})
    if not saw_eoi:
        container_errors.append({"byte_offset": pos, "reason": "Missing JPEG End-of-Image (EOI 0xFFD9) marker"})

    valid_container = saw_sof and saw_sos and saw_eoi and not container_errors
    return {
        "artifact": label,
        "container_format": "JPEG",
        "valid_container": valid_container,
        "epistemic_tier": "DERIVED",
        "segments_parsed": len(segments),
        "container_errors": container_errors,
        "icc_profiles": icc_profiles,
        "photoshop_app13_8bim_offsets": photoshop_8bim_offsets,
        "alternative_explanations": [
            "APP13/8BIM blocks show Adobe/compatible image pipeline processing, which may occur in benign format conversion as well as document manipulation.",
            "Metadata provenance is an investigation triage lead, not standalone proof of falsification.",
        ],
    }
